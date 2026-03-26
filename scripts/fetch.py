"""
vuln-tracker: fetch CVEs from NVD API and generate static HTML.
"""

import html
import json
import shutil
import sys
import time
from calendar import monthrange
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NVD_API_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
PAGE_SIZE      = 2000
SLEEP_BETWEEN  = 7  # seconds between paginated requests (rate limit: 5/30s)

ROOT_DIR       = Path(__file__).parent.parent
DATA_DIR       = ROOT_DIR / "data"
STATE_FILE     = DATA_DIR / "state.json"
CURRENT_TONL   = DATA_DIR / "current.tonl"
PREVIOUS_TONL  = DATA_DIR / "previous.tonl"
CURRENT_MD     = DATA_DIR / "current.md"
PREVIOUS_MD    = DATA_DIR / "previous.md"
TOP50_TONL     = DATA_DIR / "top50.tonl"
TOP50_MD       = DATA_DIR / "top50.md"
INDEX_HTML     = ROOT_DIR / "index.html"
TOP50_HTML     = ROOT_DIR / "top50.html"

TOP50_COUNT    = 50

TONL_HEADER    = "#version 1.0\n#delimiter \"|\"\n"
TONL_SCHEMA    = "cves[COUNT]{cveId:str|published:str|lastModified:str|cvssScore:f64|severity:str|cweId:str|cweName:str|kev:bool|description:str|nvdUrl:str}:"
FIELD_NAMES    = ["cveId", "published", "lastModified", "cvssScore", "severity",
                  "cweId", "cweName", "kev", "description", "nvdUrl"]

HEADERS        = {"User-Agent": "vuln-tracker/1.0"}

# ---------------------------------------------------------------------------
# TONL helpers
# ---------------------------------------------------------------------------

def tonl_quote_field(value: str) -> str:
    """Quote a TONL field value if it contains a pipe, quote, or newline."""
    if '|' in value or '"' in value or '\n' in value or '\r' in value:
        return '"' + value.replace('"', '""') + '"'
    return value


def tonl_parse_row(line: str) -> list:
    """Parse a single TONL data row, respecting quoted fields."""
    fields = []
    current = []
    in_quote = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_quote:
            if ch == '"':
                if i + 1 < len(line) and line[i + 1] == '"':
                    current.append('"')
                    i += 2
                    continue
                else:
                    in_quote = False
            else:
                current.append(ch)
        else:
            if ch == '"':
                in_quote = True
            elif ch == '|':
                fields.append(''.join(current))
                current = []
            else:
                current.append(ch)
        i += 1
    fields.append(''.join(current))
    return fields


def load_tonl(path: Path) -> dict:
    """Load a TONL file and return a dict keyed by cveId."""
    if not path.exists():
        return {}
    records = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith('cves['):
            continue
        fields = tonl_parse_row(stripped)
        if len(fields) != len(FIELD_NAMES):
            continue
        rec = dict(zip(FIELD_NAMES, fields))
        rec["cvssScore"] = float(rec["cvssScore"])
        rec["kev"] = rec["kev"].lower() == "true"
        records[rec["cveId"]] = rec
    return records


def write_tonl(path: Path, records: dict) -> None:
    """Write records to a TONL file, sorted by published descending."""
    sorted_recs = sorted(records.values(), key=lambda r: r["published"], reverse=True)
    lines = [TONL_HEADER, ""]
    lines.append(TONL_SCHEMA.replace("COUNT", str(len(sorted_recs))))
    for rec in sorted_recs:
        q = tonl_quote_field
        row = (
            f"  {q(rec['cveId'])}|{q(rec['published'])}|{q(rec['lastModified'])}"
            f"|{rec['cvssScore']:.1f}|{q(rec['severity'])}"
            f"|{q(rec['cweId'])}|{q(rec['cweName'])}"
            f"|{str(rec['kev']).lower()}"
            f"|{q(rec['description'])}|{q(rec['nvdUrl'])}"
        )
        lines.append(row)
    path.write_text('\n'.join(lines) + '\n', encoding="utf-8")

def write_markdown(path: Path, records: dict, title: str) -> None:
    """Write records to a Markdown file, sorted by published descending."""
    sorted_recs = sorted(records.values(), key=lambda r: r["published"], reverse=True)
    lines = [
        f"# {title}",
        "",
        f"_{len(sorted_recs)} vulnerabilities_",
        "",
        "| CVE ID | Score | Severity | CWE | KEV | Published | Description |",
        "|--------|-------|----------|-----|-----|-----------|-------------|",
    ]
    for rec in sorted_recs:
        desc = rec["description"].replace("|", "\\|").replace("\n", " ")
        if len(desc) > 120:
            desc = desc[:120].rstrip() + "..."
        kev = "Yes" if rec["kev"] else "No"
        lines.append(
            f"| [{rec['cveId']}]({rec['nvdUrl']}) "
            f"| {rec['cvssScore']:.1f} "
            f"| {rec['severity']} "
            f"| {rec['cweId']} "
            f"| {kev} "
            f"| {rec['published'][:10]} "
            f"| {desc} |"
        )
    path.write_text('\n'.join(lines) + '\n', encoding="utf-8")

# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"last_fetched": None, "current_month": ""}


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
        f.write("\n")

# ---------------------------------------------------------------------------
# NVD API client
# ---------------------------------------------------------------------------

def fetch_nvd_page(params: dict) -> dict:
    resp = requests.get(NVD_API_URL, params=params, headers=HEADERS, timeout=30)
    if resp.status_code == 429:
        print("Rate limited (429). Exiting — next run will resume via last_fetched.")
        sys.exit(1)
    if resp.status_code != 200:
        print(f"NVD API error: HTTP {resp.status_code}")
        sys.exit(1)
    return resp.json()


def fetch_all_cves(params_base: dict) -> list:
    """Fetch all CVEs for a given set of base parameters, handling pagination."""
    results = []
    start_index = 0
    total_results = None

    while True:
        params = {**params_base, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}
        data = fetch_nvd_page(params)

        if total_results is None:
            total_results = data["totalResults"]
            print(f"  Total results: {total_results}")

        results.extend(data.get("vulnerabilities", []))
        actual_page_size = data.get("resultsPerPage", 0)
        start_index += actual_page_size

        if start_index >= total_results or actual_page_size == 0:
            break

        print(f"  Fetched {start_index}/{total_results}, sleeping {SLEEP_BETWEEN}s...")
        time.sleep(SLEEP_BETWEEN)

    return results

# ---------------------------------------------------------------------------
# CVE parsing
# ---------------------------------------------------------------------------

def resolve_cvss(metrics: dict) -> tuple:
    """Resolve CVSS score and severity from available metric versions."""
    # v4.0, v3.1, v3.0: severity inside cvssData
    for version_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version_key)
        if entries:
            m = entries[0]
            score = m["cvssData"]["baseScore"]
            severity = m["cvssData"].get("baseSeverity", "NONE")
            return float(score), severity.upper()
    # v2.0: severity at metric level, not inside cvssData
    entries = metrics.get("cvssMetricV2")
    if entries:
        m = entries[0]
        score = m["cvssData"]["baseScore"]
        severity = m.get("baseSeverity", "NONE")
        return float(score), severity.upper()
    return 0.0, "NONE"


def parse_cve(item: dict) -> dict:
    """Parse a single NVD vulnerability item into our data model."""
    cve = item["cve"]
    cve_id = cve["id"]

    published     = cve.get("published", "")
    last_modified = cve.get("lastModified", "")

    metrics = cve.get("metrics", {})
    cvss_score, severity = resolve_cvss(metrics)

    cwe_id = "N/A"
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        for desc in weaknesses[0].get("description", []):
            if desc.get("lang") == "en":
                cwe_id = desc.get("value", "N/A")
                break

    kev = "cisaExploitAdd" in cve

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    return {
        "cveId":        cve_id,
        "published":    published,
        "lastModified": last_modified,
        "cvssScore":    cvss_score,
        "severity":     severity,
        "cweId":        cwe_id,
        "cweName":      "N/A",
        "kev":          kev,
        "description":  description,
        "nvdUrl":       NVD_DETAIL_URL + cve_id,
    }

# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def merge_records(existing: dict, incoming: list) -> dict:
    """Upsert incoming records into existing dict by cveId."""
    merged = dict(existing)
    for rec in incoming:
        merged[rec["cveId"]] = rec
    return merged

# ---------------------------------------------------------------------------
# Month helpers
# ---------------------------------------------------------------------------

def get_prev_month_range(now: datetime) -> tuple:
    year, month = now.year, now.month - 1
    if month == 0:
        month, year = 12, year - 1
    _, last_day = monthrange(year, month)
    first = datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc)
    last  = datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc)
    return first, last


def get_prev_month_str(now: datetime) -> str:
    year, month = now.year, now.month - 1
    if month == 0:
        month, year = 12, year - 1
    return f"{year}-{month:02d}"

# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def render_table_row(rec: dict) -> str:
    sev_lower = rec["severity"].lower()
    score_str = f"{rec['cvssScore']:.1f}"
    cve_id    = html.escape(rec["cveId"])
    nvd_url   = html.escape(rec["nvdUrl"])
    cwe       = html.escape(rec["cweId"])
    desc_full = html.escape(rec["description"])
    desc_summary = html.escape(rec["description"][:80] + ("..." if len(rec["description"]) > 80 else ""))
    published = html.escape(rec["published"][:10])
    kev_cell  = '<span class="kev-yes">&#10003;</span>' if rec["kev"] else "&nbsp;"

    return (
        f"      <tr>\n"
        f"        <td><a href=\"{nvd_url}\" target=\"_blank\" rel=\"noopener\">{cve_id}</a></td>\n"
        f"        <td>{score_str}</td>\n"
        f"        <td><span class=\"severity {sev_lower}\">{html.escape(rec['severity'])}</span></td>\n"
        f"        <td>{cwe}</td>\n"
        f"        <td>{kev_cell}</td>\n"
        f"        <td><details><summary>{desc_summary}</summary><p>{desc_full}</p></details></td>\n"
        f"        <td>{published}</td>\n"
        f"      </tr>"
    )


def render_section(title: str, records: dict) -> str:
    sorted_recs = sorted(records.values(), key=lambda r: r["published"], reverse=True)
    count = len(sorted_recs)
    rows = "\n".join(render_table_row(r) for r in sorted_recs)
    if not rows:
        rows = "      <tr><td colspan=\"7\">No vulnerabilities recorded for this period.</td></tr>"
    return f"""    <section>
      <h2>{html.escape(title)} <span class="count">({count})</span></h2>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Score</th>
              <th>Severity</th>
              <th>CWE</th>
              <th>KEV</th>
              <th>Description</th>
              <th>Published</th>
            </tr>
          </thead>
          <tbody>
{rows}
          </tbody>
        </table>
      </div>
    </section>"""


def render_html(current: dict, previous: dict, timestamp: str, now: datetime) -> str:
    current_label  = now.strftime("%B %Y")
    prev_dt        = get_prev_month_range(now)[0]
    previous_label = prev_dt.strftime("%B %Y")

    current_section  = render_section(f"Current Month — {current_label}", current)
    previous_section = render_section(f"Previous Month — {previous_label}", previous)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vuln-tracker</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="container">
    <header>
      <h1>vuln-tracker</h1>
      <p class="subtitle">CVEs from the National Vulnerability Database — current and previous month</p>
      <p class="last-updated">Last updated: {html.escape(timestamp)}</p>
    </header>
    <nav>
      <a href="top50.html">&#9733; Top {TOP50_COUNT}</a>
      <span class="nav-sep">|</span>
      <span class="nav-data">Data:
        <a href="data/current.tonl">current.tonl</a>
        <a href="data/current.md">current.md</a>
        <a href="data/previous.tonl">previous.tonl</a>
        <a href="data/previous.md">previous.md</a>
      </span>
    </nav>
    <main>
{current_section}
{previous_section}
    </main>
    <footer>
      <p>This product uses the NVD API but is not endorsed or certified by the NVD.</p>
    </footer>
  </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Top-N selection
# ---------------------------------------------------------------------------

def get_top50(current: dict, previous: dict) -> dict:
    """Return the top TOP50_COUNT CVEs ranked by KEV status then CVSS score."""
    combined = {**previous, **current}  # current wins on duplicate cveId
    ranked = sorted(
        combined.values(),
        key=lambda r: (r["kev"], r["cvssScore"]),
        reverse=True,
    )
    return {r["cveId"]: r for r in ranked[:TOP50_COUNT]}


def render_html_top50(records: dict, timestamp: str) -> str:
    sorted_recs = sorted(records.values(), key=lambda r: (r["kev"], r["cvssScore"]), reverse=True)
    rows = "\n".join(render_table_row(r) for r in sorted_recs)
    if not rows:
        rows = "      <tr><td colspan=\"7\">No data available.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vuln-tracker — Top {TOP50_COUNT}</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="container">
    <header>
      <h1>vuln-tracker — Top {TOP50_COUNT}</h1>
      <p class="subtitle">The {TOP50_COUNT} most important CVEs from the current and previous month, ranked by KEV status then CVSS score</p>
      <p class="last-updated">Last updated: {html.escape(timestamp)}</p>
    </header>
    <nav>
      <a href="index.html">&larr; All CVEs</a>
      <span class="nav-sep">|</span>
      <span class="nav-data">Data:
        <a href="data/top50.tonl">top50.tonl</a>
        <a href="data/top50.md">top50.md</a>
      </span>
    </nav>
    <main>
      <section>
        <h2>Top {TOP50_COUNT} <span class="count">({len(sorted_recs)})</span></h2>
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Score</th>
                <th>Severity</th>
                <th>CWE</th>
                <th>KEV</th>
                <th>Description</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
{rows}
            </tbody>
          </table>
        </div>
      </section>
    </main>
    <footer>
      <p>This product uses the NVD API but is not endorsed or certified by the NVD.</p>
    </footer>
  </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    now_utc     = datetime.now(timezone.utc)
    today_month = now_utc.strftime("%Y-%m")

    state = load_state()

    # --- Month rollover ---
    if state["current_month"] != today_month:
        print(f"Month rollover: '{state['current_month']}' -> '{today_month}'")
        if CURRENT_TONL.exists():
            shutil.copy2(CURRENT_TONL, PREVIOUS_TONL)
        if CURRENT_MD.exists():
            shutil.copy2(CURRENT_MD, PREVIOUS_MD)
        write_tonl(CURRENT_TONL, {})
        state["current_month"] = today_month
        state["last_fetched"]  = None

    # --- Fetch ---
    if state["last_fetched"] is None:
        # Full fetch: current month
        first_of_month = now_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        print(f"Full fetch: current month ({today_month})...")
        current_raw = fetch_all_cves({
            "pubStartDate": first_of_month.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":   now_utc.strftime("%Y-%m-%dT%H:%M:%S.000"),
        })

        # Full fetch: previous month
        prev_first, prev_last = get_prev_month_range(now_utc)
        prev_month_str = get_prev_month_str(now_utc)
        print(f"Full fetch: previous month ({prev_month_str})...")
        previous_raw = fetch_all_cves({
            "pubStartDate": prev_first.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":   prev_last.strftime("%Y-%m-%dT%H:%M:%S.000"),
        })

        current_records  = merge_records(load_tonl(CURRENT_TONL),  [parse_cve(v) for v in current_raw])
        previous_records = merge_records(load_tonl(PREVIOUS_TONL), [parse_cve(v) for v in previous_raw])

    else:
        # Incremental: fetch modified since last run
        print(f"Incremental fetch since {state['last_fetched']}...")
        inc_raw = fetch_all_cves({
            "lastModStartDate": state["last_fetched"],
            "lastModEndDate":   now_utc.strftime("%Y-%m-%dT%H:%M:%S.000"),
        })
        inc_parsed = [parse_cve(v) for v in inc_raw]

        prev_month_str = get_prev_month_str(now_utc)
        current_new  = [r for r in inc_parsed if r["published"].startswith(today_month)]
        previous_new = [r for r in inc_parsed if r["published"].startswith(prev_month_str)]

        current_records  = merge_records(load_tonl(CURRENT_TONL),  current_new)
        previous_records = merge_records(load_tonl(PREVIOUS_TONL), previous_new)

    # --- Write outputs (all-or-nothing order: data first, then HTML, then state) ---
    current_label  = now_utc.strftime("%B %Y")
    previous_label = get_prev_month_range(now_utc)[0].strftime("%B %Y")

    print(f"Writing TONL: {len(current_records)} current, {len(previous_records)} previous")
    write_tonl(CURRENT_TONL,  current_records)
    write_tonl(PREVIOUS_TONL, previous_records)

    print("Writing Markdown...")
    write_markdown(CURRENT_MD,  current_records,  f"CVEs — {current_label}")
    write_markdown(PREVIOUS_MD, previous_records, f"CVEs — {previous_label}")

    top50 = get_top50(current_records, previous_records)
    print(f"Writing Top {TOP50_COUNT} ({len(top50)} entries)...")
    write_tonl(TOP50_TONL, top50)
    write_markdown(TOP50_MD, top50, f"Top {TOP50_COUNT} CVEs — {current_label} & {previous_label}")
    TOP50_HTML.write_text(render_html_top50(top50, timestamp), encoding="utf-8")

    timestamp = now_utc.strftime("%Y-%m-%d %H:%M UTC")
    print("Generating index.html...")
    INDEX_HTML.write_text(render_html(current_records, previous_records, timestamp, now_utc), encoding="utf-8")

    state["last_fetched"] = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    save_state(state)

    print("Done.")


if __name__ == "__main__":
    main()
