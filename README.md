# vuln-tracker

A zero-JavaScript static site that surfaces CVEs from the **current and previous calendar month**, auto-refreshed every 2 hours via GitHub Actions and the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities).

**[Live site →](https://julian-schn.github.io/vuln-tracker/)**

---

## Features

| | |
|---|---|
| 🚫 Zero JavaScript | Pure HTML + CSS — works everywhere, no client-side execution |
| 🔄 Auto-updated | GitHub Actions cron job fetches new data every 2 hours |
| 🎯 Top 50 view | Most critical CVEs ranked by a composite **VAP score** |
| 🏷️ Severity badges | Color-coded labels: CRITICAL · HIGH · MEDIUM · LOW · NONE |
| ⚠️ KEV indicator | Flags [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| 📊 EPSS scores | [Exploit Prediction Scoring System](https://www.first.org/epss/) probability and percentile |
| 🌙 Dark mode | Automatic via `prefers-color-scheme` |
| 📁 Machine-readable data | All data available as TONL and Markdown files |

## How it works

```
┌──────────────┐    NVD API 2.0    ┌──────────────┐    EPSS API     ┌──────────────┐
│ GitHub Action │ ──────────────► │  fetch.py     │ ─────────────► │  Enrichment  │
│ (every 2h)   │                  │  Parse CVEs   │                │  EPSS scores │
└──────────────┘                  └──────┬───────┘                └──────┬───────┘
                                         │                               │
                                         ▼                               ▼
                        ┌─────────────────────────────────┐
                        │  Generate outputs               │
                        │  • data/*.tonl  (structured)    │
                        │  • data/*.md    (Markdown)      │
                        │  • index.html   (all CVEs)      │
                        │  • top50.html   (top 50 CVEs)   │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                                  GitHub Pages
```

1. A cron job triggers `scripts/fetch.py` every 2 hours (or on manual dispatch).
2. The script performs a **full fetch** on month rollover, or an **incremental fetch** of recently modified CVEs.
3. Each CVE is enriched with EPSS probability and percentile data from the [FIRST EPSS API](https://www.first.org/epss/).
4. A **VAP score** (Vulnerability Assessment Priority) is computed: `70% CVSS + 30% EPSS×10` (range 0–10).
5. Static HTML, TONL, and Markdown files are generated and deployed to GitHub Pages.

## Views

- **All CVEs** (`index.html`) — every CVE from the current and previous month in two tables, sorted by publish date.
- **Top 50** (`top50.html`) — the 50 most important CVEs across both months, ranked by VAP score.

Both pages are linked via a navigation bar at the top.

## File structure

```
.
├── .github/workflows/fetch-cves.yml   # Cron job (every 2 hours)
├── scripts/fetch.py                   # NVD API client + HTML generator
├── data/
│   ├── current.tonl                   # Current month CVEs (TONL)
│   ├── current.md                     # Current month CVEs (Markdown)
│   ├── previous.tonl                  # Previous month CVEs (TONL)
│   ├── previous.md                    # Previous month CVEs (Markdown)
│   ├── top50.tonl                     # Top 50 CVEs (TONL)
│   ├── top50.md                       # Top 50 CVEs (Markdown)
│   └── state.json                     # Fetch state (last run timestamp)
├── index.html                         # Generated site — all CVEs
├── top50.html                         # Generated site — top 50
└── style.css                          # Stylesheet (incl. dark mode)
```

## Local development

```bash
# Install the only dependency
pip install requests

# Fetch data and generate HTML
python scripts/fetch.py
```

This writes all data files to `data/` and generates `index.html` + `top50.html` in the repo root. Open either in a browser to preview.

> **Note:** The initial fetch pulls all CVEs for the current and previous month from the NVD API, which can take a few minutes due to rate limiting (≈ 5 requests per 30 seconds).

## Glossary

| Term | Meaning |
|------|---------|
| **CVE** | Common Vulnerabilities and Exposures — a unique identifier for a security vulnerability |
| **CVSS** | Common Vulnerability Scoring System — severity score from 0.0 to 10.0 |
| **CWE** | Common Weakness Enumeration — categorises the type of vulnerability |
| **KEV** | Known Exploited Vulnerabilities — CISA catalogue of actively exploited CVEs |
| **EPSS** | Exploit Prediction Scoring System — probability a CVE will be exploited in the wild |
| **VAP** | Vulnerability Assessment Priority — composite score: `70% CVSS + 30% EPSS×10` |
| **TONL** | A pipe-delimited structured data format used as the canonical data layer |

## Attribution

- This product uses the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) but is not endorsed or certified by the NVD.
- EPSS data is provided by the [FIRST EPSS API](https://www.first.org/epss/).
- KEV status is based on the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (sourced via NVD).

## License

[MIT](LICENSE)
