# vuln-tracker

A static GitHub Pages site that displays CVEs (Common Vulnerabilities and Exposures) from the current and previous calendar month. Data is auto-refreshed every 2 hours via a GitHub Actions cron job polling the NVD API 2.0.

- Zero JavaScript — pure HTML + CSS
- Data stored in TONL format as the canonical data layer
- Markdown tables generated automatically for GitHub viewing
- Severity color-coded: CRITICAL, HIGH, MEDIUM, LOW, NONE
- KEV (Known Exploited Vulnerabilities) indicator
- Dedicated **Top 50** view (ranked by KEV status and CVSS score)
- Dark mode support

## Local development

```bash
pip install requests
python scripts/fetch.py
```

This writes `data/current.tonl`, `data/previous.tonl`, `data/current.md`, `data/previous.md`, `data/top50.tonl`, `data/top50.md`, `data/state.json` to the data dir and `index.html`, `top50.html` to the repo root. Open `index.html` or `top50.html` in a browser to preview.

## File structure

```
.
├── .github/workflows/fetch-cves.yml  # Cron job (every 2 hours)
├── scripts/fetch.py                  # NVD API client + HTML generator
├── data/
│   ├── current.tonl                  # Current month CVEs (TONL format)
│   ├── current.md                    # Current month CVEs (Markdown table)
│   ├── previous.tonl                 # Previous month CVEs (TONL format)
│   ├── previous.md                   # Previous month CVEs (Markdown table)
│   ├── top50.tonl                    # Top 50 most severe CVEs (TONL format)
│   ├── top50.md                      # Top 50 most severe CVEs (Markdown table)
│   └── state.json                    # Fetch state (last run, current month)
├── index.html                        # Generated static site (All CVEs)
├── top50.html                        # Generated static site (Top 50 CVEs)
└── style.css                         # Styles
```

## Views

- **Global View** (`index.html`): Displays all CVEs from the current and previous months, separated into two large tables.
- **Top 50 View** (`top50.html`): Displays a consolidated table of the 50 most important CVEs across both months, ranked first by whether they are Known Exploited Vulnerabilities (KEV) and then by their CVSS score.

The two views are linked via a top navigation menu (`<nav>`) on each page, allowing you to easily toggle between the complete dataset and the prioritized Top 50 list.

## Attribution

This product uses the NVD API but is not endorsed or certified by the NVD.

NVD API documentation: https://nvd.nist.gov/developers/vulnerabilities

## License

MIT
