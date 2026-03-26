# vuln-tracker

A static GitHub Pages site that displays CVEs (Common Vulnerabilities and Exposures) from the current and previous calendar month. Data is auto-refreshed every 2 hours via a GitHub Actions cron job polling the NVD API 2.0.

- Zero JavaScript — pure HTML + CSS
- Data stored in TONL format as the canonical data layer
- Markdown tables generated automatically for GitHub viewing
- Severity color-coded: CRITICAL, HIGH, MEDIUM, LOW, NONE
- KEV (Known Exploited Vulnerabilities) indicator
- Dark mode support

## Local development

```bash
pip install requests
python scripts/fetch.py
```

This writes `data/current.tonl`, `data/previous.tonl`, `data/current.md`, `data/previous.md`, `data/state.json`, and `index.html` to the repo root. Open `index.html` in a browser to preview.

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
│   └── state.json                    # Fetch state (last run, current month)
├── index.html                        # Generated static site
└── style.css                         # Styles
```

## Attribution

This product uses the NVD API but is not endorsed or certified by the NVD.

NVD API documentation: https://nvd.nist.gov/developers/vulnerabilities

## License

MIT
