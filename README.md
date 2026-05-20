# 🛡️ MS Patch & CVE Dashboard

Single-file web dashboard that aggregates Microsoft Patch Tuesday data — KBs, CVEs, severity ratings, exploited vulnerabilities — and links them together. Includes a PowerShell script generator for auditing Windows machines.

**Live site:** https://franvoz.github.io/KBSCVES/

---

## Features

- KB and CVE tables with severity, CVSS scores, exploit flags
- KB ↔ CVE bidirectional mapping
- Filter/search across KBs, CVEs, products
- Click-through detail modals with links to MSRC advisories and NVD
- PowerShell script generator (local check, remote/MSP check, full audit)
- CSV export
- Pre-cached static data — works offline once loaded

## Data sources

| Source | Used when |
|--------|-----------|
| **MSRC** (Microsoft Security Response Center) | Pre-fetched via `fetch-data.js` — full KB mapping |
| **NVD/NIST** | Live fallback when no cache available — CVE data only, KB mapping partial |

## Update data locally

Requires Node.js 18+.

```bash
node fetch-data.js              # last 6 months (default)
node fetch-data.js --months 12  # last 12 months
```

Then commit and push `data/*.json` to refresh the live site.

## Deploy

Pure static site — no server, no build step. Deploy `ms-patch-dashboard.html` + `data/` to any static host (GitHub Pages, Netlify, Vercel, S3, etc.).

## Project structure

```
ms-patch-dashboard.html   # entire frontend (HTML + CSS + JS)
fetch-data.js             # data update script (run locally)
data/                     # pre-fetched monthly JSON files
  2026-May.json
  2026-Apr.json
  ...
```

---

## ⚠️ Disclaimer

**This project is provided as-is, with no warranties of any kind, express or implied.**

- Data accuracy depends entirely on the MSRC and NVD APIs. No guarantee that data is complete, current, or error-free.
- **Do not use this tool as the sole basis for security decisions in production environments.**
- Not affiliated with Microsoft or NIST.
- Use at your own risk.
