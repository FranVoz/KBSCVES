# KBSCVES — MS Patch & CVE Dashboard

## Project overview

Single-file SPA (`ms-patch-dashboard.html`) for French-speaking MSP/IT admins.
Fetches live Microsoft patch data, correlates KBs to CVEs, generates PowerShell audit scripts.
No build system. No dependencies. Open directly in browser.

## Architecture

```
ms-patch-dashboard.html   ← entire app: HTML + CSS + JS in one file
```

**Data source:** MSRC API v2.0 — `https://api.msrc.microsoft.com/cvrf/v2.0`
- `/updates` — list of available months (last ~18)
- `/cvrf/{monthId}` — CVRF document for a given Patch Tuesday month

**State object `S`:**
- `S.vulns[]` — parsed vulnerability objects
- `S.kbMap` — `Map<kbId, { kb, cves[], products Set, maxSev, hasExpl }>`
- `S.prodMap` — `Map<productId, name>`
- `S.month` — current selected month ID

## Tabs

| Tab | Panel ID | Description |
|-----|----------|-------------|
| Dashboard | `panel-dashboard` | Stats + top exploited/critical CVEs |
| KBs | `panel-kbs` | Filterable KB table with severity, CVE count |
| CVEs | `panel-cves` | Filterable CVE table with CVSS, exploit flags |
| KB ↔ CVE | `panel-mapping` | Bidirectional mapping cards |
| PowerShell | `panel-ps` | Dynamic script generator + 5 utility scripts |

## PowerShell generator — script types

- `kb-local` — check KB on local machine
- `kb-remote` — check KB on multiple machines via WinRM
- `cve-local` — check CVE exposure (looks for any corrective KB)
- `cve-remote` — CVE exposure on multiple machines
- `audit` — full month audit: pulls critical/exploited KBs from loaded data

## Key functions

| Function | Purpose |
|----------|---------|
| `loadData()` | Fetches `/updates`, populates month selector, triggers `loadMonth()` |
| `loadMonth(id)` | Fetches CVRF, calls `parseCVRF()`, renders all panels |
| `parseCVRF(cvrf)` | Extracts vulns + product map from MSRC CVRF JSON |
| `buildKBMap(vulns)` | Builds KB→CVEs map from parsed vulns |
| `renderDash/KBs/CVEs/Map()` | Re-render respective panel (called after filter changes) |
| `buildScript()` | Regenerates PS script from generator form state |
| `showCVE/showKB(id)` | Opens detail modal |
| `quickKB/quickCVE(id)` | Jumps to PS tab with that KB/CVE pre-filled |

## Severity handling

`SEV_ORD = { Critical:4, Important:3, Moderate:2, Low:1 }` — used for sorting and comparison.
Severity extracted from CVRF `Threats[].Description.Value` (must be in `SEV_VALS`); falls back to CVSS score ranges.

## KB extraction from CVRF

Two strategies per vulnerability:
1. `Remediations` where `Type === 2` ("Vendor Fix") and `Description.Value` is a 5-7 digit number → `"KB" + digits`
2. `Remediations[].URL` matching `?q=KB\d+`

## Known constraints

- **CORS**: MSRC API must be reachable from the browser. Some browsers/environments block cross-origin requests to `api.msrc.microsoft.com`. Error message reminds user to check CORS/connection.
- **No auth**: MSRC API is public, no key needed.
- **Single file**: all CSS, JS, and HTML inline. Keep it that way unless explicitly asked to split.

## Language

UI is in French. All user-facing strings, comments in PS scripts, and variable names in PS scripts stay French. Code JS/CSS identifiers stay in English.

## Always-on instructions

- **instruct_00** — Après chaque tâche terminée, conclure avec un court récapitulatif : une phrase sur ce qui a été demandé, une phrase sur ce qui a été fait.
