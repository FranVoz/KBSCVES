#!/usr/bin/env node
// Fetch MS patch data (MSRC preferred, NVD fallback) → saves data/{month}.json
// Usage: node fetch-data.js [--months 6]
// Requires Node 18+ (built-in fetch)

const fs   = require('fs');
const path = require('path');

const MSRC    = 'https://api.msrc.microsoft.com/cvrf/v2.0';
const NVD     = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const MON     = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const DATADIR = path.join(__dirname, 'data');

const args   = process.argv.slice(2);
const nMonths = parseInt(args[args.indexOf('--months') + 1] || '6');

// ── helpers ──────────────────────────────────────────────────────────────────

async function get(url, headers = {}) {
  const r = await fetch(url, { headers: { Accept: 'application/json', ...headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return r.json();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function monthIds(n) {
  const ids = [];
  const now = new Date();
  for (let i = 0; i < n; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    ids.push(`${d.getFullYear()}-${MON[d.getMonth()]}`);
  }
  return ids;
}

// ── MSRC parser (mirrors HTML parseCVRF) ─────────────────────────────────────

const SEV_VALS = new Set(['Critical','Important','Moderate','Low']);

function parseCVRF(cvrf) {
  const pm = new Map();
  (cvrf.ProductTree?.FullProductName || []).forEach(p => pm.set(String(p.ProductID), p.Value));

  const vulns = (cvrf.Vulnerability || []).map(v => {
    const threats = v.Threats || [];
    const sevT = threats.find(t => SEV_VALS.has(t.Description?.Value));
    let severity = sevT?.Description?.Value || 'Unknown';
    if (severity === 'Unknown' && v.CVSSScoreSets?.[0]?.BaseScore) {
      const s = v.CVSSScoreSets[0].BaseScore;
      severity = s >= 9 ? 'Critical' : s >= 7 ? 'Important' : s >= 4 ? 'Moderate' : 'Low';
    }

    const exploited = threats.some(t => {
      const val = (t.Description?.Value || '').toLowerCase();
      return val === 'exploited:yes' || val.includes('exploitation detected');
    });
    const pubDisc = threats.some(t =>
      (t.Description?.Value || '').toLowerCase().includes('publicly disclosed:yes')
    );

    const kbs = [];
    (v.Remediations || []).forEach(r => {
      const isVF = r.Type === 2 || r.Type === '2' || String(r.Type).toLowerCase() === 'vendor fix';
      if (isVF) {
        const val = (r.Description?.Value || '').trim();
        if (/^\d{5,7}$/.test(val)) { const kb = 'KB'+val; if (!kbs.includes(kb)) kbs.push(kb); }
      }
      const m = (r.URL || '').match(/[?&]q=(KB\d+)/i);
      if (m && !kbs.includes(m[1].toUpperCase())) kbs.push(m[1].toUpperCase());
    });

    const pids = new Set();
    (v.ProductStatuses || []).forEach(ps => (ps.ProductID || []).forEach(id => pids.add(String(id))));
    const products = [...pids].map(id => pm.get(id)).filter(Boolean);

    return {
      cveId: v.CVE,
      title: v.Title?.Value || v.CVE || '',
      severity,
      exploited,
      pubDisc,
      kbs,
      products,
      cvss: v.CVSSScoreSets?.[0]?.BaseScore || null,
      desc: (v.Notes || []).find(n => n.Type === 1 || n.Type === 'Description')?.Value || '',
    };
  });

  return vulns;
}

// ── NVD parser (mirrors HTML parseNVD) ───────────────────────────────────────

function parseNVD(data) {
  return (data.vulnerabilities || []).map(item => {
    const cve  = item.cve;
    const m31  = cve.metrics?.cvssMetricV31?.[0];
    const m30  = cve.metrics?.cvssMetricV30?.[0];
    const met  = m31 || m30;
    const cvss = met?.cvssData?.baseScore ?? null;
    const nvdSev = met?.cvssData?.baseSeverity || '';
    const SEV_MAP = { CRITICAL:'Critical', HIGH:'Important', MEDIUM:'Moderate', LOW:'Low' };
    const severity = SEV_MAP[nvdSev] ||
      (cvss >= 9 ? 'Critical' : cvss >= 7 ? 'Important' : cvss >= 4 ? 'Moderate' : 'Low');

    const desc  = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const title = desc.length > 120 ? desc.substring(0, 120) + '…' : (desc || cve.id);

    const kbs = [];
    (cve.references || []).forEach(ref => {
      const u = ref.url || '';
      const m = u.match(/(?:\/help\/|\/kb\/)(\d{6,7})\b/i);
      if (m) { const kb = 'KB'+m[1]; if (!kbs.includes(kb)) kbs.push(kb); }
      const m2 = u.match(/[?&]q=(KB\d+)/i);
      if (m2) { const kb = m2[1].toUpperCase(); if (!kbs.includes(kb)) kbs.push(kb); }
    });

    return {
      cveId: cve.id, title, severity,
      exploited: !!cve.cisaExploitAdd,
      pubDisc: false, kbs, products: [], cvss, desc,
    };
  });
}

// ── fetch one month ───────────────────────────────────────────────────────────

async function fetchMonth(monthId) {
  // Try MSRC first (no CORS server-side)
  try {
    process.stdout.write(`  MSRC… `);
    const cvrf = await get(`${MSRC}/cvrf/${monthId}`);
    const vulns = parseCVRF(cvrf);
    console.log(`✓ ${vulns.length} CVEs (MSRC)`);
    return { vulns, source: 'MSRC' };
  } catch (e) {
    console.log(`✗ MSRC: ${e.message}`);
  }

  // Fall back to NVD
  try {
    process.stdout.write(`  NVD…  `);
    const [yr, mon] = monthId.split('-');
    const y = parseInt(yr), m = MON.indexOf(mon);
    if (m < 0) throw new Error('invalid month: ' + monthId);
    const start = new Date(Date.UTC(y, m, 1));
    const end   = new Date(Date.UTC(y, m + 1, 0, 23, 59, 59));
    const fmt   = d => d.toISOString().replace(/\.\d{3}Z$/, '.000');
    const url   = `${NVD}?sourceIdentifier=secure%40microsoft.com&pubStartDate=${fmt(start)}&pubEndDate=${fmt(end)}&resultsPerPage=2000`;
    const data  = await get(url);
    const vulns = parseNVD(data);
    console.log(`✓ ${vulns.length} CVEs (NVD)`);
    return { vulns, source: 'NVD' };
  } catch (e) {
    console.log(`✗ NVD: ${e.message}`);
    return null;
  }
}

// ── main ─────────────────────────────────────────────────────────────────────

(async () => {
  if (!fs.existsSync(DATADIR)) fs.mkdirSync(DATADIR);

  const ids = monthIds(nMonths);
  console.log(`Fetching ${ids.length} months: ${ids.join(', ')}\n`);

  let ok = 0, fail = 0;
  for (const monthId of ids) {
    console.log(`[${monthId}]`);
    const result = await fetchMonth(monthId);
    if (result) {
      const file = path.join(DATADIR, `${monthId}.json`);
      fs.writeFileSync(file, JSON.stringify({
        month:   monthId,
        fetched: new Date().toISOString(),
        source:  result.source,
        vulns:   result.vulns,
      }));
      console.log(`  → saved ${file}`);
      ok++;
    } else {
      console.log(`  → SKIPPED (no data)`);
      fail++;
    }
    // NVD rate limit: 5 req/30s → 1 req/6s to be safe
    if (ids.indexOf(monthId) < ids.length - 1) await sleep(6000);
  }

  console.log(`\nDone: ${ok} saved, ${fail} failed.`);
})();
