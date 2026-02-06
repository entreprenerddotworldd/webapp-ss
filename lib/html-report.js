#!/usr/bin/env node
/**
 * html-report.js - Generates a consolidated HTML security dashboard
 * from all webapp-ss scan results (JSON + text files in the report dir).
 *
 * Usage: node html-report.js <report-dir> [project-name]
 */

const fs = require("fs");
const path = require("path");

const reportDir = process.argv[2];
const projectName = process.argv[3] || path.basename(process.cwd());

if (!reportDir || !fs.existsSync(reportDir)) {
  console.error("Usage: node html-report.js <report-dir> [project-name]");
  process.exit(1);
}

// ─── Data Loaders ──────────────────────────────────────────

function loadJSON(filename) {
  const p = path.join(reportDir, filename);
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function loadJSONL(filename) {
  const p = path.join(reportDir, filename);
  if (!fs.existsSync(p) || fs.statSync(p).size === 0) return [];
  try {
    return fs
      .readFileSync(p, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function loadText(filename) {
  const p = path.join(reportDir, filename);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p, "utf8");
}

function esc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Filtered Data Loader ──────────────────────────────────

const filteredData = loadJSON("filtered-results.json");
const hasFiltered = filteredData !== null;

// ─── Parse Results ─────────────────────────────────────────

function parseSemgrep() {
  // Prefer filtered results
  if (hasFiltered && filteredData.semgrep) {
    const actionable = filteredData.semgrep.actionable || [];
    const suppressed = filteredData.semgrep.suppressed || [];
    const rawCount = actionable.length + suppressed.length;
    const bySev = {};
    for (const r of actionable) {
      const sev = (r.extra || {}).severity || "UNKNOWN";
      if (!bySev[sev]) bySev[sev] = [];
      bySev[sev].push({
        path: r.path || "?",
        line: (r.start || {}).line || "?",
        message: (r.extra || {}).message || "No description",
        fix: (r.extra || {}).fix || "",
        ruleId: r.check_id || "",
      });
    }
    return {
      total: actionable.length,
      rawTotal: rawCount,
      suppressed: suppressed.length,
      bySeverity: bySev,
      isFiltered: true,
    };
  }

  const data = loadJSON("semgrep.json");
  if (!data) return null;
  const results = data.results || [];
  const bySev = {};
  for (const r of results) {
    const sev = (r.extra || {}).severity || "UNKNOWN";
    if (!bySev[sev]) bySev[sev] = [];
    bySev[sev].push({
      path: r.path || "?",
      line: (r.start || {}).line || "?",
      message: (r.extra || {}).message || "No description",
      fix: (r.extra || {}).fix || "",
      ruleId: r.check_id || "",
    });
  }
  return { total: results.length, bySeverity: bySev, isFiltered: false };
}

function parseTrivy() {
  // If filtered + deduplicated SCA data exists, use that
  if (hasFiltered && filteredData.sca) {
    const results = filteredData.sca.results || [];
    return {
      total: results.length,
      rawTotal: filteredData.summary?.trivy?.raw || results.length,
      suppressed: (filteredData.summary?.trivy?.suppressed || 0) + (filteredData.summary?.dependencyCheck?.suppressed || 0),
      duplicatesRemoved: filteredData.sca.duplicatesRemoved || 0,
      vulns: results.map(v => ({
        pkg: v.pkg || "?",
        version: v.version || "?",
        fixed: v.fixed || "no fix yet",
        id: v.id || "?",
        severity: v.severity || "?",
        title: v.title || "",
        url: v.url || "",
      })),
      isFiltered: true,
    };
  }

  const data = loadJSON("trivy.json");
  if (!data) return null;
  const vulns = [];
  for (const r of data.Results || []) {
    for (const v of r.Vulnerabilities || []) {
      vulns.push({
        pkg: v.PkgName || "?",
        version: v.InstalledVersion || "?",
        fixed: v.FixedVersion || "no fix yet",
        id: v.VulnerabilityID || "?",
        severity: v.Severity || "?",
        title: v.Title || "",
        url: v.PrimaryURL || "",
      });
    }
  }
  return { total: vulns.length, vulns, isFiltered: false };
}

function parseNuclei() {
  if (hasFiltered && filteredData.nuclei) {
    const actionable = filteredData.nuclei.actionable || [];
    const suppressed = filteredData.nuclei.suppressed || [];
    return {
      total: actionable.length,
      rawTotal: actionable.length + suppressed.length,
      suppressed: suppressed.length,
      findings: actionable.map((f) => ({
        name: (f.info || {}).name || "?",
        severity: (f.info || {}).severity || "?",
        description: (f.info || {}).description || "",
        matched: f["matched-at"] || "",
      })),
      isFiltered: true,
    };
  }

  const findings = loadJSONL("nuclei.json");
  return {
    total: findings.length,
    findings: findings.map((f) => ({
      name: (f.info || {}).name || "?",
      severity: (f.info || {}).severity || "?",
      description: (f.info || {}).description || "",
      matched: f["matched-at"] || "",
    })),
    isFiltered: false,
  };
}

function parseGitleaks() {
  const data = loadJSON("gitleaks.json");
  if (!data || !Array.isArray(data)) return null;
  return {
    total: data.length,
    leaks: data.map((l) => ({
      rule: l.RuleID || "?",
      file: l.File || "?",
      line: l.StartLine || "?",
      match: (l.Match || "").substring(0, 60),
    })),
  };
}

function parseZap() {
  const data = loadJSON("zap-baseline.json");
  if (!data) return null;
  const site = (data.site || [])[0] || {};
  const alerts = site.alerts || [];
  return {
    total: alerts.length,
    alerts: alerts.map((a) => ({
      name: a.name || "?",
      risk: (a.riskdesc || "Unknown").split(" ")[0],
      description: a.desc || "",
      solution: a.solution || "",
      count: parseInt(a.count || "0", 10),
    })),
  };
}

function parseHeaders() {
  const text = loadText("headers-report.txt");
  if (!text) return null;
  const lines = text.split("\n");
  const passMatch = text.match(/Passed:\s*(\d+)/);
  const warnMatch = text.match(/Warnings:\s*(\d+)/);
  const failMatch = text.match(/Failures:\s*(\d+)/);
  return {
    passed: passMatch ? parseInt(passMatch[1]) : 0,
    warnings: warnMatch ? parseInt(warnMatch[1]) : 0,
    failures: failMatch ? parseInt(failMatch[1]) : 0,
    raw: loadText("raw-headers.txt"),
  };
}

function parseProdReadiness() {
  const text = loadText("prod-readiness.txt");
  if (!text) return null;
  const scoreMatch = text.match(/Score:\s*(\d+)%/);
  const lines = text.split("\n").filter((l) => l.startsWith("["));
  const checks = lines.map((l) => {
    const statusMatch = l.match(/^\[(\w+)\]/);
    const fixMatch = l.match(/FIX:\s*(.+)/);
    return {
      status: statusMatch ? statusMatch[1] : "?",
      message: l.replace(/^\[\w+\]\s*/, "").replace(/\s*FIX:.*/, ""),
      fix: fixMatch ? fixMatch[1] : "",
    };
  });
  return {
    score: scoreMatch ? parseInt(scoreMatch[1]) : null,
    checks,
  };
}

// ─── HTML Generation ───────────────────────────────────────

function severityBadge(sev) {
  const colors = {
    CRITICAL: "#dc2626",
    ERROR: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#d97706",
    WARNING: "#d97706",
    LOW: "#2563eb",
    INFO: "#6b7280",
    INFORMATIONAL: "#6b7280",
  };
  const color = colors[(sev || "").toUpperCase()] || "#6b7280";
  return `<span class="badge" style="background:${color}">${esc(sev)}</span>`;
}

function statusIcon(status) {
  switch ((status || "").toUpperCase()) {
    case "PASS":
      return '<span class="status-pass">PASS</span>';
    case "FAIL":
      return '<span class="status-fail">FAIL</span>';
    case "WARN":
      return '<span class="status-warn">WARN</span>';
    default:
      return `<span class="status-info">${esc(status)}</span>`;
  }
}

function scoreGauge(score) {
  if (score === null || score === undefined) return "";
  let color = "#dc2626";
  if (score >= 80) color = "#16a34a";
  else if (score >= 60) color = "#d97706";
  else if (score >= 40) color = "#ea580c";

  return `
    <div class="gauge">
      <svg viewBox="0 0 120 120" width="140" height="140">
        <circle cx="60" cy="60" r="50" fill="none" stroke="#1e293b" stroke-width="10"/>
        <circle cx="60" cy="60" r="50" fill="none" stroke="${color}" stroke-width="10"
          stroke-dasharray="${(score / 100) * 314} 314"
          stroke-linecap="round" transform="rotate(-90 60 60)"/>
        <text x="60" y="55" text-anchor="middle" fill="${color}" font-size="28" font-weight="bold">${score}</text>
        <text x="60" y="75" text-anchor="middle" fill="#94a3b8" font-size="12">/ 100</text>
      </svg>
    </div>`;
}

function filterBanner() {
  const parts = [];
  const s = filteredData && filteredData.summary;
  if (s) {
    if (s.semgrep) parts.push("SAST: " + s.semgrep.suppressed + " suppressed");
    if (s.sca) parts.push("SCA: " + s.sca.duplicatesRemoved + " duplicates removed");
    if (s.trivy) parts.push("Trivy: " + s.trivy.suppressed + " false positives");
    if (s.nuclei) parts.push("Nuclei: " + s.nuclei.suppressed + " suppressed");
  }
  const detail = parts.length
    ? '<br><span style="color:var(--text-muted);font-size:0.8rem">' + parts.join(" | ") + "</span>"
    : "";
  return '<div style="background:rgba(56,189,248,0.08);border:1px solid var(--accent);border-radius:8px;padding:0.75rem 1.25rem;margin-bottom:1rem;font-size:0.85rem;color:var(--accent);">' +
    "<strong>Filtered Report</strong> &mdash; False positives, duplicates, and noise have been removed. Counts reflect actionable findings only." +
    detail + "</div>";
}

function buildHTML() {
  const semgrep = parseSemgrep();
  const trivy = parseTrivy();
  const gitleaks = parseGitleaks();
  const zap = parseZap();
  const nuclei = parseNuclei();
  const headers = parseHeaders();
  const prod = parseProdReadiness();

  const timestamp = new Date().toISOString();

  // Compute summary stats
  let totalIssues = 0;
  let criticalCount = 0;
  const sections = [];

  if (semgrep) {
    totalIssues += semgrep.total;
    criticalCount += (semgrep.bySeverity["ERROR"] || []).length;
    sections.push("SAST");
  }
  if (trivy) {
    totalIssues += trivy.total;
    criticalCount += trivy.vulns.filter((v) => v.severity === "CRITICAL").length;
    sections.push("SCA");
  }
  if (gitleaks && gitleaks.total > 0) {
    totalIssues += gitleaks.total;
    criticalCount += gitleaks.total;
    sections.push("Secrets");
  }
  if (zap) {
    totalIssues += zap.total;
    criticalCount += zap.alerts.filter((a) => a.risk === "High").length;
    sections.push("DAST");
  }
  if (nuclei) {
    totalIssues += nuclei.total;
    sections.push("Nuclei");
  }
  if (headers) sections.push("Headers");
  if (prod) sections.push("Prod Readiness");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>webapp-ss Security Report - ${esc(projectName)}</title>
<style>
  :root {
    --bg: #0f172a;
    --surface: #1e293b;
    --surface2: #334155;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --green: #4ade80;
    --red: #f87171;
    --yellow: #fbbf24;
    --orange: #fb923c;
    --border: #334155;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
  }
  h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
  h2 {
    font-size: 1.3rem;
    color: var(--accent);
    margin: 2rem 0 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }
  h3 { font-size: 1rem; color: var(--text-muted); margin: 1rem 0 0.5rem; }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 2px solid var(--accent);
  }
  .header-meta { color: var(--text-muted); font-size: 0.85rem; }
  .summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .card {
    background: var(--surface);
    border-radius: 8px;
    padding: 1.25rem;
    border: 1px solid var(--border);
  }
  .card-label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .card-value { font-size: 2rem; font-weight: 700; margin: 0.25rem 0; }
  .card-value.green { color: var(--green); }
  .card-value.red { color: var(--red); }
  .card-value.yellow { color: var(--yellow); }
  .card-value.orange { color: var(--orange); }

  .section { background: var(--surface); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid var(--border); }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .section-title { font-size: 1.1rem; font-weight: 600; }
  .section-count { background: var(--surface2); padding: 0.2rem 0.7rem; border-radius: 12px; font-size: 0.8rem; }

  table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; font-size: 0.85rem; }
  th { text-align: left; padding: 0.6rem 0.8rem; background: var(--surface2); color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }
  td { padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: rgba(56, 189, 248, 0.04); }

  .badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
  }
  .fix-text { color: var(--green); font-size: 0.8rem; margin-top: 0.25rem; }
  .mono { font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 0.8rem; }

  .status-pass { color: var(--green); font-weight: 700; }
  .status-fail { color: var(--red); font-weight: 700; }
  .status-warn { color: var(--yellow); font-weight: 700; }
  .status-info { color: var(--text-muted); font-weight: 700; }

  .gauge { text-align: center; margin: 1rem 0; }
  .verdict { text-align: center; font-size: 1.2rem; font-weight: 700; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
  .verdict.pass { background: rgba(74, 222, 128, 0.1); color: var(--green); border: 1px solid var(--green); }
  .verdict.warn { background: rgba(251, 191, 36, 0.1); color: var(--yellow); border: 1px solid var(--yellow); }
  .verdict.fail { background: rgba(248, 113, 113, 0.1); color: var(--red); border: 1px solid var(--red); }

  .empty { color: var(--text-muted); font-style: italic; padding: 1rem; text-align: center; }

  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .nav { position: sticky; top: 0; background: var(--bg); padding: 0.75rem 0; margin-bottom: 1rem; z-index: 10; border-bottom: 1px solid var(--border); display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .nav a {
    padding: 0.3rem 0.75rem;
    background: var(--surface);
    border-radius: 6px;
    font-size: 0.8rem;
    border: 1px solid var(--border);
  }
  .nav a:hover { background: var(--surface2); text-decoration: none; }

  @media print {
    body { background: #fff; color: #111; }
    .nav { display: none; }
    .card, .section { border: 1px solid #ddd; }
    .badge { border: 1px solid currentColor; }
  }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>webapp-ss Security Report</h1>
    <div class="header-meta">
      Project: <strong>${esc(projectName)}</strong> &nbsp;|&nbsp;
      Generated: ${timestamp} &nbsp;|&nbsp;
      Scanners: ${sections.join(", ") || "None"}
    </div>
  </div>
  ${prod ? scoreGauge(prod.score) : ""}
</div>

<div class="summary-cards">
  <div class="card">
    <div class="card-label">${hasFiltered ? "Actionable Issues" : "Total Issues"}</div>
    <div class="card-value ${totalIssues === 0 ? "green" : totalIssues > 10 ? "red" : "orange"}">${totalIssues}</div>
  </div>
  <div class="card">
    <div class="card-label">Critical / High</div>
    <div class="card-value ${criticalCount === 0 ? "green" : "red"}">${criticalCount}</div>
  </div>
  ${
    prod
      ? `<div class="card">
    <div class="card-label">Prod Readiness</div>
    <div class="card-value ${(prod.score || 0) >= 80 ? "green" : (prod.score || 0) >= 60 ? "yellow" : "red"}">${prod.score !== null ? prod.score + "%" : "N/A"}</div>
  </div>`
      : ""
  }
  ${
    headers
      ? `<div class="card">
    <div class="card-label">Headers</div>
    <div class="card-value ${headers.failures === 0 ? "green" : "red"}">${headers.passed}/${headers.passed + headers.warnings + headers.failures}</div>
  </div>`
      : ""
  }
  ${
    gitleaks
      ? `<div class="card">
    <div class="card-label">Leaked Secrets</div>
    <div class="card-value ${gitleaks.total === 0 ? "green" : "red"}">${gitleaks.total}</div>
  </div>`
      : ""
  }
</div>

${hasFiltered ? filterBanner() : ""}

<nav class="nav">
  ${semgrep ? '<a href="#sast">SAST</a>' : ""}
  ${trivy ? '<a href="#sca">SCA</a>' : ""}
  ${gitleaks ? '<a href="#secrets">Secrets</a>' : ""}
  ${zap ? '<a href="#dast-zap">ZAP</a>' : ""}
  ${nuclei && nuclei.total > 0 ? '<a href="#dast-nuclei">Nuclei</a>' : ""}
  ${headers ? '<a href="#headers">Headers</a>' : ""}
  ${prod ? '<a href="#prod">Prod Readiness</a>' : ""}
</nav>

${
  semgrep
    ? `
<div class="section" id="sast">
  <div class="section-header">
    <span class="section-title">SAST - Static Code Analysis (Semgrep)</span>
    <span class="section-count">${semgrep.total} actionable${semgrep.isFiltered ? ` (${semgrep.suppressed} noise filtered from ${semgrep.rawTotal} raw)` : ` finding${semgrep.total !== 1 ? "s" : ""}`}</span>
  </div>
  ${
    semgrep.total === 0
      ? '<div class="empty">No issues found.</div>'
      : `<table>
    <tr><th>Severity</th><th>Location</th><th>Issue</th><th>Fix</th></tr>
    ${Object.entries(semgrep.bySeverity)
      .sort(([a], [b]) => {
        const order = { ERROR: 0, WARNING: 1, INFO: 2 };
        return (order[a] ?? 3) - (order[b] ?? 3);
      })
      .flatMap(([sev, items]) =>
        items.map(
          (item) => `
      <tr>
        <td>${severityBadge(sev)}</td>
        <td class="mono">${esc(item.path)}:${item.line}</td>
        <td>${esc(item.message)}</td>
        <td>${item.fix ? `<div class="fix-text">${esc(item.fix)}</div>` : '<span style="color:var(--text-muted)">See rule docs</span>'}</td>
      </tr>`
        )
      )
      .join("")}
  </table>`
  }
</div>`
    : ""
}

${
  trivy
    ? `
<div class="section" id="sca">
  <div class="section-header">
    <span class="section-title">SCA - Dependency Vulnerabilities (Trivy)</span>
    <span class="section-count">${trivy.total} actionable CVE${trivy.total !== 1 ? "s" : ""}${trivy.isFiltered ? ` (${trivy.suppressed} false positives + ${trivy.duplicatesRemoved || 0} duplicates removed)` : ""}</span>
  </div>
  ${
    trivy.total === 0
      ? '<div class="empty">No HIGH/CRITICAL vulnerabilities in dependencies.</div>'
      : `<table>
    <tr><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed In</th><th>CVE</th></tr>
    ${trivy.vulns
      .sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      })
      .map(
        (v) => `
      <tr>
        <td>${severityBadge(v.severity)}</td>
        <td class="mono">${esc(v.pkg)}</td>
        <td class="mono">${esc(v.version)}</td>
        <td class="mono fix-text">${esc(v.fixed)}</td>
        <td>${v.url ? `<a href="${esc(v.url)}" target="_blank">${esc(v.id)}</a>` : esc(v.id)}</td>
      </tr>`
      )
      .join("")}
  </table>`
  }
</div>`
    : ""
}

${
  gitleaks
    ? `
<div class="section" id="secrets">
  <div class="section-header">
    <span class="section-title">Secret Detection (Gitleaks)</span>
    <span class="section-count">${gitleaks.total} leak${gitleaks.total !== 1 ? "s" : ""}</span>
  </div>
  ${
    gitleaks.total === 0
      ? '<div class="empty">No leaked secrets detected.</div>'
      : `<table>
    <tr><th>Rule</th><th>File</th><th>Line</th><th>Match (truncated)</th><th>Fix</th></tr>
    ${gitleaks.leaks
      .map(
        (l) => `
      <tr>
        <td>${severityBadge("CRITICAL")}&nbsp;${esc(l.rule)}</td>
        <td class="mono">${esc(l.file)}</td>
        <td>${l.line}</td>
        <td class="mono">${esc(l.match)}...</td>
        <td class="fix-text">Remove secret, rotate credential, use env vars or secret manager</td>
      </tr>`
      )
      .join("")}
  </table>`
  }
</div>`
    : ""
}

${
  zap
    ? `
<div class="section" id="dast-zap">
  <div class="section-header">
    <span class="section-title">DAST - Live Scan (OWASP ZAP)</span>
    <span class="section-count">${zap.total} alert type${zap.total !== 1 ? "s" : ""}</span>
  </div>
  ${
    zap.total === 0
      ? '<div class="empty">No issues found during live scanning.</div>'
      : `<table>
    <tr><th>Risk</th><th>Alert</th><th>Instances</th><th>Fix</th></tr>
    ${zap.alerts
      .sort((a, b) => {
        const order = { High: 0, Medium: 1, Low: 2, Informational: 3 };
        return (order[a.risk] ?? 4) - (order[b.risk] ?? 4);
      })
      .map(
        (a) => `
      <tr>
        <td>${severityBadge(a.risk)}</td>
        <td>${esc(a.name)}</td>
        <td>${a.count}</td>
        <td class="fix-text">${esc(a.solution).substring(0, 200)}</td>
      </tr>`
      )
      .join("")}
  </table>`
  }
</div>`
    : ""
}

${
  nuclei && nuclei.total > 0
    ? `
<div class="section" id="dast-nuclei">
  <div class="section-header">
    <span class="section-title">DAST - Vulnerability Templates (Nuclei)</span>
    <span class="section-count">${nuclei.total} actionable${nuclei.isFiltered ? ` (${nuclei.suppressed} filtered from ${nuclei.rawTotal} raw)` : ` finding${nuclei.total !== 1 ? "s" : ""}`}</span>
  </div>
  <table>
    <tr><th>Severity</th><th>Name</th><th>Matched URL</th><th>Description</th></tr>
    ${nuclei.findings
      .map(
        (f) => `
      <tr>
        <td>${severityBadge(f.severity)}</td>
        <td>${esc(f.name)}</td>
        <td class="mono">${esc(f.matched)}</td>
        <td>${esc(f.description).substring(0, 200)}</td>
      </tr>`
      )
      .join("")}
  </table>
</div>`
    : ""
}

${
  headers
    ? `
<div class="section" id="headers">
  <div class="section-header">
    <span class="section-title">Security Headers Analysis</span>
    <span class="section-count">${headers.passed} pass, ${headers.warnings} warn, ${headers.failures} fail</span>
  </div>
  <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; margin-bottom: 1rem;">
    <div class="card"><div class="card-label">Passed</div><div class="card-value green" style="font-size:1.5rem">${headers.passed}</div></div>
    <div class="card"><div class="card-label">Warnings</div><div class="card-value yellow" style="font-size:1.5rem">${headers.warnings}</div></div>
    <div class="card"><div class="card-label">Failures</div><div class="card-value red" style="font-size:1.5rem">${headers.failures}</div></div>
  </div>
  ${
    headers.raw
      ? `<h3>Raw Response Headers</h3><pre style="background:var(--surface2);padding:1rem;border-radius:6px;overflow-x:auto;font-size:0.8rem;">${esc(headers.raw)}</pre>`
      : ""
  }
</div>`
    : ""
}

${
  prod
    ? `
<div class="section" id="prod">
  <div class="section-header">
    <span class="section-title">Production Readiness Assessment</span>
    <span class="section-count">Score: ${prod.score !== null ? prod.score + "%" : "N/A"}</span>
  </div>
  ${scoreGauge(prod.score)}
  ${
    prod.score !== null
      ? prod.score >= 80
        ? '<div class="verdict pass">READY FOR PRODUCTION</div>'
        : prod.score >= 60
          ? '<div class="verdict warn">NEEDS ATTENTION</div>'
          : '<div class="verdict fail">NOT READY FOR PRODUCTION</div>'
      : ""
  }
  ${
    prod.checks.length > 0
      ? `<table>
    <tr><th>Status</th><th>Check</th><th>Remediation</th></tr>
    ${prod.checks
      .map(
        (c) => `
      <tr>
        <td>${statusIcon(c.status)}</td>
        <td>${esc(c.message)}</td>
        <td>${c.fix ? `<div class="fix-text">${esc(c.fix)}</div>` : ""}</td>
      </tr>`
      )
      .join("")}
  </table>`
      : ""
  }
</div>`
    : ""
}

<div style="text-align:center; color:var(--text-muted); font-size:0.75rem; margin-top:3rem; padding-top:1rem; border-top:1px solid var(--border);">
  Generated by <strong>webapp-ss</strong> &mdash; ${timestamp}
</div>

</body>
</html>`;
}

// ─── Main ──────────────────────────────────────────────────

const html = buildHTML();
const outPath = path.join(reportDir, "security-report.html");
fs.writeFileSync(outPath, html);
console.log(`[+] HTML report generated: ${outPath}`);
