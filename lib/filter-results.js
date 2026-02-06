#!/usr/bin/env node
/**
 * filter-results.js - Intelligence layer for webapp-ss
 *
 * Reads raw scan results and produces filtered output by:
 * 1. Deduplicating CVEs across scanners (Trivy + Dependency-Check)
 * 2. Filtering non-shipped code (node_modules/examples, test fixtures)
 * 3. Classifying semgrep findings (mitigated pattern detection)
 * 4. Removing known false positive patterns
 * 5. Applying user-configured suppressions
 *
 * Usage: node filter-results.js <report-dir> [config-path]
 */

const fs = require("fs");
const path = require("path");

const reportDir = process.argv[2];
const configPath = process.argv[3];

if (!reportDir || !fs.existsSync(reportDir)) {
  console.error("Usage: node filter-results.js <report-dir> [webapp-ss.config.cjs]");
  process.exit(1);
}

// Load config if provided
let config = { filters: {} };
if (configPath && fs.existsSync(configPath)) {
  try {
    delete require.cache[require.resolve(path.resolve(configPath))];
    config = require(path.resolve(configPath));
  } catch {}
}
const filters = config.filters || {};

// ─── Helpers ───────────────────────────────────────────────

function loadJSON(filename) {
  const p = path.join(reportDir, filename);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}

function loadJSONL(filename) {
  const p = path.join(reportDir, filename);
  if (!fs.existsSync(p) || fs.statSync(p).size === 0) return [];
  try {
    return fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map(l => JSON.parse(l));
  } catch { return []; }
}

// Paths that indicate non-shipped code (examples, tests, demos inside deps)
const NON_SHIPPED_PATTERNS = [
  /node_modules\/.*\/examples?\//i,
  /node_modules\/.*\/test\//i,
  /node_modules\/.*\/tests?\//i,
  /node_modules\/.*\/demo\//i,
  /node_modules\/.*\/fixtures?\//i,
  /node_modules\/.*\/benchmark\//i,
  /node_modules\/.*\/docs?\//i,
  /node_modules\/.*\/samples?\//i,
  /\.min\.js$/,
];

function isNonShippedPath(filePath) {
  return NON_SHIPPED_PATTERNS.some(p => p.test(filePath));
}

// ─── Semgrep Filtering ────────────────────────────────────

// Patterns that indicate a finding is already mitigated
const MITIGATED_PATTERNS = {
  // path.join with path traversal - safe when input is from DB lookup, slugify, or hardcoded
  "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal": {
    safePatterns: [
      /slugify\s*\(/,         // Input sanitized by slugify
      /getTenantsDir\(\)/,    // Deterministic base path
      /templateName/,         // Covered by runtime whitelist
      /__dirname/,            // Relative to code directory
    ],
    check: "context",
  },
  // Format string injection in Node.js console.log - not exploitable
  "javascript.lang.security.audit.unsafe-formatstring": {
    reason: "Node.js console.log does not process C-style format specifiers (%n, %x). Not exploitable.",
    autoSuppress: true,
  },
};

// Semgrep rules that are informational noise in most Node.js/React projects
const LOW_VALUE_RULES = new Set([
  "javascript.lang.security.audit.unsafe-formatstring",
]);

function filterSemgrep() {
  const data = loadJSON("semgrep.json");
  if (!data) return null;

  const raw = data.results || [];
  const userIgnoreRules = new Set(filters.semgrep?.ignoreRules || []);
  const userIgnorePaths = filters.semgrep?.ignorePaths || [];

  const filtered = [];
  const suppressed = [];

  for (const r of raw) {
    const ruleId = r.check_id || "";
    const filePath = r.path || "";
    const severity = (r.extra || {}).severity || "UNKNOWN";

    // User-configured rule suppression
    if (userIgnoreRules.has(ruleId)) {
      suppressed.push({ ...r, _reason: "User-configured rule suppression" });
      continue;
    }

    // User-configured path suppression
    if (userIgnorePaths.some(p => filePath.includes(p))) {
      suppressed.push({ ...r, _reason: "User-configured path suppression" });
      continue;
    }

    // Non-shipped code
    if (isNonShippedPath(filePath)) {
      suppressed.push({ ...r, _reason: "Non-shipped code (examples/tests in node_modules)" });
      continue;
    }

    // Suppress all INFO findings when configured (these are informational, not vulnerabilities)
    if (filters.semgrep?.suppressInfoFindings !== false && severity === "INFO") {
      suppressed.push({ ...r, _reason: "INFO-level finding suppressed (informational, not a vulnerability)" });
      continue;
    }

    // Known low-value rules (non-INFO that are still not exploitable)
    if (LOW_VALUE_RULES.has(ruleId)) {
      suppressed.push({ ...r, _reason: MITIGATED_PATTERNS[ruleId]?.reason || "Low-value finding" });
      continue;
    }

    // Auto-suppress rules marked as non-exploitable
    const mitigation = MITIGATED_PATTERNS[ruleId];
    if (mitigation?.autoSuppress) {
      suppressed.push({ ...r, _reason: mitigation.reason });
      continue;
    }

    filtered.push(r);
  }

  return {
    raw: raw.length,
    filtered: filtered.length,
    suppressed: suppressed.length,
    results: filtered,
    suppressedResults: suppressed,
  };
}

// ─── SCA Filtering (Trivy + Dependency-Check) ─────────────

function filterTrivy() {
  const data = loadJSON("trivy.json");
  if (!data) return null;

  const userIgnoreCVEs = new Set(filters.sca?.ignoreCVEs || []);
  const raw = [];
  const filtered = [];
  const suppressed = [];

  for (const r of data.Results || []) {
    const target = r.Target || "";
    for (const v of r.Vulnerabilities || []) {
      const entry = { ...v, _target: target };
      raw.push(entry);

      const cveId = v.VulnerabilityID || "";

      // User-suppressed CVEs
      if (userIgnoreCVEs.has(cveId)) {
        suppressed.push({ ...entry, _reason: "User-configured CVE suppression" });
        continue;
      }

      // Non-shipped paths
      if (isNonShippedPath(target)) {
        suppressed.push({ ...entry, _reason: "Non-shipped dependency (examples/tests)" });
        continue;
      }

      // Check if the vuln has a fix and if installed version matches the fix
      const installed = v.InstalledVersion || "";
      const fixed = v.FixedVersion || "";
      if (fixed && installed === fixed) {
        suppressed.push({ ...entry, _reason: "Already on fixed version" });
        continue;
      }

      filtered.push(entry);
    }
  }

  return {
    raw: raw.length,
    filtered: filtered.length,
    suppressed: suppressed.length,
    results: filtered,
    suppressedResults: suppressed,
  };
}

function filterDependencyCheck() {
  const data = loadJSON("dependency-check-report.json");
  if (!data) return null;

  const userIgnoreCVEs = new Set(filters.sca?.ignoreCVEs || []);
  const deps = data.dependencies || [];
  const raw = [];
  const filtered = [];
  const suppressed = [];

  for (const dep of deps) {
    const vulns = dep.vulnerabilities || [];
    if (vulns.length === 0) continue;

    const filePath = dep.filePath || dep.fileName || "";

    for (const v of vulns) {
      const entry = {
        name: v.name || "",
        severity: v.severity || "",
        cvssScore: v.cvssv3?.baseScore || v.cvssv2?.score || 0,
        description: v.description || "",
        source: v.source || "",
        pkg: dep.fileName || "",
        filePath,
      };
      raw.push(entry);

      // User-suppressed
      if (userIgnoreCVEs.has(v.name)) {
        suppressed.push({ ...entry, _reason: "User-configured CVE suppression" });
        continue;
      }

      // Non-shipped paths (examples, tests, demos inside deps)
      if (isNonShippedPath(filePath)) {
        suppressed.push({ ...entry, _reason: "Non-shipped dependency (examples/tests/demos)" });
        continue;
      }

      // Known false positive: jQuery in globalize examples
      if (filePath.includes("globalize") && filePath.includes("examples") &&
          (v.name || "").includes("CVE") && filePath.includes("jquery")) {
        suppressed.push({ ...entry, _reason: "jQuery in globalize examples - not bundled or shipped" });
        continue;
      }

      filtered.push(entry);
    }
  }

  return {
    raw: raw.length,
    filtered: filtered.length,
    suppressed: suppressed.length,
    results: filtered,
    suppressedResults: suppressed,
  };
}

// ─── CVE Deduplication ────────────────────────────────────

function deduplicateCVEs(trivyResults, dcResults) {
  if (!trivyResults && !dcResults) return null;

  const seen = new Map(); // CVE ID -> best entry
  const all = [];

  // Trivy findings (prefer these - usually more accurate metadata)
  if (trivyResults) {
    for (const v of trivyResults.results) {
      const id = v.VulnerabilityID || "";
      if (id && !seen.has(id)) {
        seen.set(id, {
          id,
          source: "trivy",
          pkg: v.PkgName || "?",
          version: v.InstalledVersion || "?",
          fixed: v.FixedVersion || "no fix yet",
          severity: v.Severity || "?",
          title: v.Title || "",
          url: v.PrimaryURL || "",
        });
      }
    }
  }

  // DC findings - add only if not already seen from Trivy
  if (dcResults) {
    for (const v of dcResults.results) {
      const id = v.name || "";
      if (id && !seen.has(id)) {
        seen.set(id, {
          id,
          source: "dependency-check",
          pkg: v.pkg || "?",
          version: "?",
          fixed: "see NVD",
          severity: v.severity || "?",
          title: v.description ? v.description.substring(0, 120) : "",
          url: `https://nvd.nist.gov/vuln/detail/${id}`,
          cvssScore: v.cvssScore,
        });
      }
    }
  }

  const deduped = Array.from(seen.values());

  // Count how many were duplicates
  const trivyCount = trivyResults ? trivyResults.filtered : 0;
  const dcCount = dcResults ? dcResults.filtered : 0;
  const duplicatesRemoved = (trivyCount + dcCount) - deduped.length;

  return {
    total: deduped.length,
    duplicatesRemoved,
    results: deduped.sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    }),
  };
}

// ─── Nuclei Filtering ─────────────────────────────────────

function filterNuclei() {
  const findings = loadJSONL("nuclei.json");
  if (findings.length === 0) return null;

  const userIgnoreTemplates = new Set(filters.nuclei?.ignoreTemplates || []);
  const filtered = [];
  const suppressed = [];

  for (const f of findings) {
    const templateId = f["template-id"] || f.templateID || "";
    const info = f.info || {};
    const matchedAt = f["matched-at"] || "";
    const severity = (info.severity || "").toLowerCase();

    // User-suppressed templates
    if (userIgnoreTemplates.has(templateId)) {
      suppressed.push({ ...f, _reason: "User-configured template suppression" });
      continue;
    }

    // Version-detection-only templates that match on headers not actual vuln
    // These templates detect technology presence, not confirmed vulnerabilities
    const headerOnlyPatterns = [
      /tech-detect/i,
      /version-detect/i,
      /fingerprint/i,
    ];
    if (headerOnlyPatterns.some(p => p.test(templateId))) {
      suppressed.push({ ...f, _reason: "Technology detection only, not confirmed vulnerability" });
      continue;
    }

    filtered.push(f);
  }

  return {
    raw: findings.length,
    filtered: filtered.length,
    suppressed: suppressed.length,
    results: filtered,
    suppressedResults: suppressed,
  };
}

// ─── Main ──────────────────────────────────────────────────

const semgrep = filterSemgrep();
const trivy = filterTrivy();
const dc = filterDependencyCheck();
const sca = deduplicateCVEs(trivy, dc);
const nuclei = filterNuclei();

const summary = {
  timestamp: new Date().toISOString(),
  semgrep: semgrep ? { raw: semgrep.raw, actionable: semgrep.filtered, suppressed: semgrep.suppressed } : null,
  sca: sca ? { total: sca.total, duplicatesRemoved: sca.duplicatesRemoved } : null,
  trivy: trivy ? { raw: trivy.raw, actionable: trivy.filtered, suppressed: trivy.suppressed } : null,
  dependencyCheck: dc ? { raw: dc.raw, actionable: dc.filtered, suppressed: dc.suppressed } : null,
  nuclei: nuclei ? { raw: nuclei.raw, actionable: nuclei.filtered, suppressed: nuclei.suppressed } : null,
};

// Write filtered results
const output = {
  _meta: {
    version: "1.0",
    generated: summary.timestamp,
    description: "Filtered and deduplicated security scan results from webapp-ss",
  },
  summary,
  semgrep: semgrep ? { actionable: semgrep.results, suppressed: semgrep.suppressedResults } : null,
  sca: sca || null,
  nuclei: nuclei ? { actionable: nuclei.results, suppressed: nuclei.suppressedResults } : null,
};

const outPath = path.join(reportDir, "filtered-results.json");
fs.writeFileSync(outPath, JSON.stringify(output, null, 2));

// Print summary
console.log("");
console.log("=== FILTERED RESULTS (noise removed) ===");
console.log("");

if (semgrep) {
  const pct = semgrep.raw > 0 ? Math.round((semgrep.suppressed / semgrep.raw) * 100) : 0;
  console.log(`  SAST:    ${semgrep.filtered} actionable / ${semgrep.raw} raw (${pct}% noise removed)`);
  if (semgrep.filtered > 0) {
    // Group by severity
    const bySev = {};
    for (const r of semgrep.results) {
      const sev = (r.extra || {}).severity || "UNKNOWN";
      bySev[sev] = (bySev[sev] || 0) + 1;
    }
    const parts = Object.entries(bySev).map(([s, c]) => `${c} ${s}`).join(", ");
    console.log(`           ${parts}`);
  }
}

if (sca) {
  console.log(`  SCA:     ${sca.total} unique CVEs (${sca.duplicatesRemoved} duplicates removed)`);
  if (sca.total > 0) {
    const bySev = {};
    for (const r of sca.results) {
      bySev[r.severity] = (bySev[r.severity] || 0) + 1;
    }
    const parts = Object.entries(bySev).map(([s, c]) => `${c} ${s}`).join(", ");
    console.log(`           ${parts}`);
    for (const r of sca.results.slice(0, 5)) {
      console.log(`           - [${r.severity}] ${r.pkg}@${r.version} (${r.id}) -> ${r.fixed}`);
    }
  }
}

if (trivy && dc) {
  const totalSuppressed = (trivy.suppressed || 0) + (dc.suppressed || 0);
  if (totalSuppressed > 0) {
    console.log(`           (${totalSuppressed} false positives filtered from raw scans)`);
  }
}

if (nuclei) {
  const pct = nuclei.raw > 0 ? Math.round((nuclei.suppressed / nuclei.raw) * 100) : 0;
  console.log(`  DAST:    ${nuclei.filtered} actionable / ${nuclei.raw} raw (${pct}% noise removed)`);
}

console.log("");
console.log(`  [*] Filtered results: ${outPath}`);
console.log("");
