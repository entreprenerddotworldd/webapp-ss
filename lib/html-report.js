#!/usr/bin/env node
/**
 * html-report.js - Generates a security dashboard from webapp-ss scan results.
 *
 * Usage: node html-report.js <report-dir> [project-name] [project-dir]
 */

const fs = require("fs");
const path = require("path");

const reportDir = process.argv[2];
const projectName = process.argv[3] || path.basename(process.cwd());
const projectDir = process.argv[4] || null;

if (!reportDir || !fs.existsSync(reportDir)) {
  console.error(
    "Usage: node html-report.js <report-dir> [project-name] [project-dir]",
  );
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
    const raw = fs.readFileSync(p, "utf8").trim();
    // Handle both JSON array format and JSONL (one object per line)
    if (raw.startsWith("[")) {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [parsed];
    }
    return raw
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

// ─── Source Code Reader ────────────────────────────────────

const _fileCache = {};

function readSourceLine(filePath, lineNum, contextLines) {
  if (!projectDir || !filePath || !lineNum) return null;
  contextLines = contextLines || 1;

  // Resolve: semgrep paths often have leading /
  let resolved = filePath.startsWith("/")
    ? path.join(projectDir, filePath)
    : path.join(projectDir, filePath);

  if (!_fileCache[resolved]) {
    try {
      if (!fs.existsSync(resolved)) return null;
      _fileCache[resolved] = fs.readFileSync(resolved, "utf8").split("\n");
    } catch {
      return null;
    }
  }

  const lines = _fileCache[resolved];
  const start = Math.max(0, lineNum - 1 - contextLines);
  const end = Math.min(lines.length, lineNum + contextLines);
  const result = [];
  for (let i = start; i < end; i++) {
    result.push({
      num: i + 1,
      text: lines[i] || "",
      highlight: i + 1 === lineNum,
    });
  }
  return result;
}

// ─── Filtered Data ─────────────────────────────────────────

const filteredData = loadJSON("filtered-results.json");
const hasFiltered = filteredData !== null;

// ─── Remediation Database ──────────────────────────────────

const REMEDIATION = {
  "path-join-resolve-traversal": {
    title: "Path Traversal Prevention",
    fix: "Validate that user-supplied path segments cannot escape the intended directory. Use path.resolve() and verify the result starts with the allowed base directory. Consider using an allowlist of valid values.",
    example:
      'const base = path.resolve(allowedDir);\nconst target = path.resolve(allowedDir, userInput);\nif (!target.startsWith(base)) throw new Error("Path traversal blocked");',
  },
  "detect-non-literal-regexp": {
    title: "RegExp Injection / ReDoS Prevention",
    fix: "Never construct RegExp from unsanitized user input. Escape all special regex characters first, or use a safe regex library like re2.",
    example:
      'function escapeRegExp(s) {\n  return s.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");\n}\nconst safeRe = new RegExp(escapeRegExp(userInput));',
  },
  "detect-child-process": {
    title: "Command Injection Prevention",
    fix: "Never pass unsanitized input to child_process.exec(). Use execFile() with an argument array, or validate input against an allowlist.",
    example:
      "const { execFile } = require('child_process');\nexecFile('/usr/bin/cmd', [validatedArg], callback);",
  },
  "eval-injection": {
    title: "Code Injection Prevention",
    fix: "Never use eval(), new Function(), or vm.runInNewContext() with user input. Use JSON.parse() for data, or a sandboxed interpreter.",
    example: "",
  },
  "sql-injection": {
    title: "SQL Injection Prevention",
    fix: "Always use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
    example: "db.query('SELECT * FROM users WHERE id = $1', [userId]);",
  },
  "xss": {
    title: "Cross-Site Scripting Prevention",
    fix: "Always escape or sanitize user input before rendering in HTML. Use framework auto-escaping (React JSX, template engines with escaping enabled).",
    example: "",
  },
};

function getRemediation(ruleId) {
  const shortId = (ruleId || "").split(".").pop();
  for (const [key, val] of Object.entries(REMEDIATION)) {
    if (shortId.includes(key) || (ruleId || "").includes(key)) return val;
  }
  return null;
}

// ─── Security Headers Database ─────────────────────────────

const EXPECTED_HEADERS = {
  "strict-transport-security": {
    importance: "critical",
    name: "Strict-Transport-Security",
    desc: "Forces HTTPS connections, prevents downgrade attacks",
    fix: "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  "content-security-policy": {
    importance: "critical",
    name: "Content-Security-Policy",
    desc: "Prevents XSS, code injection, and data theft",
    fix: "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'",
  },
  "x-content-type-options": {
    importance: "high",
    name: "X-Content-Type-Options",
    desc: "Prevents MIME type sniffing attacks",
    fix: "Add header: X-Content-Type-Options: nosniff",
  },
  "x-frame-options": {
    importance: "high",
    name: "X-Frame-Options",
    desc: "Prevents clickjacking by blocking framing",
    fix: "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
  },
  "referrer-policy": {
    importance: "medium",
    name: "Referrer-Policy",
    desc: "Controls how much referrer info is shared",
    fix: "Add header: Referrer-Policy: strict-origin-when-cross-origin",
  },
  "permissions-policy": {
    importance: "medium",
    name: "Permissions-Policy",
    desc: "Restricts browser feature access (camera, mic, etc.)",
    fix: "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
  },
  "cross-origin-opener-policy": {
    importance: "low",
    name: "Cross-Origin-Opener-Policy",
    desc: "Isolates browsing context from cross-origin popups",
    fix: "Add header: Cross-Origin-Opener-Policy: same-origin",
  },
};

const DANGEROUS_HEADERS = {
  "x-powered-by": {
    name: "X-Powered-By",
    desc: "Reveals technology stack to attackers",
    fix: 'Remove this header (Express: app.disable("x-powered-by"))',
  },
  server: {
    name: "Server",
    desc: "Reveals server software and version",
    fix: "Remove or anonymize the Server header",
  },
};

// ─── Parse Functions ───────────────────────────────────────

function parseSemgrepGrouped() {
  let findings = [];

  if (hasFiltered && filteredData.semgrep) {
    findings = filteredData.semgrep.actionable || [];
  } else {
    const data = loadJSON("semgrep.json");
    if (!data) return null;
    findings = data.results || [];
  }

  if (findings.length === 0)
    return {
      total: 0,
      groups: [],
      rawTotal: hasFiltered
        ? (filteredData.semgrep.actionable || []).length +
          (filteredData.semgrep.suppressed || []).length
        : 0,
      suppressed: hasFiltered
        ? (filteredData.semgrep.suppressed || []).length
        : 0,
      isFiltered: hasFiltered,
    };

  // Group by rule ID
  const groupMap = {};
  for (const r of findings) {
    const ruleId = r.check_id || "unknown";
    const extra = r.extra || {};
    const meta = extra.metadata || {};

    if (!groupMap[ruleId]) {
      groupMap[ruleId] = {
        ruleId,
        shortId: ruleId.split(".").pop(),
        severity: extra.severity || "UNKNOWN",
        message: extra.message || "",
        owasp: (meta.owasp || []).map((o) =>
          o.replace(/^A\d+:\d+ - /, "").trim(),
        ),
        cwe: (meta.cwe || []).map((c) => c.replace(/^CWE-\d+:\s*/, "").trim()),
        cweIds: (meta.cwe || []).map((c) => {
          const m = c.match(/CWE-(\d+)/);
          return m ? "CWE-" + m[1] : c;
        }),
        confidence: meta.confidence || "",
        impact: meta.impact || "",
        likelihood: meta.likelihood || "",
        vulnClass: (meta.vulnerability_class || []).join(", "),
        references: meta.references || [],
        source: meta.source || meta.shortlink || "",
        files: {},
        totalInstances: 0,
      };
    }

    const filePath = r.path || "?";
    const line = (r.start || {}).line || 0;

    if (!groupMap[ruleId].files[filePath]) {
      groupMap[ruleId].files[filePath] = [];
    }
    groupMap[ruleId].files[filePath].push(line);
    groupMap[ruleId].totalInstances++;
  }

  // Convert files map to array and read code snippets
  const groups = Object.values(groupMap).map((g) => {
    g.fileList = Object.entries(g.files).map(([fp, lines]) => ({
      path: fp,
      lines: [...new Set(lines)].sort((a, b) => a - b),
      snippets: [...new Set(lines)]
        .sort((a, b) => a - b)
        .slice(0, 3)
        .map((ln) => ({ line: ln, code: readSourceLine(fp, ln, 1) }))
        .filter((s) => s.code),
    }));
    delete g.files;
    return g;
  });

  // Sort: ERROR > WARNING > INFO, then by instance count desc
  const sevOrder = { ERROR: 0, WARNING: 1, INFO: 2 };
  groups.sort(
    (a, b) =>
      (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3) ||
      b.totalInstances - a.totalInstances,
  );

  const rawTotal = hasFiltered
    ? findings.length + (filteredData.semgrep.suppressed || []).length
    : findings.length;

  return {
    total: findings.length,
    rawTotal,
    suppressed: hasFiltered
      ? (filteredData.semgrep.suppressed || []).length
      : 0,
    groups,
    isFiltered: hasFiltered,
  };
}

function parseSCA() {
  if (hasFiltered && filteredData.sca) {
    const results = filteredData.sca.results || [];
    return {
      total: results.length,
      rawTotal:
        (filteredData.summary?.trivy?.raw || 0) +
        (filteredData.summary?.dependencyCheck?.raw || 0),
      suppressed:
        (filteredData.summary?.trivy?.suppressed || 0) +
        (filteredData.summary?.dependencyCheck?.suppressed || 0),
      duplicatesRemoved: filteredData.sca.duplicatesRemoved || 0,
      vulns: results.map((v) => ({
        pkg: v.pkg || "?",
        version: v.version || "?",
        fixed: v.fixed || "no fix yet",
        id: v.id || "?",
        severity: (v.severity || "?").toUpperCase(),
        title: v.title || "",
        url:
          v.url ||
          (v.id && v.id.startsWith("CVE")
            ? "https://nvd.nist.gov/vuln/detail/" + v.id
            : ""),
        cvssScore: v.cvssScore || null,
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
        severity: (v.Severity || "?").toUpperCase(),
        title: v.Title || "",
        url:
          v.PrimaryURL ||
          (v.VulnerabilityID
            ? "https://nvd.nist.gov/vuln/detail/" + v.VulnerabilityID
            : ""),
        cvssScore: v.CVSS
          ? Object.values(v.CVSS)[0]?.V3Score || null
          : null,
      });
    }
  }
  return { total: vulns.length, vulns, isFiltered: false };
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
      cweid: a.cweid || "",
      wascid: a.wascid || "",
      reference: a.reference || "",
    })),
  };
}

function parseNucleiEnriched() {
  let findings = [];

  if (hasFiltered && filteredData.nuclei) {
    findings = (filteredData.nuclei.actionable || []).flat();
  } else {
    findings = loadJSONL("nuclei.json");
  }

  const suppressed =
    hasFiltered && filteredData.nuclei
      ? (filteredData.nuclei.suppressed || []).length
      : 0;

  return {
    total: findings.length,
    rawTotal: findings.length + suppressed,
    suppressed,
    findings: findings.map((f) => {
      const info = f.info || {};
      return {
        name: info.name || "?",
        severity: (info.severity || "unknown").toUpperCase(),
        description: info.description || "",
        matched: f["matched-at"] || "",
        remediation: info.remediation || "",
        references: info.reference || [],
        tags: info.tags || [],
        templateId: f["template-id"] || f.templateID || "",
        cvss: info.classification?.cvss_score || null,
      };
    }),
    isFiltered: hasFiltered,
  };
}

function parseHeadersStructured() {
  const raw = loadText("raw-headers.txt");
  const reportText = loadText("headers-report.txt");

  if (!raw && !reportText) return null;

  // Parse raw headers into a map
  const headerMap = {};
  if (raw) {
    for (const line of raw.split("\n")) {
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0 && !line.startsWith("HTTP/")) {
        const name = line.substring(0, colonIdx).trim().toLowerCase();
        const value = line.substring(colonIdx + 1).trim();
        headerMap[name] = value;
      }
    }
  }

  // Check expected headers
  const present = [];
  const missing = [];
  for (const [key, info] of Object.entries(EXPECTED_HEADERS)) {
    if (headerMap[key]) {
      present.push({ ...info, value: headerMap[key] });
    } else {
      missing.push(info);
    }
  }

  // Check dangerous headers
  const dangerous = [];
  for (const [key, info] of Object.entries(DANGEROUS_HEADERS)) {
    if (headerMap[key]) {
      dangerous.push({ ...info, value: headerMap[key] });
    }
  }

  // Parse report text for counts if available
  let reportCounts = null;
  if (reportText) {
    const passMatch = reportText.match(/Passed:\s*(\d+)/);
    const warnMatch = reportText.match(/Warnings:\s*(\d+)/);
    const failMatch = reportText.match(/Failures:\s*(\d+)/);
    reportCounts = {
      passed: passMatch ? parseInt(passMatch[1]) : 0,
      warnings: warnMatch ? parseInt(warnMatch[1]) : 0,
      failures: failMatch ? parseInt(failMatch[1]) : 0,
    };
  }

  return {
    present,
    missing,
    dangerous,
    headerMap,
    raw,
    reportCounts,
    totalChecked: Object.keys(EXPECTED_HEADERS).length,
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
      message: l
        .replace(/^\[\w+\]\s*/, "")
        .replace(/\s*FIX:.*/, "")
        .trim(),
      fix: fixMatch ? fixMatch[1] : "",
    };
  });

  // Sort: FAIL first, then WARN, then PASS
  const statusOrder = { FAIL: 0, WARN: 1, PASS: 2 };
  checks.sort(
    (a, b) =>
      (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3),
  );

  return {
    score: scoreMatch ? parseInt(scoreMatch[1]) : null,
    checks,
  };
}

// ─── Security Grade Calculator ─────────────────────────────

function calcSecurityGrade(semgrep, sca, gitleaks, zap, nuclei, headers, prod) {
  let score = 100;

  // Secrets are critical
  if (gitleaks && gitleaks.total > 0) {
    score -= Math.min(40, gitleaks.total * 20);
  }

  // DAST high/critical findings
  if (nuclei) {
    for (const f of nuclei.findings) {
      if (f.severity === "CRITICAL") score -= 15;
      else if (f.severity === "HIGH") score -= 10;
      else if (f.severity === "MEDIUM") score -= 4;
    }
  }

  if (zap) {
    for (const a of zap.alerts) {
      if (a.risk === "High") score -= 10;
      else if (a.risk === "Medium") score -= 4;
    }
  }

  // SCA vulnerabilities
  if (sca) {
    for (const v of sca.vulns) {
      if (v.severity === "CRITICAL") score -= 12;
      else if (v.severity === "HIGH") score -= 7;
      else if (v.severity === "MEDIUM") score -= 3;
    }
  }

  // SAST findings (discounted by confidence)
  if (semgrep) {
    for (const g of semgrep.groups) {
      const confDiscount = g.confidence === "LOW" ? 0.3 : g.confidence === "MEDIUM" ? 0.6 : 1;
      const basePenalty = g.severity === "ERROR" ? 8 : g.severity === "WARNING" ? 3 : 1;
      // Penalty per group, not per instance (diminishing returns)
      score -= Math.round(basePenalty * confDiscount);
    }
  }

  // Missing critical headers
  if (headers) {
    for (const h of headers.missing) {
      if (h.importance === "critical") score -= 5;
      else if (h.importance === "high") score -= 3;
    }
    for (const h of headers.dangerous) score -= 3;
  }

  // Prod readiness failures
  if (prod) {
    for (const c of prod.checks) {
      if (c.status === "FAIL") score -= 8;
      else if (c.status === "WARN") score -= 2;
    }
  }

  score = Math.max(0, Math.min(100, score));

  let grade, gradeColor;
  if (score >= 90) { grade = "A"; gradeColor = "#16a34a"; }
  else if (score >= 80) { grade = "B"; gradeColor = "#4ade80"; }
  else if (score >= 70) { grade = "C"; gradeColor = "#d97706"; }
  else if (score >= 55) { grade = "D"; gradeColor = "#ea580c"; }
  else { grade = "F"; gradeColor = "#dc2626"; }

  return { score, grade, gradeColor };
}

// ─── Executive Summary Generator ───────────────────────────

function generateActions(semgrep, sca, gitleaks, zap, nuclei, headers, prod) {
  const actions = [];

  // 1. Leaked secrets
  if (gitleaks && gitleaks.total > 0) {
    actions.push({
      priority: "CRITICAL",
      title: "Rotate " + gitleaks.total + " leaked credential" + (gitleaks.total > 1 ? "s" : ""),
      detail: "Gitleaks detected secrets in your code or git history. These must be rotated immediately as they may already be compromised.",
      fix: "1. Rotate every detected credential\n2. Add secrets to .gitignore\n3. Use environment variables or a secret manager\n4. Consider using git-filter-repo to purge from history",
    });
  }

  // 2. Critical/High DAST findings
  if (nuclei) {
    for (const f of nuclei.findings) {
      if (f.severity === "CRITICAL" || f.severity === "HIGH") {
        actions.push({
          priority: f.severity,
          title: f.name + (f.templateId ? " (" + f.templateId + ")" : ""),
          detail: f.description.replace(/\n/g, " ").trim(),
          fix: f.remediation
            ? f.remediation.replace(/\n/g, " ").trim()
            : "See references for remediation steps.",
        });
      }
    }
  }

  // 3. Critical/High ZAP findings
  if (zap) {
    for (const a of zap.alerts) {
      if (a.risk === "High") {
        actions.push({
          priority: "HIGH",
          title: a.name + " (OWASP ZAP)",
          detail: (a.description || "").replace(/<[^>]+>/g, "").substring(0, 200),
          fix: (a.solution || "").replace(/<[^>]+>/g, "").substring(0, 200),
        });
      }
    }
  }

  // 4. Critical/High SCA vulnerabilities
  if (sca) {
    for (const v of sca.vulns) {
      if (v.severity === "CRITICAL" || v.severity === "HIGH") {
        actions.push({
          priority: v.severity,
          title: "Update " + v.pkg + " - " + v.id,
          detail: v.title || v.id + " in " + v.pkg + "@" + v.version,
          fix: v.fixed !== "no fix yet" && v.fixed !== "see NVD"
            ? "Upgrade to " + v.pkg + "@" + v.fixed
            : "Check " + (v.url || "NVD") + " for available patches",
        });
      }
    }
  }

  // 5. SAST rule groups (grouped, not per-instance)
  if (semgrep) {
    for (const g of semgrep.groups) {
      const fileCount = g.fileList.length;
      const confNote = g.confidence === "LOW"
        ? " (LOW confidence - verify manually)"
        : g.confidence === "MEDIUM"
          ? " (MEDIUM confidence)"
          : "";

      const remediation = getRemediation(g.ruleId);
      actions.push({
        priority: g.severity === "ERROR" ? "HIGH" : "MEDIUM",
        title: g.vulnClass || g.shortId + " (" + g.totalInstances + " instances in " + fileCount + " file" + (fileCount > 1 ? "s" : "") + ")" + confNote,
        detail: g.message.substring(0, 200),
        fix: remediation ? remediation.fix : "Review flagged code and apply input validation.",
      });
    }
  }

  // 6. Medium SCA
  if (sca) {
    for (const v of sca.vulns) {
      if (v.severity === "MEDIUM") {
        actions.push({
          priority: "MEDIUM",
          title: "Update " + v.pkg + " - " + v.id,
          detail: v.title || v.id,
          fix: v.fixed !== "no fix yet" && v.fixed !== "see NVD"
            ? "Upgrade to " + v.pkg + "@" + v.fixed
            : "Check " + (v.url || "NVD") + " for patches",
        });
      }
    }
  }

  // 7. Prod readiness failures
  if (prod) {
    for (const c of prod.checks) {
      if (c.status === "FAIL") {
        actions.push({
          priority: "HIGH",
          title: c.message,
          detail: "Production readiness check failed.",
          fix: c.fix,
        });
      }
    }
  }

  // 8. Missing critical security headers
  if (headers) {
    const critMissing = headers.missing.filter((h) => h.importance === "critical");
    if (critMissing.length > 0) {
      actions.push({
        priority: "MEDIUM",
        title: "Add missing security headers: " + critMissing.map((h) => h.name).join(", "),
        detail: "Critical security headers are missing from HTTP responses.",
        fix: critMissing.map((h) => h.fix).join("\n"),
      });
    }
    if (headers.dangerous.length > 0) {
      actions.push({
        priority: "LOW",
        title: "Remove information-leaking headers: " + headers.dangerous.map((h) => h.name).join(", "),
        detail: "These headers expose your technology stack to potential attackers.",
        fix: headers.dangerous.map((h) => h.fix).join("\n"),
      });
    }
  }

  // Deduplicate and cap
  return actions.slice(0, 12);
}

// ─── HTML Helpers ──────────────────────────────────────────

function severityBadge(sev) {
  const colors = {
    CRITICAL: "#dc2626", ERROR: "#dc2626", HIGH: "#ea580c",
    MEDIUM: "#d97706", WARNING: "#d97706", LOW: "#2563eb",
    INFO: "#6b7280", INFORMATIONAL: "#6b7280",
  };
  const color = colors[(sev || "").toUpperCase()] || "#6b7280";
  return '<span class="badge" style="background:' + color + '">' + esc(sev) + "</span>";
}

function priorityBadge(priority) {
  return severityBadge(priority);
}

function confidenceBadge(confidence) {
  if (!confidence) return "";
  const colors = { HIGH: "#dc2626", MEDIUM: "#d97706", LOW: "#2563eb" };
  const color = colors[confidence] || "#6b7280";
  return '<span class="conf-badge" style="border-color:' + color + ";color:" + color + '">Confidence: ' + esc(confidence) + "</span>";
}

function owaspBadges(owasp, cweIds) {
  let html = "";
  if (cweIds && cweIds.length > 0) {
    for (const c of cweIds.slice(0, 3)) {
      html += '<span class="tag-badge cwe">' + esc(c) + "</span>";
    }
  }
  if (owasp && owasp.length > 0) {
    for (const o of owasp.slice(0, 2)) {
      html += '<span class="tag-badge owasp">' + esc(o) + "</span>";
    }
  }
  return html;
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
      return '<span class="status-info">' + esc(status) + "</span>";
  }
}

function codeBlock(snippets) {
  if (!snippets || snippets.length === 0) return "";
  let html = '<div class="code-block">';
  for (const s of snippets) {
    if (!s.code) continue;
    html += '<div class="code-snippet">';
    for (const line of s.code) {
      const cls = line.highlight ? "code-line highlight" : "code-line";
      html +=
        '<div class="' + cls + '"><span class="line-num">' + line.num + '</span><span class="line-text">' + esc(line.text) + "</span></div>";
    }
    html += "</div>";
  }
  html += "</div>";
  return html;
}

function gradeGauge(grade, gradeColor, score) {
  return '<div class="grade-gauge">' +
    '<svg viewBox="0 0 120 120" width="120" height="120">' +
    '<circle cx="60" cy="60" r="50" fill="none" stroke="#1e293b" stroke-width="10"/>' +
    '<circle cx="60" cy="60" r="50" fill="none" stroke="' + gradeColor + '" stroke-width="10" stroke-dasharray="' + ((score / 100) * 314) + ' 314" stroke-linecap="round" transform="rotate(-90 60 60)"/>' +
    '<text x="60" y="52" text-anchor="middle" fill="' + gradeColor + '" font-size="36" font-weight="bold">' + grade + "</text>" +
    '<text x="60" y="72" text-anchor="middle" fill="#94a3b8" font-size="11">' + score + " / 100</text>" +
    "</svg></div>";
}

// ─── Build HTML ────────────────────────────────────────────

function buildHTML() {
  const semgrep = parseSemgrepGrouped();
  const sca = parseSCA();
  const gitleaks = parseGitleaks();
  const zap = parseZap();
  const nuclei = parseNucleiEnriched();
  const headers = parseHeadersStructured();
  const prod = parseProdReadiness();

  const timestamp = new Date().toISOString();
  const security = calcSecurityGrade(semgrep, sca, gitleaks, zap, nuclei, headers, prod);
  const actions = generateActions(semgrep, sca, gitleaks, zap, nuclei, headers, prod);

  // Compute totals
  let totalIssues = 0;
  let criticalCount = 0;
  const scanners = [];

  if (semgrep && semgrep.total > 0) {
    totalIssues += semgrep.total;
    for (const g of semgrep.groups) {
      if (g.severity === "ERROR") criticalCount += g.totalInstances;
    }
    scanners.push("SAST");
  }
  if (sca && sca.total > 0) {
    totalIssues += sca.total;
    criticalCount += sca.vulns.filter((v) => v.severity === "CRITICAL" || v.severity === "HIGH").length;
    scanners.push("SCA");
  }
  if (gitleaks) {
    if (gitleaks.total > 0) {
      totalIssues += gitleaks.total;
      criticalCount += gitleaks.total;
    }
    scanners.push("Secrets");
  }
  if (zap) {
    totalIssues += zap.total;
    criticalCount += zap.alerts.filter((a) => a.risk === "High").length;
    scanners.push("ZAP");
  }
  if (nuclei && nuclei.total > 0) {
    totalIssues += nuclei.total;
    criticalCount += nuclei.findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length;
    scanners.push("Nuclei");
  }
  if (headers) scanners.push("Headers");
  if (prod) scanners.push("Prod");

  // ─── HTML Template ─────────────────────────────────────
  let html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">';
  html += '<meta name="viewport" content="width=device-width, initial-scale=1.0">';
  html += "<title>Security Report - " + esc(projectName) + "</title>";
  html += "<style>" + CSS() + "</style></head><body>";

  // Header
  html += '<div class="header"><div><h1>Security Report</h1>';
  html += '<div class="header-meta">';
  html += "Project: <strong>" + esc(projectName) + "</strong> &nbsp;|&nbsp; ";
  html += timestamp + " &nbsp;|&nbsp; ";
  html += "Scans: " + (scanners.join(", ") || "None");
  html += "</div></div>";
  html += gradeGauge(security.grade, security.gradeColor, security.score);
  html += "</div>";

  // Executive Summary
  if (actions.length > 0) {
    html += '<div class="section exec-summary" id="actions">';
    html += '<div class="section-header"><span class="section-title">Priority Actions</span>';
    html += '<span class="section-count">' + actions.length + " item" + (actions.length > 1 ? "s" : "") + "</span></div>";
    for (let i = 0; i < actions.length; i++) {
      const a = actions[i];
      html += '<div class="action-item">';
      html += '<div class="action-header">';
      html += '<span class="action-num">' + (i + 1) + "</span>";
      html += priorityBadge(a.priority);
      html += ' <strong>' + esc(a.title) + "</strong></div>";
      html += '<div class="action-detail">' + esc(a.detail) + "</div>";
      if (a.fix) {
        html += '<div class="action-fix"><strong>Fix:</strong> ' + esc(a.fix) + "</div>";
      }
      html += "</div>";
    }
    html += "</div>";
  }

  // Summary Cards
  html += '<div class="summary-cards">';
  html += '<div class="card"><div class="card-label">Security Grade</div>';
  html += '<div class="card-value" style="color:' + security.gradeColor + '">' + security.grade + "</div></div>";
  html += '<div class="card"><div class="card-label">' + (hasFiltered ? "Actionable" : "Total") + " Issues</div>";
  html += '<div class="card-value ' + (totalIssues === 0 ? "green" : totalIssues > 10 ? "red" : "orange") + '">' + totalIssues + "</div></div>";
  html += '<div class="card"><div class="card-label">Critical / High</div>';
  html += '<div class="card-value ' + (criticalCount === 0 ? "green" : "red") + '">' + criticalCount + "</div></div>";
  if (gitleaks) {
    html += '<div class="card"><div class="card-label">Leaked Secrets</div>';
    html += '<div class="card-value ' + (gitleaks.total === 0 ? "green" : "red") + '">' + gitleaks.total + "</div></div>";
  }
  if (prod) {
    html += '<div class="card"><div class="card-label">Prod Readiness</div>';
    const ps = prod.score || 0;
    html += '<div class="card-value ' + (ps >= 80 ? "green" : ps >= 60 ? "yellow" : "red") + '">' + (prod.score !== null ? prod.score + "%" : "N/A") + "</div></div>";
  }
  if (headers) {
    const hPresent = headers.present.length;
    html += '<div class="card"><div class="card-label">Headers</div>';
    html += '<div class="card-value ' + (headers.missing.length === 0 ? "green" : "orange") + '">' + hPresent + "/" + headers.totalChecked + "</div></div>";
  }
  html += "</div>";

  // Filter Banner
  if (hasFiltered) {
    const parts = [];
    const s = filteredData.summary;
    if (s) {
      if (s.semgrep && s.semgrep.suppressed) parts.push("SAST: " + s.semgrep.suppressed + " suppressed");
      if (s.sca && s.sca.duplicatesRemoved) parts.push("SCA: " + s.sca.duplicatesRemoved + " duplicates removed");
      if (s.trivy && s.trivy.suppressed) parts.push("Trivy: " + s.trivy.suppressed + " false positives");
      if (s.dependencyCheck && s.dependencyCheck.suppressed) parts.push("Dep-Check: " + s.dependencyCheck.suppressed + " false positives");
      if (s.nuclei && s.nuclei.suppressed) parts.push("Nuclei: " + s.nuclei.suppressed + " suppressed");
    }
    html += '<div class="filter-banner"><strong>Filtered Report</strong> &mdash; False positives, duplicates, and noise removed. Counts show actionable findings only.';
    if (parts.length) {
      html += '<br><span style="opacity:0.7;font-size:0.8rem">' + parts.join(" | ") + "</span>";
    }
    html += "</div>";
  }

  // Nav
  html += '<nav class="nav">';
  if (actions.length) html += '<a href="#actions">Actions</a>';
  if (semgrep && semgrep.total > 0) html += '<a href="#sast">SAST</a>';
  if (sca && sca.total > 0) html += '<a href="#sca">SCA</a>';
  if (gitleaks) html += '<a href="#secrets">Secrets</a>';
  if (zap && zap.total > 0) html += '<a href="#dast-zap">ZAP</a>';
  if (nuclei && nuclei.total > 0) html += '<a href="#dast-nuclei">Nuclei</a>';
  if (headers) html += '<a href="#headers">Headers</a>';
  if (prod) html += '<a href="#prod">Prod</a>';
  html += "</nav>";

  // ─── SAST Section ──────────────────────────────────────
  if (semgrep && semgrep.total > 0) {
    html += '<div class="section" id="sast">';
    html += '<div class="section-header"><span class="section-title">SAST &mdash; Static Code Analysis</span>';
    html += '<span class="section-count">' + semgrep.total + " actionable";
    if (semgrep.isFiltered) html += " (" + semgrep.suppressed + " noise filtered from " + semgrep.rawTotal + " raw)";
    html += "</span></div>";

    for (const g of semgrep.groups) {
      html += '<details class="rule-group" open>';
      html += "<summary>";
      html += severityBadge(g.severity) + " ";
      html += confidenceBadge(g.confidence) + " ";
      html += "<strong>" + esc(g.vulnClass || g.shortId) + "</strong>";
      html += ' <span class="instance-count">' + g.totalInstances + " instance" + (g.totalInstances > 1 ? "s" : "") + " in " + g.fileList.length + " file" + (g.fileList.length > 1 ? "s" : "") + "</span>";
      html += "</summary>";

      html += '<div class="rule-detail">';

      // Tags
      const tags = owaspBadges(g.owasp, g.cweIds);
      if (tags) html += '<div class="tag-row">' + tags + "</div>";

      // Description
      html += '<div class="rule-desc">' + esc(g.message) + "</div>";

      // Remediation
      const rem = getRemediation(g.ruleId);
      if (rem) {
        html += '<div class="remediation-box">';
        html += "<strong>" + esc(rem.title) + "</strong><br>";
        html += esc(rem.fix);
        if (rem.example) {
          html += '<pre class="code-example">' + esc(rem.example) + "</pre>";
        }
        html += "</div>";
      }

      // File list with code
      for (const f of g.fileList) {
        html += '<div class="file-entry">';
        html += '<div class="file-path">' + esc(f.path) + " &mdash; line" + (f.lines.length > 1 ? "s " : " ") + f.lines.join(", ") + "</div>";
        if (f.snippets.length > 0) {
          html += codeBlock(f.snippets);
        }
        html += "</div>";
      }

      // Rule reference link
      if (g.source) {
        html += '<div class="rule-link"><a href="' + esc(g.source) + '" target="_blank">View rule documentation</a></div>';
      }

      html += "</div></details>";
    }

    html += "</div>";
  } else if (semgrep) {
    html += '<div class="section" id="sast"><div class="section-header"><span class="section-title">SAST &mdash; Static Code Analysis</span></div>';
    html += '<div class="empty">No actionable findings.</div></div>';
  }

  // ─── SCA Section ───────────────────────────────────────
  if (sca) {
    html += '<div class="section" id="sca">';
    html += '<div class="section-header"><span class="section-title">SCA &mdash; Dependency Vulnerabilities</span>';
    html += '<span class="section-count">' + sca.total + " CVE" + (sca.total !== 1 ? "s" : "");
    if (sca.isFiltered) html += " (" + sca.suppressed + " false positives + " + (sca.duplicatesRemoved || 0) + " duplicates removed)";
    html += "</span></div>";

    if (sca.total === 0) {
      html += '<div class="empty">No actionable vulnerabilities in dependencies.</div>';
    } else {
      html += '<div class="table-wrap"><table><tr><th>Severity</th><th>Package</th><th>Installed</th><th>Fix Version</th><th>CVE</th><th>Details</th></tr>';
      const sorted = [...sca.vulns].sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
      });
      for (const v of sorted) {
        html += "<tr><td>" + severityBadge(v.severity) + "</td>";
        html += '<td class="mono">' + esc(v.pkg) + "</td>";
        html += '<td class="mono">' + esc(v.version) + "</td>";
        html += '<td class="mono fix-text">' + esc(v.fixed) + "</td>";
        html += "<td>";
        if (v.url) html += '<a href="' + esc(v.url) + '" target="_blank">' + esc(v.id) + "</a>";
        else html += esc(v.id);
        html += "</td>";
        html += "<td>" + esc(v.title).substring(0, 120) + "</td></tr>";
      }
      html += "</table></div>";
    }
    html += "</div>";
  }

  // ─── Secrets Section ───────────────────────────────────
  if (gitleaks) {
    html += '<div class="section" id="secrets">';
    html += '<div class="section-header"><span class="section-title">Secret Detection (Gitleaks)</span>';
    html += '<span class="section-count">' + gitleaks.total + " leak" + (gitleaks.total !== 1 ? "s" : "") + "</span></div>";

    if (gitleaks.total === 0) {
      html += '<div class="empty">No leaked secrets detected.</div>';
    } else {
      html += '<div class="table-wrap"><table><tr><th>Rule</th><th>File</th><th>Line</th><th>Match</th><th>Fix</th></tr>';
      for (const l of gitleaks.leaks) {
        html += "<tr><td>" + severityBadge("CRITICAL") + " " + esc(l.rule) + "</td>";
        html += '<td class="mono">' + esc(l.file) + "</td>";
        html += "<td>" + l.line + "</td>";
        html += '<td class="mono">' + esc(l.match) + "...</td>";
        html += '<td class="fix-text">Rotate credential, remove from code, use env vars</td></tr>';
      }
      html += "</table></div>";
    }
    html += "</div>";
  }

  // ─── ZAP Section ───────────────────────────────────────
  if (zap && zap.total > 0) {
    html += '<div class="section" id="dast-zap">';
    html += '<div class="section-header"><span class="section-title">DAST &mdash; OWASP ZAP</span>';
    html += '<span class="section-count">' + zap.total + " alert" + (zap.total !== 1 ? "s" : "") + "</span></div>";
    html += '<div class="table-wrap"><table><tr><th>Risk</th><th>Alert</th><th>Instances</th><th>Fix</th></tr>';
    const sorted = [...zap.alerts].sort((a, b) => {
      const order = { High: 0, Medium: 1, Low: 2, Informational: 3 };
      return (order[a.risk] ?? 4) - (order[b.risk] ?? 4);
    });
    for (const a of sorted) {
      html += "<tr><td>" + severityBadge(a.risk) + "</td>";
      html += "<td>" + esc(a.name) + "</td>";
      html += "<td>" + a.count + "</td>";
      html += '<td class="fix-text">' + esc(a.solution).replace(/<[^>]+>/g, "").substring(0, 300) + "</td></tr>";
    }
    html += "</table></div></div>";
  }

  // ─── Nuclei Section ────────────────────────────────────
  if (nuclei && nuclei.total > 0) {
    html += '<div class="section" id="dast-nuclei">';
    html += '<div class="section-header"><span class="section-title">DAST &mdash; Nuclei Vulnerability Scan</span>';
    html += '<span class="section-count">' + nuclei.total + " finding" + (nuclei.total !== 1 ? "s" : "");
    if (nuclei.isFiltered && nuclei.suppressed) html += " (" + nuclei.suppressed + " filtered)";
    html += "</span></div>";

    for (const f of nuclei.findings) {
      html += '<div class="nuclei-finding">';
      html += '<div class="nuclei-header">' + severityBadge(f.severity) + " <strong>" + esc(f.name) + "</strong>";
      if (f.templateId) html += ' <span class="mono" style="opacity:0.6">' + esc(f.templateId) + "</span>";
      html += "</div>";
      if (f.description) html += '<div class="rule-desc">' + esc(f.description).substring(0, 500) + "</div>";
      if (f.matched) html += '<div class="file-path">Matched: ' + esc(f.matched) + "</div>";
      if (f.remediation) {
        html += '<div class="remediation-box"><strong>Remediation:</strong> ' + esc(f.remediation) + "</div>";
      }
      if (f.references && f.references.length > 0) {
        html += '<div class="ref-links">References: ';
        html += f.references.slice(0, 3).map((r) => '<a href="' + esc(r) + '" target="_blank">' + esc(r).substring(0, 60) + "</a>").join(" | ");
        html += "</div>";
      }
      html += "</div>";
    }
    html += "</div>";
  }

  // ─── Headers Section ───────────────────────────────────
  if (headers) {
    html += '<div class="section" id="headers">';
    html += '<div class="section-header"><span class="section-title">Security Headers Analysis</span>';
    html += '<span class="section-count">' + headers.present.length + "/" + headers.totalChecked + " present</span></div>";

    // Dangerous headers (remove these)
    if (headers.dangerous.length > 0) {
      html += "<h3>Remove These Headers</h3>";
      html += '<div class="table-wrap"><table><tr><th>Status</th><th>Header</th><th>Current Value</th><th>Risk</th><th>Fix</th></tr>';
      for (const h of headers.dangerous) {
        html += "<tr><td>" + severityBadge("WARNING") + "</td>";
        html += '<td class="mono">' + esc(h.name) + "</td>";
        html += '<td class="mono">' + esc(h.value) + "</td>";
        html += "<td>" + esc(h.desc) + "</td>";
        html += '<td class="fix-text">' + esc(h.fix) + "</td></tr>";
      }
      html += "</table></div>";
    }

    // Missing headers
    if (headers.missing.length > 0) {
      html += "<h3>Missing Headers</h3>";
      html += '<div class="table-wrap"><table><tr><th>Importance</th><th>Header</th><th>Purpose</th><th>Recommended Value</th></tr>';
      const impOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const sorted = [...headers.missing].sort((a, b) => (impOrder[a.importance] ?? 4) - (impOrder[b.importance] ?? 4));
      for (const h of sorted) {
        html += "<tr><td>" + severityBadge(h.importance) + "</td>";
        html += '<td class="mono">' + esc(h.name) + "</td>";
        html += "<td>" + esc(h.desc) + "</td>";
        html += '<td class="fix-text">' + esc(h.fix) + "</td></tr>";
      }
      html += "</table></div>";
    }

    // Present headers
    if (headers.present.length > 0) {
      html += "<h3>Present Headers</h3>";
      html += '<div class="table-wrap"><table><tr><th>Status</th><th>Header</th><th>Value</th></tr>';
      for (const h of headers.present) {
        html += '<tr><td><span class="status-pass">PASS</span></td>';
        html += '<td class="mono">' + esc(h.name) + "</td>";
        html += '<td class="mono">' + esc(h.value) + "</td></tr>";
      }
      html += "</table></div>";
    }

    // Raw headers in a collapsible
    if (headers.raw) {
      html += '<details><summary style="cursor:pointer;color:var(--text-muted);font-size:0.85rem;margin-top:1rem;">View raw response headers</summary>';
      html += '<pre class="code-example" style="margin-top:0.5rem">' + esc(headers.raw) + "</pre></details>";
    }

    html += "</div>";
  }

  // ─── Prod Readiness Section ────────────────────────────
  if (prod) {
    html += '<div class="section" id="prod">';
    html += '<div class="section-header"><span class="section-title">Production Readiness</span>';
    html += '<span class="section-count">Score: ' + (prod.score !== null ? prod.score + "%" : "N/A") + "</span></div>";

    // Gauge
    if (prod.score !== null) {
      let gaugeColor = "#dc2626";
      if (prod.score >= 80) gaugeColor = "#16a34a";
      else if (prod.score >= 60) gaugeColor = "#d97706";
      else if (prod.score >= 40) gaugeColor = "#ea580c";

      html += '<div class="gauge"><svg viewBox="0 0 120 120" width="140" height="140">';
      html += '<circle cx="60" cy="60" r="50" fill="none" stroke="#1e293b" stroke-width="10"/>';
      html += '<circle cx="60" cy="60" r="50" fill="none" stroke="' + gaugeColor + '" stroke-width="10" stroke-dasharray="' + ((prod.score / 100) * 314) + ' 314" stroke-linecap="round" transform="rotate(-90 60 60)"/>';
      html += '<text x="60" y="55" text-anchor="middle" fill="' + gaugeColor + '" font-size="28" font-weight="bold">' + prod.score + "</text>";
      html += '<text x="60" y="75" text-anchor="middle" fill="#94a3b8" font-size="12">/ 100</text>';
      html += "</svg></div>";

      if (prod.score >= 80) html += '<div class="verdict pass">READY FOR PRODUCTION</div>';
      else if (prod.score >= 60) html += '<div class="verdict warn">NEEDS ATTENTION BEFORE PRODUCTION</div>';
      else html += '<div class="verdict fail">NOT READY FOR PRODUCTION</div>';
    }

    if (prod.checks.length > 0) {
      html += '<div class="table-wrap"><table><tr><th>Status</th><th>Check</th><th>Remediation</th></tr>';
      for (const c of prod.checks) {
        html += "<tr><td>" + statusIcon(c.status) + "</td>";
        html += "<td>" + esc(c.message) + "</td>";
        html += "<td>" + (c.fix ? '<div class="fix-text">' + esc(c.fix) + "</div>" : "") + "</td></tr>";
      }
      html += "</table></div>";
    }
    html += "</div>";
  }

  // Footer
  html += '<div class="footer">Generated by <strong>webapp-ss</strong> &mdash; ' + timestamp + "</div>";
  html += "</body></html>";

  return html;
}

// ─── CSS ───────────────────────────────────────────────────

function CSS() {
  return `
:root {
  --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
  --text: #e2e8f0; --text-muted: #94a3b8; --accent: #38bdf8;
  --green: #4ade80; --red: #f87171; --yellow: #fbbf24; --orange: #fb923c;
  --border: #334155;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: var(--bg); color: var(--text);
  line-height: 1.6; padding: clamp(1rem, 3vw, 2rem);
  max-width: 1400px; margin: 0 auto;
}
h1 { font-size: clamp(1.3rem, 3vw, 1.8rem); margin-bottom: 0.25rem; }
h3 { font-size: 0.95rem; color: var(--text-muted); margin: 1.25rem 0 0.5rem; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.header {
  display: flex; justify-content: space-between; align-items: flex-start;
  flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem;
  padding-bottom: 1.5rem; border-bottom: 2px solid var(--accent);
}
.header-meta { color: var(--text-muted); font-size: 0.85rem; }
.grade-gauge { text-align: center; }

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.75rem; margin-bottom: 1.5rem;
}
.card {
  background: var(--surface); border-radius: 8px;
  padding: 1rem; border: 1px solid var(--border);
}
.card-label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.card-value { font-size: 1.8rem; font-weight: 700; margin: 0.15rem 0; }
.card-value.green { color: var(--green); }
.card-value.red { color: var(--red); }
.card-value.yellow { color: var(--yellow); }
.card-value.orange { color: var(--orange); }

.filter-banner {
  background: rgba(56,189,248,0.08); border: 1px solid var(--accent);
  border-radius: 8px; padding: 0.75rem 1.25rem;
  margin-bottom: 1rem; font-size: 0.85rem; color: var(--accent);
}

.nav {
  position: sticky; top: 0; background: var(--bg);
  padding: 0.75rem 0; margin-bottom: 1rem; z-index: 10;
  border-bottom: 1px solid var(--border);
  display: flex; gap: 0.5rem; flex-wrap: wrap;
}
.nav a {
  padding: 0.3rem 0.75rem; background: var(--surface);
  border-radius: 6px; font-size: 0.8rem; border: 1px solid var(--border);
}
.nav a:hover { background: var(--surface2); text-decoration: none; }

.section {
  background: var(--surface); border-radius: 8px;
  padding: clamp(1rem, 2vw, 1.5rem); margin-bottom: 1.5rem;
  border: 1px solid var(--border);
}
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem; }
.section-title { font-size: 1.1rem; font-weight: 600; }
.section-count { background: var(--surface2); padding: 0.2rem 0.7rem; border-radius: 12px; font-size: 0.8rem; white-space: nowrap; }

.exec-summary .action-item {
  background: var(--bg); border-radius: 6px; padding: 1rem;
  margin-bottom: 0.75rem; border-left: 3px solid var(--accent);
}
.action-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.4rem; }
.action-num {
  display: inline-flex; align-items: center; justify-content: center;
  width: 22px; height: 22px; border-radius: 50%;
  background: var(--surface2); font-size: 0.75rem; font-weight: 700;
  flex-shrink: 0;
}
.action-detail { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.3rem; }
.action-fix { color: var(--green); font-size: 0.85rem; white-space: pre-line; }

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; font-size: 0.85rem; }
th { text-align: left; padding: 0.6rem 0.8rem; background: var(--surface2); color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; white-space: nowrap; }
td { padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: rgba(56,189,248,0.04); }

.badge {
  display: inline-block; padding: 0.15rem 0.5rem;
  border-radius: 4px; font-size: 0.7rem; font-weight: 700;
  color: #fff; text-transform: uppercase; white-space: nowrap;
}
.conf-badge {
  display: inline-block; padding: 0.1rem 0.4rem;
  border-radius: 4px; font-size: 0.65rem; font-weight: 600;
  border: 1px solid; background: transparent;
}
.tag-badge {
  display: inline-block; padding: 0.1rem 0.45rem;
  border-radius: 3px; font-size: 0.65rem; font-weight: 600;
  margin-right: 0.3rem; margin-bottom: 0.2rem;
}
.tag-badge.cwe { background: rgba(220,38,38,0.15); color: #fca5a5; }
.tag-badge.owasp { background: rgba(56,189,248,0.15); color: var(--accent); }
.tag-row { margin: 0.5rem 0; }

.fix-text { color: var(--green); font-size: 0.8rem; }
.mono { font-family: 'Fira Code', 'Cascadia Code', 'Consolas', monospace; font-size: 0.8rem; }

.status-pass { color: var(--green); font-weight: 700; }
.status-fail { color: var(--red); font-weight: 700; }
.status-warn { color: var(--yellow); font-weight: 700; }
.status-info { color: var(--text-muted); font-weight: 700; }

.gauge { text-align: center; margin: 1rem 0; }
.verdict { text-align: center; font-size: 1.1rem; font-weight: 700; padding: 0.75rem; border-radius: 8px; margin: 1rem 0; }
.verdict.pass { background: rgba(74,222,128,0.1); color: var(--green); border: 1px solid var(--green); }
.verdict.warn { background: rgba(251,191,36,0.1); color: var(--yellow); border: 1px solid var(--yellow); }
.verdict.fail { background: rgba(248,113,113,0.1); color: var(--red); border: 1px solid var(--red); }

.empty { color: var(--text-muted); font-style: italic; padding: 1rem; text-align: center; }

details.rule-group {
  background: var(--bg); border-radius: 6px;
  margin-bottom: 0.75rem; border: 1px solid var(--border);
}
details.rule-group summary {
  padding: 0.75rem 1rem; cursor: pointer;
  display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;
}
details.rule-group summary:hover { background: var(--surface2); border-radius: 6px; }
.instance-count { color: var(--text-muted); font-size: 0.8rem; }
.rule-detail { padding: 0 1rem 1rem; }
.rule-desc { color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0; line-height: 1.5; }
.rule-link { margin-top: 0.75rem; font-size: 0.8rem; }

.remediation-box {
  background: rgba(74,222,128,0.06); border: 1px solid rgba(74,222,128,0.2);
  border-radius: 6px; padding: 0.75rem 1rem;
  margin: 0.75rem 0; font-size: 0.85rem; color: var(--green);
}
.code-example {
  background: var(--surface2); padding: 0.75rem;
  border-radius: 4px; font-size: 0.8rem; overflow-x: auto;
  margin-top: 0.5rem; color: var(--text); white-space: pre;
  font-family: 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
}

.file-entry { margin: 0.5rem 0; }
.file-path { font-family: 'Fira Code', monospace; font-size: 0.8rem; color: var(--accent); margin-bottom: 0.25rem; }

.code-block { margin: 0.25rem 0 0.75rem; }
.code-snippet {
  background: #0d1117; border-radius: 4px;
  overflow-x: auto; margin-bottom: 0.25rem; border: 1px solid #21262d;
}
.code-line {
  display: flex; font-family: 'Fira Code', 'Cascadia Code', monospace;
  font-size: 0.78rem; line-height: 1.5;
}
.code-line.highlight { background: rgba(220,38,38,0.12); }
.line-num {
  display: inline-block; min-width: 3rem; text-align: right;
  padding: 0 0.5rem; color: #484f58; user-select: none; flex-shrink: 0;
}
.line-text { padding: 0 0.75rem; white-space: pre; }

.nuclei-finding {
  background: var(--bg); border-radius: 6px; padding: 1rem;
  margin-bottom: 0.75rem; border: 1px solid var(--border);
}
.nuclei-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
.ref-links { font-size: 0.8rem; margin-top: 0.5rem; }
.ref-links a { margin-right: 0.5rem; }

.footer {
  text-align: center; color: var(--text-muted); font-size: 0.75rem;
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
}

@media (max-width: 768px) {
  .summary-cards { grid-template-columns: repeat(2, 1fr); }
  .section-header { flex-direction: column; align-items: flex-start; }
  .header { flex-direction: column; align-items: center; text-align: center; }
  details.rule-group summary { font-size: 0.85rem; }
  .action-header { font-size: 0.9rem; }
}
@media (max-width: 480px) {
  .summary-cards { grid-template-columns: 1fr 1fr; gap: 0.5rem; }
  .card { padding: 0.75rem; }
  .card-value { font-size: 1.4rem; }
  body { padding: 0.75rem; }
}
@media print {
  body { background: #fff; color: #111; }
  .nav, .filter-banner { display: none; }
  .card, .section, details.rule-group { border: 1px solid #ddd; break-inside: avoid; }
  .badge { border: 1px solid currentColor; }
  .code-snippet { background: #f5f5f5; }
  .code-line.highlight { background: rgba(220,38,38,0.08); }
}
`;
}

// ─── Main ──────────────────────────────────────────────────

const html = buildHTML();
const outPath = path.join(reportDir, "security-report.html");
fs.writeFileSync(outPath, html);
console.log("[+] HTML report generated: " + outPath);
