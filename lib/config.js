const fs = require("fs");
const path = require("path");

const CONFIG_FILENAME = "webapp-ss.config.js";

const DEFAULTS = {
  scanners: {
    sast: true,
    sca: true,
    dast: true,
    secrets: true,
    headers: true,
    prodReadiness: true,
  },

  server: {
    port: "auto",
    url: null,
    waitTimeout: 30,
    startCommand: null,
  },

  thresholds: {
    sast: "error",
    sca: "critical",
    dast: "high",
    secrets: "any",
  },

  paths: {
    exclude: [
      "node_modules",
      ".git",
      "dist",
      "build",
      "coverage",
      ".next",
      "*.min.js",
    ],
    reports: "./webapp-ss-reports",
  },

  tools: {
    preferDocker: false,
    semgrep: {
      configs: ["auto", "p/owasp-top-ten", "p/security-audit"],
      extraArgs: [],
    },
    trivy: {
      severity: ["HIGH", "CRITICAL"],
      extraArgs: [],
    },
    dependencyCheck: {
      enabled: true,
      extraArgs: [],
    },
    zap: {
      scanType: "baseline",
      extraArgs: [],
    },
    nuclei: {
      severity: ["medium", "high", "critical"],
      templates: [],
      extraArgs: [],
    },
    gitleaks: {
      scanGitHistory: true,
      extraArgs: [],
    },
  },

  hooks: {
    prePush: true,
    preCommit: false,
    scanMode: "quick",
  },

  ci: {
    enabled: true,
    triggers: ["push", "pull_request"],
    branches: ["main", "master", "develop"],
    dastInCI: true,
  },

  prodReadiness: {
    requiredHeaders: [
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "X-Frame-Options",
      "Content-Security-Policy",
    ],
    blockedPaths: ["/.env", "/.git/config", "/.git/HEAD", "/admin", "/debug"],
    minScore: 80,
  },

  filters: {
    enabled: true,
    semgrep: {
      ignoreRules: [],
      ignorePaths: [],
      suppressInfoFindings: true,
    },
    sca: {
      ignoreCVEs: [],
      ignoreNonShipped: true,
      deduplicateCVEs: true,
    },
    nuclei: {
      ignoreTemplates: [],
      suppressTechDetection: true,
    },
  },

  reports: {
    format: ["json", "html"],
    verbose: false,
    openInBrowser: false,
  },
};

function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === "object" &&
      !Array.isArray(source[key]) &&
      target[key] &&
      typeof target[key] === "object" &&
      !Array.isArray(target[key])
    ) {
      result[key] = deepMerge(target[key], source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

function findProjectRoot(startDir) {
  let dir = startDir || process.cwd();
  while (dir !== path.dirname(dir)) {
    if (
      fs.existsSync(path.join(dir, "package.json")) ||
      fs.existsSync(path.join(dir, CONFIG_FILENAME))
    ) {
      return dir;
    }
    dir = path.dirname(dir);
  }
  return process.cwd();
}

function loadConfig(projectDir) {
  const configPath = path.join(projectDir, CONFIG_FILENAME);

  if (!fs.existsSync(configPath)) {
    return { ...DEFAULTS, _configPath: null, _projectDir: projectDir };
  }

  try {
    // Clear require cache so config changes are picked up
    delete require.cache[require.resolve(configPath)];
    const userConfig = require(configPath);
    const merged = deepMerge(DEFAULTS, userConfig);
    merged._configPath = configPath;
    merged._projectDir = projectDir;
    return merged;
  } catch (err) {
    console.error(`[!] Error loading ${CONFIG_FILENAME}: ${err.message}`);
    console.error("[!] Using default configuration.");
    return { ...DEFAULTS, _configPath: configPath, _projectDir: projectDir };
  }
}

function generateConfigTemplate() {
  return `// webapp-ss.config.js
// Web Application Security Scanner Configuration
// Docs: https://github.com/YOUR_USER/webapp-ss

module.exports = {
  // ─── Scanners ────────────────────────────────────────────
  // Toggle individual scanners on/off
  scanners: {
    sast: true,           // Semgrep static code analysis
    sca: true,            // Trivy + OWASP Dependency-Check
    dast: true,           // ZAP + Nuclei live scanning
    secrets: true,        // Gitleaks credential detection
    headers: true,        // HTTP security headers analysis
    prodReadiness: true,  // Production readiness scoring
  },

  // ─── Server ──────────────────────────────────────────────
  // How to find/reach your running dev server
  server: {
    port: "auto",         // "auto" to detect, or a number like 3000
    url: null,            // Full URL override (e.g. "https://staging.myapp.com")
    waitTimeout: 30,      // Seconds to wait for server in CI
    startCommand: null,   // Custom start command (e.g. "npm run dev")
  },

  // ─── Thresholds ──────────────────────────────────────────
  // At what severity level should the scan be considered "failed"?
  // This controls exit codes and CI pass/fail behavior.
  thresholds: {
    sast: "error",        // "error" | "warning" | "info" | "none"
    sca: "critical",      // "critical" | "high" | "medium" | "low" | "none"
    dast: "high",         // "high" | "medium" | "low" | "none"
    secrets: "any",       // "any" (fail on any leak) | "none"
  },

  // ─── Paths ───────────────────────────────────────────────
  paths: {
    exclude: [            // Skip these directories/patterns
      "node_modules",
      ".git",
      "dist",
      "build",
      "coverage",
      ".next",
      "*.min.js",
    ],
    reports: "./webapp-ss-reports",
  },

  // ─── Tool Configuration ──────────────────────────────────
  tools: {
    preferDocker: false,  // true = always use Docker, even if native is installed

    semgrep: {
      configs: ["auto", "p/owasp-top-ten", "p/security-audit"],
      extraArgs: [],      // Additional CLI args for semgrep
    },

    trivy: {
      severity: ["HIGH", "CRITICAL"],
      extraArgs: [],
    },

    dependencyCheck: {
      enabled: true,      // Can be slow on first run (NVD download)
      extraArgs: [],
    },

    zap: {
      scanType: "baseline",  // "baseline" (passive) or "full" (active+passive)
      extraArgs: [],
    },

    nuclei: {
      severity: ["medium", "high", "critical"],
      templates: [],      // Extra template paths
      extraArgs: [],
    },

    gitleaks: {
      scanGitHistory: true,  // Also scan git commit history
      extraArgs: [],
    },
  },

  // ─── Git Hooks ───────────────────────────────────────────
  // Automatically scan before push/commit
  hooks: {
    prePush: true,        // Run scan before git push
    preCommit: false,     // Run quick scan before git commit
    scanMode: "quick",    // What mode for hooks: "quick" | "code-only"
  },

  // ─── CI / GitHub Actions ─────────────────────────────────
  ci: {
    enabled: true,
    triggers: ["push", "pull_request"],
    branches: ["main", "master", "develop"],
    dastInCI: true,       // Build app and run live scans in CI
  },

  // ─── Production Readiness ────────────────────────────────
  prodReadiness: {
    requiredHeaders: [
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "X-Frame-Options",
      "Content-Security-Policy",
    ],
    blockedPaths: [       // These should return 403/404 in prod
      "/.env",
      "/.git/config",
      "/.git/HEAD",
      "/admin",
      "/debug",
    ],
    minScore: 80,         // Minimum score to pass (0-100)
  },

  // ─── Noise Filtering ──────────────────────────────────────
  // The intelligence layer that removes false positives and noise.
  // This is what makes reports actionable instead of overwhelming.
  filters: {
    enabled: true,          // Run the filter pass after scanning

    semgrep: {
      ignoreRules: [
        // Add semgrep rule IDs to suppress. Example:
        // "javascript.lang.security.audit.unsafe-formatstring",
      ],
      ignorePaths: [
        // Paths to ignore in SAST results. Example:
        // "tests/", "scripts/seed-data.js",
      ],
      suppressInfoFindings: true,  // Hide INFO-level findings (usually noise)
    },

    sca: {
      ignoreCVEs: [
        // CVEs you've verified are false positives. Example:
        // "CVE-2023-XXXXX",
      ],
      ignoreNonShipped: true,     // Filter vulns in example/test/demo code inside deps
      deduplicateCVEs: true,       // Merge duplicate CVEs across Trivy + Dependency-Check
    },

    nuclei: {
      ignoreTemplates: [
        // Nuclei template IDs to suppress. Example:
        // "tech-detect:react",
      ],
      suppressTechDetection: true, // Hide "we detected React" type findings
    },
  },

  // ─── Reports ─────────────────────────────────────────────
  reports: {
    format: ["json", "html"],
    verbose: false,       // Show all details in terminal output
    openInBrowser: false, // Auto-open HTML reports after scan
  },
};
`;
}

module.exports = {
  DEFAULTS,
  CONFIG_FILENAME,
  loadConfig,
  findProjectRoot,
  generateConfigTemplate,
};
