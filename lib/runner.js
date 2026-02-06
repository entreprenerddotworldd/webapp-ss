const { execSync, spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const SCRIPTS_DIR = path.join(__dirname, "..", "scripts");

function buildEnvFromConfig(config) {
  const env = { ...process.env };

  // Server
  if (config.server.port !== "auto") {
    env.WEBAPP_SS_PORT = String(config.server.port);
  }
  if (config.server.url) {
    env.WEBAPP_SS_URL = config.server.url;
  }
  env.WEBAPP_SS_WAIT_TIMEOUT = String(config.server.waitTimeout);

  // Thresholds
  env.WEBAPP_SS_THRESHOLD_SAST = config.thresholds.sast;
  env.WEBAPP_SS_THRESHOLD_SCA = config.thresholds.sca;
  env.WEBAPP_SS_THRESHOLD_DAST = config.thresholds.dast;
  env.WEBAPP_SS_THRESHOLD_SECRETS = config.thresholds.secrets;

  // Paths
  env.WEBAPP_SS_EXCLUDE = config.paths.exclude.join(",");
  env.WEBAPP_SS_REPORTS = path.resolve(
    config._projectDir,
    config.paths.reports
  );

  // Tool preferences
  env.WEBAPP_SS_PREFER_DOCKER = config.tools.preferDocker ? "1" : "0";
  env.WEBAPP_SS_SEMGREP_CONFIGS = config.tools.semgrep.configs.join(",");
  env.WEBAPP_SS_TRIVY_SEVERITY = config.tools.trivy.severity.join(",");
  env.WEBAPP_SS_DC_ENABLED = config.tools.dependencyCheck.enabled ? "1" : "0";
  env.WEBAPP_SS_ZAP_SCAN_TYPE = config.tools.zap.scanType;
  env.WEBAPP_SS_NUCLEI_SEVERITY = config.tools.nuclei.severity.join(",");
  env.WEBAPP_SS_GITLEAKS_HISTORY = config.tools.gitleaks.scanGitHistory
    ? "1"
    : "0";

  // Prod readiness
  env.WEBAPP_SS_REQUIRED_HEADERS =
    config.prodReadiness.requiredHeaders.join(",");
  env.WEBAPP_SS_BLOCKED_PATHS = config.prodReadiness.blockedPaths.join(",");
  env.WEBAPP_SS_MIN_SCORE = String(config.prodReadiness.minScore);

  // Reports
  env.WEBAPP_SS_REPORT_FORMAT = config.reports.format.join(",");
  env.WEBAPP_SS_VERBOSE = config.reports.verbose ? "1" : "0";

  return env;
}

function determineScanMode(config, cliMode) {
  // CLI flag takes priority
  if (cliMode) return cliMode;

  // Build mode from scanner toggles
  const s = config.scanners;
  const hasCode = s.sast || s.sca || s.secrets;
  const hasLive = s.dast || s.headers;

  if (hasCode && hasLive) return "full";
  if (hasCode && !hasLive) return "code-only";
  if (!hasCode && hasLive) return "live-only";
  return "full";
}

function buildAuditArgs(config, cliOptions) {
  const args = [];

  const mode = determineScanMode(config, cliOptions.mode);
  args.push(`--${mode}`);

  if (cliOptions.port) {
    args.push("-p", String(cliOptions.port));
  } else if (config.server.port !== "auto") {
    args.push("-p", String(config.server.port));
  }

  if (cliOptions.url) {
    args.push("-u", cliOptions.url);
  } else if (config.server.url) {
    args.push("-u", config.server.url);
  }

  args.push("-d", config._projectDir);

  const reportDir = path.resolve(config._projectDir, config.paths.reports);
  args.push("-o", reportDir);

  return args;
}

function runAudit(config, cliOptions) {
  const auditScript = path.join(__dirname, "..", "audit.sh");
  const args = buildAuditArgs(config, cliOptions);
  const env = buildEnvFromConfig(config);

  const child = spawn("bash", [auditScript, ...args], {
    env,
    stdio: "inherit",
    cwd: config._projectDir,
  });

  child.on("close", (code) => {
    // Open reports in browser if configured
    if (config.reports.openInBrowser && code !== null) {
      const reportDir = path.resolve(config._projectDir, config.paths.reports);
      const htmlFiles = fs.readdirSync(reportDir).filter((f) => f.endsWith(".html"));
      for (const f of htmlFiles) {
        const fullPath = path.join(reportDir, f);
        try {
          execSync(`xdg-open "${fullPath}" 2>/dev/null || open "${fullPath}" 2>/dev/null`, {
            stdio: "ignore",
          });
        } catch {
          // ignore - browser open is best-effort
        }
      }
    }

    process.exit(code || 0);
  });

  child.on("error", (err) => {
    console.error(`[!] Failed to run audit: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { runAudit, buildEnvFromConfig, determineScanMode };
