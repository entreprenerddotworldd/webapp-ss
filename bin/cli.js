#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const {
  loadConfig,
  findProjectRoot,
  generateConfigTemplate,
  CONFIG_FILENAME,
} = require("../lib/config");
const { runAudit } = require("../lib/runner");
const { installHooks, removeHooks } = require("../lib/hooks");

const VERSION = require("../package.json").version;

// ─── Help ──────────────────────────────────────────────────
function showHelp() {
  console.log(`
webapp-ss v${VERSION} - Web Application Security Scanner

USAGE
  webapp-ss <command> [options]

COMMANDS
  init              Create webapp-ss.config.js in your project
  scan              Run security scans (default command)
  hooks             Install git hooks from config
  hooks --remove    Remove webapp-ss git hooks
  check-tools       Check which scanning tools are available
  ci                Install/update GitHub Actions workflow

SCAN OPTIONS
  --full            All scans: SAST + SCA + DAST + secrets + headers + prod (default)
  --quick           Fast: SAST + secrets only (no Docker needed)
  --code-only       Offline: SAST + SCA + secrets (no running server)
  --live-only       Live: DAST + headers (needs running server)
  --prod-check      Production readiness assessment

  -p, --port PORT   Dev server port (default: auto-detect)
  -u, --url URL     Full target URL
  -v, --verbose     Show detailed output

EXAMPLES
  npx webapp-ss init                  # Generate config file
  npx webapp-ss scan                  # Full scan with auto-detect
  npx webapp-ss scan --quick          # Fast scan, no Docker
  npx webapp-ss scan -p 5173          # Scan app on port 5173
  npx webapp-ss scan --prod-check     # Pre-deployment check
  npx webapp-ss check-tools           # Verify tool installation
`);
}

// ─── Commands ──────────────────────────────────────────────

function cmdInit(projectDir) {
  const configPath = path.join(projectDir, CONFIG_FILENAME);

  if (fs.existsSync(configPath)) {
    console.log(`[!] ${CONFIG_FILENAME} already exists.`);
    console.log(`    Delete it first if you want to regenerate.`);
    process.exit(1);
  }

  fs.writeFileSync(configPath, generateConfigTemplate());
  console.log(`[+] Created ${CONFIG_FILENAME}`);
  console.log("");

  // Add reports dir to .gitignore
  const gitignorePath = path.join(projectDir, ".gitignore");
  const entries = ["webapp-ss-reports/"];
  if (fs.existsSync(gitignorePath)) {
    const content = fs.readFileSync(gitignorePath, "utf8");
    const toAdd = entries.filter((e) => !content.includes(e));
    if (toAdd.length > 0) {
      fs.appendFileSync(gitignorePath, "\n# webapp-ss\n" + toAdd.join("\n") + "\n");
      console.log(`[+] Updated .gitignore`);
    }
  } else {
    fs.writeFileSync(gitignorePath, "# webapp-ss\n" + entries.join("\n") + "\n");
    console.log(`[+] Created .gitignore`);
  }

  // Load config and set up hooks + CI
  const config = loadConfig(projectDir);

  if (config.hooks.prePush || config.hooks.preCommit) {
    console.log("[*] Setting up git hooks...");
    installHooks(projectDir, config);
  }

  if (config.ci.enabled) {
    const workflowDir = path.join(projectDir, ".github", "workflows");
    const workflowSrc = path.join(__dirname, "..", "workflows", "security-scan.yml");
    const workflowDest = path.join(workflowDir, "security-scan.yml");

    if (fs.existsSync(workflowSrc)) {
      fs.mkdirSync(workflowDir, { recursive: true });
      fs.copyFileSync(workflowSrc, workflowDest);
      console.log("[+] Installed .github/workflows/security-scan.yml");
    }
  }

  console.log("");
  console.log("Edit webapp-ss.config.js to customize, then run:");
  console.log("  npx webapp-ss scan");
  console.log("");
}

function cmdScan(projectDir, cliOptions) {
  const config = loadConfig(projectDir);

  // CLI overrides
  if (cliOptions.verbose) {
    config.reports.verbose = true;
  }

  console.log(
    config._configPath
      ? `[*] Config: ${path.relative(projectDir, config._configPath)}`
      : `[*] No ${CONFIG_FILENAME} found, using defaults`
  );
  console.log("");

  runAudit(config, cliOptions);
}

function cmdHooks(projectDir, remove) {
  if (remove) {
    console.log("[*] Removing webapp-ss git hooks...");
    removeHooks(projectDir);
    console.log("[*] Done.");
    return;
  }

  const config = loadConfig(projectDir);
  console.log("[*] Installing git hooks...");
  installHooks(projectDir, config);
  console.log("[*] Done.");
}

function cmdCheckTools() {
  const { execSync } = require("child_process");

  const tools = [
    {
      name: "docker",
      cmd: "docker --version",
      install: "sudo pacman -S docker",
      required: true,
    },
    {
      name: "semgrep",
      cmd: "semgrep --version",
      install: "yay -S semgrep-bin  OR  pip install semgrep",
      required: false,
    },
    {
      name: "trivy",
      cmd: "trivy --version",
      install: "yay -S trivy-bin",
      required: false,
    },
    {
      name: "gitleaks",
      cmd: "gitleaks version",
      install: "yay -S gitleaks",
      required: false,
    },
    {
      name: "nuclei",
      cmd: "nuclei --version",
      install: "yay -S nuclei-bin",
      required: false,
    },
    {
      name: "dependency-check",
      cmd: "dependency-check --version",
      install: "yay -S dependency-check-bin",
      required: false,
    },
  ];

  console.log("Tool Availability Check");
  console.log("=======================");
  console.log("");

  let allGood = true;
  for (const tool of tools) {
    try {
      const version = execSync(tool.cmd, { timeout: 10000 })
        .toString()
        .trim()
        .split("\n")[0];
      console.log(`  [OK] ${tool.name}: ${version}`);
    } catch {
      if (tool.required) {
        console.log(`  [!!] ${tool.name}: NOT INSTALLED (required)`);
        console.log(`       Install: ${tool.install}`);
        allGood = false;
      } else {
        console.log(`  [--] ${tool.name}: not installed (Docker fallback available)`);
        console.log(`       Install: ${tool.install}`);
      }
    }
  }

  console.log("");
  if (allGood) {
    console.log("All required tools are available.");
    console.log(
      "Tools marked [--] will use Docker containers automatically."
    );
  } else {
    console.log("Install required tools before running scans.");
  }
  console.log("");
}

function cmdCI(projectDir) {
  const workflowDir = path.join(projectDir, ".github", "workflows");
  const workflowSrc = path.join(__dirname, "..", "workflows", "security-scan.yml");
  const workflowDest = path.join(workflowDir, "security-scan.yml");

  if (!fs.existsSync(workflowSrc)) {
    console.log("[!] Workflow template not found.");
    process.exit(1);
  }

  fs.mkdirSync(workflowDir, { recursive: true });
  fs.copyFileSync(workflowSrc, workflowDest);
  console.log("[+] Installed .github/workflows/security-scan.yml");
  console.log("[*] Scans will run automatically on push and PR.");
  console.log("");
}

// ─── Main ──────────────────────────────────────────────────
function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    showHelp();
    process.exit(0);
  }

  if (args.includes("--version")) {
    console.log(`webapp-ss v${VERSION}`);
    process.exit(0);
  }

  const projectDir = findProjectRoot(process.cwd());
  const command = args[0] || "scan";

  switch (command) {
    case "init":
      cmdInit(projectDir);
      break;

    case "scan": {
      const cliOptions = {
        mode: null,
        port: null,
        url: null,
        verbose: false,
      };

      for (let i = 1; i < args.length; i++) {
        switch (args[i]) {
          case "--full":
            cliOptions.mode = "full";
            break;
          case "--quick":
            cliOptions.mode = "quick";
            break;
          case "--code-only":
            cliOptions.mode = "code-only";
            break;
          case "--live-only":
            cliOptions.mode = "live-only";
            break;
          case "--prod-check":
            cliOptions.mode = "prod-check";
            break;
          case "-p":
          case "--port":
            cliOptions.port = args[++i];
            break;
          case "-u":
          case "--url":
            cliOptions.url = args[++i];
            break;
          case "-v":
          case "--verbose":
            cliOptions.verbose = true;
            break;
        }
      }

      cmdScan(projectDir, cliOptions);
      break;
    }

    case "hooks":
      cmdHooks(projectDir, args.includes("--remove"));
      break;

    case "check-tools":
      cmdCheckTools();
      break;

    case "ci":
      cmdCI(projectDir);
      break;

    default:
      // Treat unknown first arg as scan mode shortcut
      if (command.startsWith("--")) {
        const cliOptions = { mode: command.replace("--", ""), port: null, url: null, verbose: false };
        cmdScan(projectDir, cliOptions);
      } else {
        console.log(`Unknown command: ${command}`);
        showHelp();
        process.exit(1);
      }
  }
}

main();
