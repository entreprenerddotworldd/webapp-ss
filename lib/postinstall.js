#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { loadConfig, findProjectRoot, CONFIG_FILENAME } = require("./config");
const { installHooks } = require("./hooks");

// postinstall runs from node_modules/webapp-ss/ - find the actual project root
const projectDir = findProjectRoot(process.cwd());

console.log("");
console.log("  ╔══════════════════════════════════════════╗");
console.log("  ║         webapp-ss installed!              ║");
console.log("  ╚══════════════════════════════════════════╝");
console.log("");

// Check if config exists
const configPath = path.join(projectDir, CONFIG_FILENAME);
if (!fs.existsSync(configPath)) {
  console.log(`  Run 'npx webapp-ss init' to create ${CONFIG_FILENAME}`);
  console.log("");
} else {
  console.log(`  [*] Found ${CONFIG_FILENAME}`);
  const config = loadConfig(projectDir);

  // Install git hooks if configured
  if (config.hooks.prePush || config.hooks.preCommit) {
    console.log("  [*] Setting up git hooks...");
    installHooks(projectDir, config);
  }

  // Copy GitHub Actions workflow if CI is enabled
  if (config.ci.enabled) {
    const workflowDir = path.join(projectDir, ".github", "workflows");
    const workflowDest = path.join(workflowDir, "security-scan.yml");
    const workflowSrc = path.join(__dirname, "..", "workflows", "security-scan.yml");

    if (!fs.existsSync(workflowDest) && fs.existsSync(workflowSrc)) {
      fs.mkdirSync(workflowDir, { recursive: true });
      fs.copyFileSync(workflowSrc, workflowDest);
      console.log("  [+] Installed .github/workflows/security-scan.yml");
    }
  }

  console.log("");
}

console.log("  Quick start:");
console.log("    npx webapp-ss init       # Create config file");
console.log("    npx webapp-ss scan       # Run full security scan");
console.log("    npx webapp-ss --help     # See all commands");
console.log("");
