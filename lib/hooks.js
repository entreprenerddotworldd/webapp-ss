const fs = require("fs");
const path = require("path");

function findGitDir(startDir) {
  let dir = startDir;
  while (dir !== path.dirname(dir)) {
    const gitDir = path.join(dir, ".git");
    if (fs.existsSync(gitDir)) {
      // Could be a file (worktree) or directory
      if (fs.statSync(gitDir).isDirectory()) {
        return gitDir;
      }
      // Worktree: .git is a file pointing to the real git dir
      const content = fs.readFileSync(gitDir, "utf8").trim();
      const match = content.match(/^gitdir:\s*(.+)$/);
      if (match) return match[1];
    }
    dir = path.dirname(dir);
  }
  return null;
}

function getHookContent(hookType, config) {
  const scanMode = config.hooks.scanMode || "quick";

  // Find webapp-ss bin path
  const binPath = path.join(__dirname, "..", "bin", "cli.js");

  return `#!/bin/sh
# webapp-ss ${hookType} hook
# Auto-installed by webapp-ss - remove with: webapp-ss hooks --remove

echo "[webapp-ss] Running ${hookType} security scan (${scanMode} mode)..."

node "${binPath}" scan --${scanMode}
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[webapp-ss] Security issues found! Fix them before ${hookType === "pre-push" ? "pushing" : "committing"}."
    echo "[webapp-ss] To bypass (NOT recommended): git ${hookType === "pre-push" ? "push" : "commit"} --no-verify"
    exit 1
fi

exit 0
`;
}

function installHooks(projectDir, config) {
  const gitDir = findGitDir(projectDir);
  if (!gitDir) {
    console.log("  [!] Not a git repository. Skipping hook installation.");
    return;
  }

  const hooksDir = path.join(gitDir, "hooks");
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  let installed = 0;

  if (config.hooks.prePush) {
    const hookPath = path.join(hooksDir, "pre-push");
    writeHook(hookPath, getHookContent("pre-push", config));
    console.log("  [+] Installed pre-push hook");
    installed++;
  }

  if (config.hooks.preCommit) {
    const hookPath = path.join(hooksDir, "pre-commit");
    writeHook(hookPath, getHookContent("pre-commit", config));
    console.log("  [+] Installed pre-commit hook");
    installed++;
  }

  if (installed === 0) {
    console.log(
      "  [*] No hooks enabled in config. Set hooks.prePush or hooks.preCommit to true."
    );
  }
}

function writeHook(hookPath, content) {
  // Check if there's an existing hook that isn't ours
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf8");
    if (!existing.includes("webapp-ss")) {
      // Backup existing hook
      const backupPath = hookPath + ".webapp-ss-backup";
      fs.copyFileSync(hookPath, backupPath);
      console.log(`  [*] Backed up existing hook to ${path.basename(backupPath)}`);

      // Append our hook to the existing one
      const merged = existing.trimEnd() + "\n\n" + content;
      fs.writeFileSync(hookPath, merged, { mode: 0o755 });
      return;
    }
  }

  fs.writeFileSync(hookPath, content, { mode: 0o755 });
}

function removeHooks(projectDir) {
  const gitDir = findGitDir(projectDir);
  if (!gitDir) return;

  const hooksDir = path.join(gitDir, "hooks");

  for (const hookName of ["pre-push", "pre-commit"]) {
    const hookPath = path.join(hooksDir, hookName);
    if (!fs.existsSync(hookPath)) continue;

    const content = fs.readFileSync(hookPath, "utf8");
    if (!content.includes("webapp-ss")) continue;

    // Check if it's purely our hook or merged
    const backupPath = hookPath + ".webapp-ss-backup";
    if (fs.existsSync(backupPath)) {
      // Restore the backup
      fs.copyFileSync(backupPath, hookPath);
      fs.unlinkSync(backupPath);
      console.log(`  [-] Restored original ${hookName} hook`);
    } else {
      fs.unlinkSync(hookPath);
      console.log(`  [-] Removed ${hookName} hook`);
    }
  }
}

module.exports = { installHooks, removeHooks };
