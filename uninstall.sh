#!/bin/bash
# Removes webapp-ss integration from a project
set -euo pipefail

TARGET_DIR="${1:-$(pwd)}"

echo "[*] Removing webapp-ss from: $TARGET_DIR"

# Remove workflow
if [[ -f "$TARGET_DIR/.github/workflows/security-scan.yml" ]]; then
    rm "$TARGET_DIR/.github/workflows/security-scan.yml"
    echo "  [-] Removed .github/workflows/security-scan.yml"
fi

# Remove wrapper
if [[ -f "$TARGET_DIR/security-scan.sh" ]]; then
    rm "$TARGET_DIR/security-scan.sh"
    echo "  [-] Removed security-scan.sh"
fi

# Remove report directory
if [[ -d "$TARGET_DIR/webapp-ss-reports" ]]; then
    rm -rf "$TARGET_DIR/webapp-ss-reports"
    echo "  [-] Removed webapp-ss-reports/"
fi

echo ""
echo "[*] webapp-ss removed. .gitignore entries left in place (harmless)."
echo ""
