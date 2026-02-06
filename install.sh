#!/bin/bash
# ============================================================
# webapp-ss installer
# Integrates webapp-ss into any project:
#   1. Copies GitHub Actions workflow
#   2. Adds report dir to .gitignore
#   3. Creates convenience symlink or wrapper script
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-$(pwd)}"

echo "[*] Installing webapp-ss into: $TARGET_DIR"
echo ""

# Validate target
if [[ ! -d "$TARGET_DIR" ]]; then
    echo "[!] Target directory does not exist: $TARGET_DIR"
    exit 1
fi

# 1. Copy GitHub Actions workflow
echo "[*] Setting up GitHub Actions workflow..."
mkdir -p "$TARGET_DIR/.github/workflows"
cp "$SCRIPT_DIR/workflows/security-scan.yml" "$TARGET_DIR/.github/workflows/security-scan.yml"
echo "  [+] Copied .github/workflows/security-scan.yml"

# 2. Add report directory to .gitignore
echo "[*] Updating .gitignore..."
GITIGNORE="$TARGET_DIR/.gitignore"
ENTRIES=(
    "webapp-ss-reports/"
    "dependency-check-report.*"
    "zap-baseline.*"
    "zap_report.*"
)

touch "$GITIGNORE"
for entry in "${ENTRIES[@]}"; do
    if ! grep -qF "$entry" "$GITIGNORE" 2>/dev/null; then
        echo "$entry" >> "$GITIGNORE"
        echo "  [+] Added '$entry' to .gitignore"
    fi
done

# 3. Determine webapp-ss location relative to target or use absolute
WEBAPP_SS_PATH="$SCRIPT_DIR"

# If webapp-ss is a subdirectory of the target (e.g., git submodule)
if [[ "$SCRIPT_DIR" == "$TARGET_DIR"/* ]]; then
    RELATIVE_PATH="${SCRIPT_DIR#$TARGET_DIR/}"
    WEBAPP_SS_PATH="\$(dirname \"\$0\")/$RELATIVE_PATH"
    echo "  [*] Detected as subdirectory: $RELATIVE_PATH"
fi

# 4. Create wrapper script in project root
WRAPPER="$TARGET_DIR/security-scan.sh"
cat > "$WRAPPER" << WRAPPER_EOF
#!/bin/bash
# webapp-ss security scanner wrapper
# Run: ./security-scan.sh [options]
# See:  ./security-scan.sh --help

WEBAPP_SS_DIR="${SCRIPT_DIR}"

# If webapp-ss was added as a git submodule, try relative path
if [[ ! -d "\$WEBAPP_SS_DIR" ]]; then
    WEBAPP_SS_DIR="\$(dirname "\$0")/webapp-ss"
fi

if [[ ! -f "\$WEBAPP_SS_DIR/audit.sh" ]]; then
    echo "[!] webapp-ss not found. Clone it:"
    echo "    git clone https://github.com/YOUR_USER/webapp-ss.git"
    echo "    or: git submodule add https://github.com/YOUR_USER/webapp-ss.git"
    exit 1
fi

exec bash "\$WEBAPP_SS_DIR/audit.sh" "\$@"
WRAPPER_EOF
chmod +x "$WRAPPER"
echo "  [+] Created $WRAPPER"

# 5. Check prerequisites
echo ""
echo "[*] Checking prerequisites..."

check_tool() {
    local name="$1" install_cmd="$2"
    if command -v "$name" &>/dev/null; then
        echo "  [OK] $name"
    else
        echo "  [--] $name (not installed)"
        echo "       Install: $install_cmd"
    fi
}

check_tool "docker" "sudo pacman -S docker"
check_tool "semgrep" "yay -S semgrep-bin  OR  pip install semgrep"
check_tool "trivy" "yay -S trivy-bin  OR  Docker fallback available"
check_tool "gitleaks" "yay -S gitleaks  OR  Docker fallback available"
check_tool "nuclei" "yay -S nuclei-bin  OR  Docker fallback available"
check_tool "dependency-check" "yay -S dependency-check-bin  OR  Docker fallback available"

echo ""
echo "[*] NOTE: All tools have Docker fallbacks. Only Docker is truly required."
echo ""
echo "==========================================="
echo "  webapp-ss installed successfully!"
echo "==========================================="
echo ""
echo "  Quick scan:    ./security-scan.sh --quick"
echo "  Full scan:     ./security-scan.sh"
echo "  Prod check:    ./security-scan.sh --prod-check"
echo "  Help:          ./security-scan.sh --help"
echo ""
echo "  GitHub Actions will run automatically on push."
echo ""
