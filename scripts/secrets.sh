#!/bin/bash
# secrets.sh - Secret/credential detection in code and git history
set -euo pipefail

PROJECT_DIR="${1:-.}"
REPORT_DIR="${2:-$PROJECT_DIR/webapp-ss-reports}"

mkdir -p "$REPORT_DIR"

echo "=== SECRET SCAN: Leaked Credentials Detection ==="

# --- Gitleaks ---
echo "[*] Running Gitleaks (code + git history)..."
if command -v gitleaks &>/dev/null; then
    gitleaks detect \
        --source="$PROJECT_DIR" \
        --report-path="$REPORT_DIR/gitleaks.json" \
        --report-format=json \
        --verbose 2>&1 | tail -20 || true
else
    # Check if it's a git repo for history scanning
    GITLEAKS_CMD="detect --source=/src --report-path=/out/gitleaks.json --report-format=json"
    if [[ -d "$PROJECT_DIR/.git" ]]; then
        docker run --rm \
            -v "$PROJECT_DIR:/src:ro" \
            -v "$REPORT_DIR:/out" \
            ghcr.io/gitleaks/gitleaks:latest \
            $GITLEAKS_CMD 2>&1 | tail -20 || true
    else
        echo "  [*] Not a git repo, scanning files only..."
        docker run --rm \
            -v "$PROJECT_DIR:/src:ro" \
            -v "$REPORT_DIR:/out" \
            ghcr.io/gitleaks/gitleaks:latest \
            detect --source=/src --no-git --report-path=/out/gitleaks.json --report-format=json \
            2>&1 | tail -20 || true
    fi
fi

if [[ -f "$REPORT_DIR/gitleaks.json" ]] && [[ -s "$REPORT_DIR/gitleaks.json" ]]; then
    python3 -c "
import json
with open('$REPORT_DIR/gitleaks.json') as f:
    leaks = json.load(f)
if not leaks:
    print('  [PASS] No secrets detected.')
else:
    print(f'  [CRITICAL] Found {len(leaks)} leaked secret(s):')
    for leak in leaks[:10]:
        rule = leak.get('RuleID', '?')
        path = leak.get('File', '?')
        line = leak.get('StartLine', '?')
        match = leak.get('Match', '')[:60]
        print(f'    - {rule} in {path}:{line}')
        print(f'      Match: {match}...')
        print(f'      FIX: Remove secret, rotate the credential, use env vars or a secret manager')
    if len(leaks) > 10:
        print(f'    ... and {len(leaks)-10} more')
" 2>/dev/null || echo "  [*] Gitleaks results saved to $REPORT_DIR/gitleaks.json"
else
    echo "  [PASS] No secrets detected."
fi

echo ""

# --- Bonus: quick grep for common dangerous patterns ---
echo "[*] Quick pattern scan for common credential leaks..."
PATTERNS=(
    'password\s*=\s*["\x27][^"\x27]+'
    'api[_-]?key\s*=\s*["\x27][^"\x27]+'
    'secret[_-]?key\s*=\s*["\x27][^"\x27]+'
    'AWS_ACCESS_KEY_ID\s*=\s*["\x27]?AK'
    'PRIVATE.KEY-----'
    'ghp_[A-Za-z0-9]{36}'
    'sk-[A-Za-z0-9]{48}'
    'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.'
)

FOUND_PATTERNS=0
for pattern in "${PATTERNS[@]}"; do
    MATCHES=$(grep -rn --include='*.js' --include='*.ts' --include='*.py' \
        --include='*.jsx' --include='*.tsx' --include='*.env*' --include='*.yml' \
        --include='*.yaml' --include='*.json' --include='*.toml' --include='*.cfg' \
        -E "$pattern" "$PROJECT_DIR" 2>/dev/null | \
        grep -v 'node_modules' | grep -v '.git/' | grep -v 'webapp-ss' | head -5) || true
    if [[ -n "$MATCHES" ]]; then
        echo "  [WARN] Possible credential pattern found:"
        echo "$MATCHES" | while read -r line; do
            echo "    $line"
        done
        FOUND_PATTERNS=$((FOUND_PATTERNS + 1))
    fi
done

if [[ $FOUND_PATTERNS -eq 0 ]]; then
    echo "  [PASS] No hardcoded credential patterns found."
fi

echo ""
