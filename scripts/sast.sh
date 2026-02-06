#!/bin/bash
# sast.sh - Static Application Security Testing via Semgrep
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-.}"
REPORT_DIR="${2:-$PROJECT_DIR/webapp-ss-reports}"

mkdir -p "$REPORT_DIR"

echo "=== SAST: Semgrep Code Scan ==="

if command -v semgrep &>/dev/null; then
    echo "[*] Running Semgrep natively..."
    semgrep scan \
        --config=auto \
        --config=p/owasp-top-ten \
        --config=p/security-audit \
        --json \
        --output="$REPORT_DIR/semgrep.json" \
        "$PROJECT_DIR" 2>&1 || true

    # Generate readable summary
    if [[ -f "$REPORT_DIR/semgrep.json" ]]; then
        python3 -c "
import json, sys
with open('$REPORT_DIR/semgrep.json') as f:
    data = json.load(f)
results = data.get('results', [])
if not results:
    print('  [PASS] No issues found.')
    sys.exit(0)
by_severity = {}
for r in results:
    sev = r.get('extra', {}).get('severity', 'UNKNOWN')
    by_severity.setdefault(sev, []).append(r)
print(f'  Found {len(results)} issue(s):')
for sev in ['ERROR', 'WARNING', 'INFO', 'UNKNOWN']:
    items = by_severity.get(sev, [])
    if items:
        print(f'    {sev}: {len(items)}')
        for item in items[:5]:
            path = item.get('path', '?')
            line = item.get('start', {}).get('line', '?')
            msg = item.get('extra', {}).get('message', 'No description')
            fix = item.get('extra', {}).get('fix', '')
            print(f'      - {path}:{line} => {msg[:120]}')
            if fix:
                print(f'        FIX: {fix[:120]}')
        if len(items) > 5:
            print(f'      ... and {len(items)-5} more')
" 2>/dev/null || echo "  [*] Results saved to $REPORT_DIR/semgrep.json (install python3 for summary)"
    fi
else
    echo "[*] Semgrep not found locally, running via Docker..."
    docker run --rm \
        -v "$PROJECT_DIR:/src" \
        -v "$REPORT_DIR:/out" \
        returntocorp/semgrep:latest \
        semgrep scan \
            --config=auto \
            --config=p/owasp-top-ten \
            --config=p/security-audit \
            --json \
            --output=/out/semgrep.json \
            /src 2>&1 || true
    echo "  [*] Results saved to $REPORT_DIR/semgrep.json"
fi

echo ""
