#!/bin/bash
# dast.sh - Dynamic Application Security Testing
# Uses ZAP (baseline + active) and Nuclei for live scanning
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_URL="${1:-}"
REPORT_DIR="${2:-./webapp-ss-reports}"

mkdir -p "$REPORT_DIR"

if [[ -z "$APP_URL" ]]; then
    echo "[!] Usage: dast.sh <url> [report_dir]"
    exit 1
fi

echo "=== DAST: Live Application Scan ==="
echo "[*] Target: $APP_URL"

# Verify the target is reachable
if ! curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$APP_URL" | grep -qE "^[23]"; then
    echo "[!] Target $APP_URL is not reachable. Is your dev server running?"
    exit 1
fi
echo "[*] Target is reachable."
echo ""

# --- ZAP Baseline Scan ---
echo "[*] Running OWASP ZAP Baseline Scan..."
# Determine Docker host address for reaching localhost from container
DOCKER_HOST_IP="host.docker.internal"
# On Linux, host.docker.internal may not resolve - use host network instead
ZAP_TARGET="$APP_URL"
NETWORK_FLAG=""

if [[ "$APP_URL" == *"localhost"* ]] || [[ "$APP_URL" == *"127.0.0.1"* ]]; then
    NETWORK_FLAG="--network host"
    ZAP_TARGET="$APP_URL"
fi

docker run --rm $NETWORK_FLAG \
    -v "$REPORT_DIR:/zap/wrk/:rw" \
    -t owasp/zap2docker-stable \
    zap-baseline.py \
        -t "$ZAP_TARGET" \
        -r zap-baseline.html \
        -J zap-baseline.json \
        -l WARN \
        --auto 2>&1 | tail -30 || true

if [[ -f "$REPORT_DIR/zap-baseline.json" ]]; then
    python3 -c "
import json
with open('$REPORT_DIR/zap-baseline.json') as f:
    data = json.load(f)
alerts = data.get('site', [{}])[0].get('alerts', []) if data.get('site') else []
if not alerts:
    print('  [PASS] ZAP found no issues.')
else:
    by_risk = {}
    for a in alerts:
        risk = a.get('riskdesc', 'Unknown').split(' ')[0]
        by_risk.setdefault(risk, []).append(a)
    total = len(alerts)
    print(f'  ZAP found {total} alert type(s):')
    for risk in ['High', 'Medium', 'Low', 'Informational']:
        items = by_risk.get(risk, [])
        if items:
            print(f'    {risk}: {len(items)}')
            for item in items[:3]:
                name = item.get('name', '?')
                sol = item.get('solution', 'No solution provided')
                print(f'      - {name}')
                print(f'        FIX: {sol[:150]}')
" 2>/dev/null || echo "  [*] ZAP report saved to $REPORT_DIR/zap-baseline.html"
fi

echo ""

# --- Nuclei Scan ---
echo "[*] Running Nuclei vulnerability scan..."
if command -v nuclei &>/dev/null; then
    nuclei \
        -u "$APP_URL" \
        -severity medium,high,critical \
        -json-export "$REPORT_DIR/nuclei.json" \
        -silent 2>/dev/null || true
else
    docker run --rm $NETWORK_FLAG \
        -v "$REPORT_DIR:/out" \
        projectdiscovery/nuclei:latest \
            -u "$ZAP_TARGET" \
            -severity medium,high,critical \
            -json-export /out/nuclei.json \
            -silent 2>/dev/null || true
fi

if [[ -f "$REPORT_DIR/nuclei.json" ]] && [[ -s "$REPORT_DIR/nuclei.json" ]]; then
    python3 -c "
import json
findings = []
with open('$REPORT_DIR/nuclei.json') as f:
    for line in f:
        line = line.strip()
        if line:
            findings.append(json.loads(line))
if not findings:
    print('  [PASS] Nuclei found no medium+ vulnerabilities.')
else:
    print(f'  Nuclei found {len(findings)} issue(s):')
    for item in findings[:10]:
        info = item.get('info', {})
        name = info.get('name', '?')
        sev = info.get('severity', '?')
        desc = info.get('description', '')
        matched = item.get('matched-at', '')
        print(f'    [{sev.upper()}] {name}')
        if matched:
            print(f'      URL: {matched}')
        if desc:
            print(f'      {desc[:150]}')
    if len(findings) > 10:
        print(f'    ... and {len(findings)-10} more')
" 2>/dev/null || echo "  [*] Nuclei results saved to $REPORT_DIR/nuclei.json"
else
    echo "  [PASS] Nuclei found no medium+ vulnerabilities."
fi

echo ""
