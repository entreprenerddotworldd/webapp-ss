#!/bin/bash
# sca.sh - Software Composition Analysis (dependency vulnerabilities)
# Uses Trivy (primary) + OWASP Dependency-Check (secondary)
set -euo pipefail

PROJECT_DIR="${1:-.}"
REPORT_DIR="${2:-$PROJECT_DIR/webapp-ss-reports}"

mkdir -p "$REPORT_DIR"

echo "=== SCA: Dependency Vulnerability Scan ==="

# --- Trivy (fast, comprehensive) ---
echo "[*] Running Trivy filesystem scan..."
if command -v trivy &>/dev/null; then
    trivy fs \
        --severity HIGH,CRITICAL \
        --format json \
        --output "$REPORT_DIR/trivy.json" \
        "$PROJECT_DIR" 2>/dev/null || true
else
    docker run --rm \
        -v "$PROJECT_DIR:/src" \
        -v "$REPORT_DIR:/out" \
        aquasec/trivy:latest fs \
            --severity HIGH,CRITICAL \
            --format json \
            --output /out/trivy.json \
            /src 2>/dev/null || true
fi

if [[ -f "$REPORT_DIR/trivy.json" ]]; then
    python3 -c "
import json, sys
with open('$REPORT_DIR/trivy.json') as f:
    data = json.load(f)
results = data.get('Results', [])
total = 0
critical = 0
high = 0
vulns = []
for r in results:
    for v in r.get('Vulnerabilities', []):
        total += 1
        sev = v.get('Severity', '')
        if sev == 'CRITICAL': critical += 1
        elif sev == 'HIGH': high += 1
        vulns.append(v)
if total == 0:
    print('  [PASS] No HIGH/CRITICAL vulnerabilities in dependencies.')
else:
    print(f'  Found {total} vulnerable dependencies (CRITICAL: {critical}, HIGH: {high})')
    for v in vulns[:8]:
        pkg = v.get('PkgName', '?')
        ver = v.get('InstalledVersion', '?')
        fix = v.get('FixedVersion', 'no fix yet')
        vid = v.get('VulnerabilityID', '?')
        sev = v.get('Severity', '?')
        print(f'    [{sev}] {pkg}@{ver} ({vid})')
        print(f'      FIX: Upgrade to {fix}')
    if len(vulns) > 8:
        print(f'    ... and {len(vulns)-8} more (see trivy.json)')
" 2>/dev/null || echo "  [*] Results saved to $REPORT_DIR/trivy.json"
fi

# --- OWASP Dependency-Check (thorough, NVD-backed) ---
echo ""
echo "[*] Running OWASP Dependency-Check..."
DC_DATA="$HOME/.webapp-ss/dependency-check-data"
mkdir -p "$DC_DATA"

if command -v dependency-check &>/dev/null; then
    dependency-check \
        --project "webapp-ss-audit" \
        --scan "$PROJECT_DIR" \
        --format HTML \
        --format JSON \
        --out "$REPORT_DIR" \
        --suppression "$SCRIPT_DIR/../configs/dc-suppressions.xml" 2>/dev/null || \
    dependency-check \
        --project "webapp-ss-audit" \
        --scan "$PROJECT_DIR" \
        --format HTML \
        --format JSON \
        --out "$REPORT_DIR" 2>/dev/null || true
else
    docker run --rm \
        -v "$PROJECT_DIR:/src" \
        -v "$REPORT_DIR:/out" \
        -v "$DC_DATA:/usr/share/dependency-check/data" \
        owasp/dependency-check:latest \
            --scan /src \
            --format HTML \
            --format JSON \
            --out /out \
            --project "webapp-ss-audit" 2>/dev/null || true
fi

if [[ -f "$REPORT_DIR/dependency-check-report.html" ]]; then
    echo "  [*] OWASP Dependency-Check report: $REPORT_DIR/dependency-check-report.html"
else
    echo "  [*] Dependency-Check report generation skipped (NVD data may need initial download)"
fi

echo ""
