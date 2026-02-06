#!/bin/bash
# headers.sh - HTTP security headers analysis
set -euo pipefail

APP_URL="${1:-}"
REPORT_DIR="${2:-./webapp-ss-reports}"

mkdir -p "$REPORT_DIR"

if [[ -z "$APP_URL" ]]; then
    echo "[!] Usage: headers.sh <url> [report_dir]"
    exit 1
fi

echo "=== SECURITY HEADERS ANALYSIS ==="
echo "[*] Target: $APP_URL"

# Fetch headers
HEADERS=$(curl -s -D - -o /dev/null --max-time 10 "$APP_URL" 2>/dev/null) || {
    echo "[!] Could not reach $APP_URL"
    exit 1
}

echo "$HEADERS" > "$REPORT_DIR/raw-headers.txt"

PASS=0
WARN=0
FAIL=0

check_header() {
    local header="$1"
    local required="$2"  # "required" or "recommended"
    local fix="$3"

    local value
    value=$(echo "$HEADERS" | grep -i "^${header}:" | head -1 | sed "s/^${header}:\s*//i" | tr -d '\r')

    if [[ -n "$value" ]]; then
        echo "  [PASS] $header: $value"
        PASS=$((PASS + 1))
    elif [[ "$required" == "required" ]]; then
        echo "  [FAIL] $header: MISSING"
        echo "         FIX: $fix"
        FAIL=$((FAIL + 1))
    else
        echo "  [WARN] $header: MISSING"
        echo "         FIX: $fix"
        WARN=$((WARN + 1))
    fi
}

echo ""
echo "--- Required Headers ---"
check_header "Strict-Transport-Security" "required" \
    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
check_header "X-Content-Type-Options" "required" \
    "Add 'X-Content-Type-Options: nosniff'"
check_header "X-Frame-Options" "required" \
    "Add 'X-Frame-Options: DENY' (or SAMEORIGIN if you use iframes)"
check_header "Content-Security-Policy" "required" \
    "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"

echo ""
echo "--- Recommended Headers ---"
check_header "Referrer-Policy" "recommended" \
    "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
check_header "Permissions-Policy" "recommended" \
    "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'"
check_header "X-XSS-Protection" "recommended" \
    "Add 'X-XSS-Protection: 0' (CSP supersedes this, but set to 0 to prevent legacy browser bugs)"
check_header "Cross-Origin-Opener-Policy" "recommended" \
    "Add 'Cross-Origin-Opener-Policy: same-origin'"
check_header "Cross-Origin-Resource-Policy" "recommended" \
    "Add 'Cross-Origin-Resource-Policy: same-origin'"
check_header "Cross-Origin-Embedder-Policy" "recommended" \
    "Add 'Cross-Origin-Embedder-Policy: require-corp'"

echo ""
echo "--- Dangerous Headers (should NOT be present) ---"

SERVER_HEADER=$(echo "$HEADERS" | grep -i "^server:" | head -1 | tr -d '\r')
if [[ -n "$SERVER_HEADER" ]]; then
    echo "  [WARN] $SERVER_HEADER"
    echo "         FIX: Remove or genericize the Server header to prevent version fingerprinting"
    WARN=$((WARN + 1))
else
    echo "  [PASS] Server header not exposed"
    PASS=$((PASS + 1))
fi

POWERED_BY=$(echo "$HEADERS" | grep -i "^x-powered-by:" | head -1 | tr -d '\r')
if [[ -n "$POWERED_BY" ]]; then
    echo "  [FAIL] $POWERED_BY"
    echo "         FIX: Remove X-Powered-By header (Express: app.disable('x-powered-by'))"
    FAIL=$((FAIL + 1))
else
    echo "  [PASS] X-Powered-By not exposed"
    PASS=$((PASS + 1))
fi

echo ""
echo "--- Cookie Security ---"
COOKIES=$(echo "$HEADERS" | grep -i "^set-cookie:" | tr -d '\r')
if [[ -n "$COOKIES" ]]; then
    echo "$COOKIES" | while read -r cookie; do
        echo "  Cookie: ${cookie:0:80}..."
        if ! echo "$cookie" | grep -qi "secure"; then
            echo "    [FAIL] Missing 'Secure' flag"
            echo "    FIX: Add Secure flag so cookie is only sent over HTTPS"
        fi
        if ! echo "$cookie" | grep -qi "httponly"; then
            echo "    [WARN] Missing 'HttpOnly' flag"
            echo "    FIX: Add HttpOnly flag to prevent JavaScript access"
        fi
        if ! echo "$cookie" | grep -qi "samesite"; then
            echo "    [WARN] Missing 'SameSite' flag"
            echo "    FIX: Add SameSite=Lax (or Strict) to prevent CSRF"
        fi
    done
else
    echo "  [INFO] No cookies set on this page"
fi

echo ""
echo "--- CORS Check ---"
CORS_RESPONSE=$(curl -s -D - -o /dev/null --max-time 10 \
    -H "Origin: https://evil-attacker.com" "$APP_URL" 2>/dev/null)
ACAO=$(echo "$CORS_RESPONSE" | grep -i "^access-control-allow-origin:" | tr -d '\r')
if [[ -n "$ACAO" ]]; then
    if echo "$ACAO" | grep -q '\*'; then
        echo "  [WARN] CORS: Access-Control-Allow-Origin: * (wildcard)"
        echo "         FIX: Restrict to specific trusted origins instead of wildcard"
        WARN=$((WARN + 1))
    elif echo "$ACAO" | grep -qi "evil-attacker"; then
        echo "  [FAIL] CORS: Origin reflection detected - reflects any origin!"
        echo "         FIX: Validate origins against an allowlist, never reflect blindly"
        FAIL=$((FAIL + 1))
    else
        echo "  [PASS] CORS configured: $ACAO"
        PASS=$((PASS + 1))
    fi
else
    echo "  [PASS] No CORS headers (same-origin only)"
    PASS=$((PASS + 1))
fi

echo ""
TOTAL=$((PASS + WARN + FAIL))
echo "--- Summary: $PASS passed, $WARN warnings, $FAIL failures out of $TOTAL checks ---"

# Save report
cat > "$REPORT_DIR/headers-report.txt" <<EOF
Security Headers Report for $APP_URL
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Passed: $PASS | Warnings: $WARN | Failures: $FAIL

Raw headers saved to: $REPORT_DIR/raw-headers.txt
EOF

echo ""
