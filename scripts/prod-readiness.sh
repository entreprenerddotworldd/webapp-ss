#!/bin/bash
# prod-readiness.sh - Production security readiness assessment
# Checks everything that matters before you push to prod
set -euo pipefail

APP_URL="${1:-}"
PROJECT_DIR="${2:-.}"
REPORT_DIR="${3:-$PROJECT_DIR/webapp-ss-reports}"

mkdir -p "$REPORT_DIR"

PASS=0
WARN=0
FAIL=0
CHECKS=()

record() {
    local status="$1" msg="$2" fix="${3:-}"
    CHECKS+=("$status|$msg|$fix")
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
    esac
}

echo "=== PRODUCTION READINESS ASSESSMENT ==="
echo "[*] Project: $PROJECT_DIR"
[[ -n "$APP_URL" ]] && echo "[*] Live URL: $APP_URL"
echo ""

# -------------------------------------------------------
# SECTION 1: Code-level checks (no running server needed)
# -------------------------------------------------------
echo "--- 1. Code & Configuration ---"

# Debug mode checks
echo "[*] Checking for debug mode indicators..."
DEBUG_HITS=$(grep -rn --include='*.js' --include='*.ts' --include='*.py' \
    --include='*.jsx' --include='*.tsx' --include='*.rb' --include='*.go' \
    --include='*.env' --include='*.env.*' --include='*.yaml' --include='*.yml' \
    --include='*.json' --include='*.toml' \
    -iE '(DEBUG\s*[:=]\s*(true|1|yes|on)|NODE_ENV\s*[:=]\s*["\x27]?development|FLASK_DEBUG|DJANGO_DEBUG)' \
    "$PROJECT_DIR" 2>/dev/null | \
    grep -v node_modules | grep -v '.git/' | grep -v webapp-ss | head -10) || true
if [[ -n "$DEBUG_HITS" ]]; then
    record "FAIL" "Debug mode enabled in source files" \
        "Ensure DEBUG=false and NODE_ENV=production in all production configs"
    echo "  [FAIL] Debug mode found:"
    echo "$DEBUG_HITS" | while read -r line; do echo "    $line"; done
else
    record "PASS" "No debug mode flags found in source"
    echo "  [PASS] No debug mode indicators"
fi

# .env file in repo
if [[ -f "$PROJECT_DIR/.env" ]] && [[ -d "$PROJECT_DIR/.git" ]]; then
    if git -C "$PROJECT_DIR" ls-files --error-unmatch .env >/dev/null 2>&1; then
        record "FAIL" ".env file is tracked by git" \
            "Add .env to .gitignore and remove from tracking: git rm --cached .env"
        echo "  [FAIL] .env file is tracked in git!"
    else
        record "PASS" ".env file exists but is not tracked by git"
        echo "  [PASS] .env exists but is gitignored"
    fi
fi

# .gitignore checks
if [[ -f "$PROJECT_DIR/.gitignore" ]]; then
    MISSING_IGNORES=()
    for pattern in ".env" ".env.*" "*.pem" "*.key" "node_modules" "__pycache__"; do
        if ! grep -q "$pattern" "$PROJECT_DIR/.gitignore" 2>/dev/null; then
            MISSING_IGNORES+=("$pattern")
        fi
    done
    if [[ ${#MISSING_IGNORES[@]} -gt 0 ]]; then
        record "WARN" "Missing .gitignore entries: ${MISSING_IGNORES[*]}" \
            "Add these patterns to .gitignore: ${MISSING_IGNORES[*]}"
        echo "  [WARN] Missing .gitignore entries: ${MISSING_IGNORES[*]}"
    else
        record "PASS" ".gitignore covers common sensitive patterns"
        echo "  [PASS] .gitignore looks good"
    fi
else
    record "FAIL" "No .gitignore file found" \
        "Create a .gitignore file to prevent committing secrets and build artifacts"
    echo "  [FAIL] No .gitignore file!"
fi

# Dockerfile security
if [[ -f "$PROJECT_DIR/Dockerfile" ]]; then
    echo "[*] Checking Dockerfile..."
    if grep -q "^FROM.*:latest" "$PROJECT_DIR/Dockerfile"; then
        record "WARN" "Dockerfile uses :latest tag" \
            "Pin to a specific version tag for reproducible builds"
        echo "  [WARN] Using :latest tag in Dockerfile"
    fi
    if grep -qE "^USER\s+root" "$PROJECT_DIR/Dockerfile" || \
       ! grep -q "^USER" "$PROJECT_DIR/Dockerfile"; then
        record "WARN" "Dockerfile may run as root" \
            "Add a non-root USER directive in your Dockerfile"
        echo "  [WARN] Container may run as root"
    else
        record "PASS" "Dockerfile uses non-root user"
        echo "  [PASS] Non-root user configured"
    fi
fi

# Check for console.log / print statements (info leakage)
echo "[*] Checking for verbose logging..."
LOG_HITS=$(grep -rn --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' \
    -E 'console\.(log|debug|trace)\(' "$PROJECT_DIR" 2>/dev/null | \
    grep -v node_modules | grep -v '.git/' | grep -v webapp-ss | \
    grep -v '\.test\.' | grep -v '\.spec\.' | wc -l) || true
if [[ "$LOG_HITS" -gt 20 ]]; then
    record "WARN" "$LOG_HITS console.log/debug statements found" \
        "Remove or replace with a proper logging library with log levels"
    echo "  [WARN] $LOG_HITS console.log/debug/trace calls (potential info leakage in prod)"
else
    record "PASS" "Minimal console logging ($LOG_HITS statements)"
    echo "  [PASS] Console logging is minimal"
fi

# Check for TODO/FIXME/HACK in security-relevant code
SEC_TODOS=$(grep -rn --include='*.js' --include='*.ts' --include='*.py' \
    --include='*.jsx' --include='*.tsx' --include='*.go' --include='*.rb' \
    -iE '(TODO|FIXME|HACK|XXX).*(auth|secur|token|password|crypt|csrf|xss|inject|sanitiz)' \
    "$PROJECT_DIR" 2>/dev/null | \
    grep -v node_modules | grep -v '.git/' | grep -v webapp-ss | head -10) || true
if [[ -n "$SEC_TODOS" ]]; then
    COUNT=$(echo "$SEC_TODOS" | wc -l)
    record "WARN" "$COUNT security-related TODO/FIXME comments found" \
        "Resolve all security-related TODOs before deploying to production"
    echo "  [WARN] $COUNT security TODOs/FIXMEs found:"
    echo "$SEC_TODOS" | head -5 | while read -r line; do echo "    $line"; done
else
    record "PASS" "No security-related TODO/FIXME comments"
    echo "  [PASS] No security TODOs"
fi

echo ""

# -------------------------------------------------------
# SECTION 2: Exposed paths (needs running server)
# -------------------------------------------------------
if [[ -n "$APP_URL" ]]; then
    echo "--- 2. Exposed Sensitive Endpoints ---"

    SENSITIVE_PATHS=(
        "/.env" "/.git/config" "/.git/HEAD"
        "/admin" "/debug" "/phpinfo.php"
        "/server-status" "/server-info"
        "/.DS_Store" "/wp-admin" "/wp-login.php"
        "/api/docs" "/swagger.json" "/openapi.json"
        "/graphql" "/graphiql"
        "/.well-known/security.txt"
        "/robots.txt" "/sitemap.xml"
        "/elmah.axd" "/trace.axd"
        "/__debug__" "/_debug_toolbar"
    )

    EXPOSED=0
    for path in "${SENSITIVE_PATHS[@]}"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${APP_URL}${path}" 2>/dev/null) || continue
        if [[ "$STATUS" =~ ^(200|301|302)$ ]]; then
            if [[ "$path" == "/.well-known/security.txt" ]] || [[ "$path" == "/robots.txt" ]]; then
                echo "  [INFO] $path ($STATUS) - expected to be public"
            else
                echo "  [FAIL] $path ($STATUS) - accessible!"
                EXPOSED=$((EXPOSED + 1))
            fi
        fi
    done

    if [[ $EXPOSED -gt 0 ]]; then
        record "FAIL" "$EXPOSED sensitive endpoint(s) are exposed" \
            "Block access to sensitive paths via middleware, reverse proxy rules, or .htaccess"
        echo "  FIX: Block these paths in your server config or add auth middleware"
    else
        record "PASS" "No sensitive endpoints exposed"
        echo "  [PASS] No sensitive endpoints accessible"
    fi

    echo ""

    # -------------------------------------------------------
    # SECTION 3: TLS / HTTPS check
    # -------------------------------------------------------
    echo "--- 3. Transport Security ---"
    if [[ "$APP_URL" == https://* ]]; then
        record "PASS" "Using HTTPS"
        echo "  [PASS] HTTPS enabled"

        # Check TLS version
        TLS_INFO=$(curl -sv --max-time 5 "$APP_URL" 2>&1 | grep "SSL connection using" | head -1) || true
        if [[ -n "$TLS_INFO" ]]; then
            echo "  [INFO] $TLS_INFO"
            if echo "$TLS_INFO" | grep -qE "TLSv1\.[01]"; then
                record "FAIL" "Using outdated TLS version" \
                    "Configure server to use TLSv1.2 or TLSv1.3 minimum"
                echo "  [FAIL] Outdated TLS version detected"
            fi
        fi
    elif [[ "$APP_URL" == http://localhost* ]] || [[ "$APP_URL" == http://127.0.0.1* ]]; then
        record "WARN" "Using HTTP (localhost is OK for dev, ensure HTTPS in prod)" \
            "Configure TLS termination via reverse proxy (nginx, Caddy) or cloud provider"
        echo "  [WARN] HTTP on localhost (expected for dev, must use HTTPS in prod)"
    else
        record "FAIL" "Using plain HTTP" \
            "Enable HTTPS with a valid TLS certificate (Let's Encrypt is free)"
        echo "  [FAIL] Plain HTTP - must use HTTPS in production!"
    fi

    echo ""
fi

# -------------------------------------------------------
# SECTION 4: Rate limiting / error handling
# -------------------------------------------------------
if [[ -n "$APP_URL" ]]; then
    echo "--- 4. Rate Limiting & Error Handling ---"

    # Check for rate limiting headers
    RATE_HEADERS=$(curl -s -D - -o /dev/null --max-time 5 "$APP_URL" 2>/dev/null | \
        grep -iE '(x-ratelimit|retry-after|x-rate-limit)' | tr -d '\r') || true
    if [[ -n "$RATE_HEADERS" ]]; then
        record "PASS" "Rate limiting headers present"
        echo "  [PASS] Rate limiting detected:"
        echo "$RATE_HEADERS" | while read -r line; do echo "    $line"; done
    else
        record "WARN" "No rate limiting headers detected" \
            "Implement rate limiting (express-rate-limit, nginx limit_req, or cloud WAF)"
        echo "  [WARN] No rate limiting headers found"
    fi

    # Check error page for info leakage
    ERROR_BODY=$(curl -s --max-time 5 "${APP_URL}/this-path-should-not-exist-$(date +%s)" 2>/dev/null) || true
    if echo "$ERROR_BODY" | grep -qiE '(stack.?trace|traceback|exception|at .+\(.+:[0-9]+\)|SQLSTATE|pg_)'; then
        record "FAIL" "Error pages leak stack traces" \
            "Configure custom error pages that don't expose internal details"
        echo "  [FAIL] Error pages expose stack traces or internal details!"
    else
        record "PASS" "Error pages don't leak internal details"
        echo "  [PASS] Error responses are clean"
    fi

    echo ""
fi

# -------------------------------------------------------
# FINAL SCORE
# -------------------------------------------------------
echo "==========================================="
echo "   PRODUCTION READINESS SCORE"
echo "==========================================="

TOTAL=$((PASS + WARN + FAIL))
if [[ $TOTAL -gt 0 ]]; then
    SCORE=$(( (PASS * 100) / TOTAL ))
else
    SCORE=100
fi

echo ""
echo "  Passed:   $PASS"
echo "  Warnings: $WARN"
echo "  Failures: $FAIL"
echo "  Score:    ${SCORE}%"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "  VERDICT: NOT READY FOR PRODUCTION"
    echo "  Fix all FAIL items before deploying."
elif [[ $WARN -gt 3 ]]; then
    echo "  VERDICT: NEEDS ATTENTION"
    echo "  No critical issues, but address warnings for hardened security."
else
    echo "  VERDICT: READY FOR PRODUCTION"
    echo "  Looking solid. Keep scanning regularly."
fi
echo ""

# Save full report
{
    echo "Production Readiness Report"
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Project: $PROJECT_DIR"
    [[ -n "$APP_URL" ]] && echo "URL: $APP_URL"
    echo "Score: ${SCORE}% (${PASS}P / ${WARN}W / ${FAIL}F)"
    echo ""
    echo "--- Details ---"
    for check in "${CHECKS[@]}"; do
        IFS='|' read -r status msg fix <<< "$check"
        echo "[$status] $msg"
        [[ -n "$fix" ]] && echo "  FIX: $fix"
    done
} > "$REPORT_DIR/prod-readiness.txt"

echo "[*] Full report: $REPORT_DIR/prod-readiness.txt"
echo ""
