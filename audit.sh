#!/bin/bash
# ============================================================
# webapp-ss - Web Application Security Scanner
# Modular security scanning for any web project
# Usage: ./audit.sh [options]
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(pwd)"
REPORT_DIR="$PROJECT_DIR/webapp-ss-reports"
APP_PORT=""
APP_URL=""
SCAN_MODE="full"  # full, quick, code-only, live-only, prod-check

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                                                        ║"
    echo "║   █   █ █████ ████   ███  ████  ████       ████  ████  ║"
    echo "║   █   █ █     █   █ █   █ █   █ █   █     █     █      ║"
    echo "║   █ █ █ ████  ████  █████ ████  ████  ─── ████  ████   ║"
    echo "║   ██ ██ █     █   █ █   █ █     █            █     █   ║"
    echo "║   █   █ █████ ████  █   █ █     █        ████  ████    ║"
    echo "║                                                        ║"
    echo "║          Web Application Security Scanner               ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $(basename "$0") [OPTIONS]"
    echo ""
    echo "Scan Modes:"
    echo "  --full            Run all scans (default)"
    echo "  --quick           SAST + secrets only (fast, no Docker needed)"
    echo "  --code-only       SAST + SCA + secrets (no running server needed)"
    echo "  --live-only       DAST + headers only (needs running server)"
    echo "  --prod-check      Production readiness assessment"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT   Specify dev server port (auto-detected if omitted)"
    echo "  -u, --url URL     Specify full target URL"
    echo "  -d, --dir DIR     Project directory (default: current directory)"
    echo "  -o, --output DIR  Report output directory"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $(basename "$0")                     # Full scan, auto-detect port"
    echo "  $(basename "$0") --quick             # Fast code-only scan"
    echo "  $(basename "$0") -p 3000             # Full scan on port 3000"
    echo "  $(basename "$0") --prod-check        # Pre-deployment assessment"
    echo "  $(basename "$0") --url https://staging.example.com --live-only"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)       SCAN_MODE="full"; shift ;;
        --quick)      SCAN_MODE="quick"; shift ;;
        --code-only)  SCAN_MODE="code-only"; shift ;;
        --live-only)  SCAN_MODE="live-only"; shift ;;
        --prod-check) SCAN_MODE="prod-check"; shift ;;
        -p|--port)    APP_PORT="$2"; shift 2 ;;
        -u|--url)     APP_URL="$2"; shift 2 ;;
        -d|--dir)     PROJECT_DIR="$2"; shift 2 ;;
        -o|--output)  REPORT_DIR="$2"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

banner

echo -e "${BOLD}[*] Scan Mode: ${CYAN}${SCAN_MODE}${NC}"
echo -e "${BOLD}[*] Project:   ${CYAN}${PROJECT_DIR}${NC}"

mkdir -p "$REPORT_DIR"

# Detect port and build URL if needed for live scans
needs_live_server() {
    [[ "$SCAN_MODE" == "full" || "$SCAN_MODE" == "live-only" || "$SCAN_MODE" == "prod-check" ]]
}

if needs_live_server && [[ -z "$APP_URL" ]]; then
    source "$SCRIPT_DIR/scripts/detect-port.sh"
    if [[ -n "$APP_PORT" ]]; then
        DETECTED=$(detect_port "$APP_PORT") || true
    else
        DETECTED=$(detect_port) || true
    fi

    if [[ -n "$DETECTED" ]]; then
        APP_URL="http://localhost:${DETECTED}"
        echo -e "${BOLD}[*] Server:    ${GREEN}${APP_URL}${NC}"
    else
        echo -e "${YELLOW}[!] No running dev server detected.${NC}"
        if [[ "$SCAN_MODE" == "live-only" ]]; then
            echo -e "${RED}[!] Cannot run live-only scan without a server. Start your app first.${NC}"
            exit 1
        fi
        echo -e "${YELLOW}[!] Skipping live scans (DAST, headers, prod-check endpoints).${NC}"
    fi
fi

if [[ -n "$APP_URL" ]]; then
    echo -e "${BOLD}[*] Target:    ${GREEN}${APP_URL}${NC}"
fi
echo -e "${BOLD}[*] Reports:   ${CYAN}${REPORT_DIR}${NC}"
echo ""

OVERALL_EXIT=0
START_TIME=$(date +%s)

# ============================================================
# SCAN EXECUTION
# ============================================================

run_scan() {
    local name="$1" script="$2"
    shift 2
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  ${name}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    bash "$SCRIPT_DIR/scripts/${script}" "$@" || OVERALL_EXIT=1
}

# --- SAST (all modes except live-only) ---
if [[ "$SCAN_MODE" != "live-only" ]]; then
    run_scan "STATIC ANALYSIS (Semgrep)" "sast.sh" "$PROJECT_DIR" "$REPORT_DIR"
fi

# --- Secrets (all modes except live-only) ---
if [[ "$SCAN_MODE" != "live-only" ]]; then
    run_scan "SECRET DETECTION (Gitleaks)" "secrets.sh" "$PROJECT_DIR" "$REPORT_DIR"
fi

# --- SCA (full and code-only) ---
if [[ "$SCAN_MODE" == "full" || "$SCAN_MODE" == "code-only" ]]; then
    run_scan "DEPENDENCY SCAN (Trivy + OWASP)" "sca.sh" "$PROJECT_DIR" "$REPORT_DIR"
fi

# --- DAST (full and live-only, needs server) ---
if [[ "$SCAN_MODE" == "full" || "$SCAN_MODE" == "live-only" ]] && [[ -n "$APP_URL" ]]; then
    run_scan "DYNAMIC ANALYSIS (ZAP + Nuclei)" "dast.sh" "$APP_URL" "$REPORT_DIR"
fi

# --- Headers (full, live-only, prod-check) ---
if [[ -n "$APP_URL" ]] && [[ "$SCAN_MODE" != "quick" && "$SCAN_MODE" != "code-only" ]]; then
    run_scan "SECURITY HEADERS" "headers.sh" "$APP_URL" "$REPORT_DIR"
fi

# --- Prod Readiness (full and prod-check) ---
if [[ "$SCAN_MODE" == "full" || "$SCAN_MODE" == "prod-check" ]]; then
    run_scan "PRODUCTION READINESS" "prod-readiness.sh" "${APP_URL:-}" "$PROJECT_DIR" "$REPORT_DIR"
fi

# ============================================================
# FILTER RESULTS (remove noise and false positives)
# ============================================================
echo ""
if command -v node &>/dev/null; then
    # Find config file if it exists (.cjs preferred, .js fallback)
    CONFIG_FILE=""
    if [[ -f "$PROJECT_DIR/webapp-ss.config.cjs" ]]; then
        CONFIG_FILE="$PROJECT_DIR/webapp-ss.config.cjs"
    elif [[ -f "$PROJECT_DIR/webapp-ss.config.js" ]]; then
        CONFIG_FILE="$PROJECT_DIR/webapp-ss.config.js"
    fi

    echo -e "${BOLD}[*] Filtering results (removing noise)...${NC}"
    node "$SCRIPT_DIR/lib/filter-results.js" "$REPORT_DIR" "$CONFIG_FILE" 2>/dev/null || true
fi

# ============================================================
# HTML REPORT
# ============================================================
echo ""
echo -e "${BOLD}[*] Generating HTML report...${NC}"
PROJECT_NAME=$(basename "$PROJECT_DIR")
if command -v node &>/dev/null; then
    node "$SCRIPT_DIR/lib/html-report.js" "$REPORT_DIR" "$PROJECT_NAME" 2>/dev/null && \
        echo -e "  ${GREEN}[+] HTML dashboard: ${REPORT_DIR}/security-report.html${NC}" || \
        echo -e "  ${YELLOW}[!] HTML report generation failed${NC}"
else
    echo -e "  ${YELLOW}[!] Node.js not found - skipping HTML report${NC}"
fi

# ============================================================
# SUMMARY
# ============================================================
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  SCAN COMPLETE${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Duration: ${DURATION}s"
echo -e "  Reports:  ${CYAN}${REPORT_DIR}/${NC}"
echo ""

# List generated reports
echo "  Generated reports:"
for f in "$REPORT_DIR"/*; do
    [[ -f "$f" ]] && echo "    - $(basename "$f")"
done
echo ""

# Auto-open HTML report in browser if configured
if [[ "${WEBAPP_SS_OPEN_BROWSER:-0}" == "1" ]] && [[ -f "$REPORT_DIR/security-report.html" ]]; then
    xdg-open "$REPORT_DIR/security-report.html" 2>/dev/null || \
    open "$REPORT_DIR/security-report.html" 2>/dev/null || true
fi

if [[ $OVERALL_EXIT -ne 0 ]]; then
    echo -e "  ${RED}${BOLD}Security issues were found. Review reports above before pushing to production.${NC}"
else
    echo -e "  ${GREEN}${BOLD}No critical issues detected. Review reports for warnings.${NC}"
fi
echo ""

exit $OVERALL_EXIT
