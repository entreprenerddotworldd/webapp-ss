#!/bin/bash
# detect-port.sh - Dynamically detect running dev server port
set -euo pipefail

COMMON_PORTS=(3000 3001 4200 4321 5000 5173 5174 8000 8080 8888 9000)

detect_port() {
    local explicit_port="${1:-}"

    if [[ -n "$explicit_port" ]]; then
        if ss -tlnp 2>/dev/null | grep -q ":${explicit_port} " || \
           lsof -Pi ":${explicit_port}" -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "$explicit_port"
            return 0
        fi
        echo "[!] Port $explicit_port is not listening" >&2
        return 1
    fi

    for port in "${COMMON_PORTS[@]}"; do
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo "$port"
            return 0
        fi
    done

    # Fallback: any user-range listening port
    local found
    found=$(ss -tlnp 2>/dev/null | grep -oP ':\K[0-9]+(?= )' | \
        awk '$1 >= 3000 && $1 <= 9999' | sort -n | head -1)

    if [[ -n "$found" ]]; then
        echo "$found"
        return 0
    fi

    echo "[!] No running dev server detected" >&2
    return 1
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    detect_port "${1:-}"
fi
