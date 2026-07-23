#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_BIN="${PROJECT_DIR}/bin/agent"
API_BIN="${PROJECT_DIR}/bin/api-server"
VITE_BIN="${PROJECT_DIR}/web/node_modules/.bin/vite"

case "${1:-}" in
    "")
        ;;
    --help|-h)
        printf 'Usage: %s\n' "$0"
        printf 'Starts the 5G-DPOP agent, API server, and Vite server in one terminal.\n'
        exit 0
        ;;
    *)
        printf 'Unknown argument: %s\n' "$1" >&2
        printf 'Usage: %s\n' "$0" >&2
        exit 2
        ;;
esac

for required_file in "$AGENT_BIN" "$API_BIN" "$VITE_BIN"; do
    if [[ ! -x "$required_file" ]]; then
        printf 'Missing executable: %s\n' "$required_file" >&2
        printf 'Run the one-time setup and build steps in docs/quick-start.md.\n' >&2
        exit 1
    fi
done

agent_pid=""
api_pid=""
web_pid=""

cleanup() {
    trap - EXIT INT TERM
    printf '\nStopping 5G-DPOP services...\n'

    [[ -n "$web_pid" ]] && kill -TERM "$web_pid" 2>/dev/null || true
    [[ -n "$api_pid" ]] && kill -TERM "$api_pid" 2>/dev/null || true
    [[ -n "$agent_pid" ]] && sudo -n kill -TERM "$agent_pid" 2>/dev/null || true

    [[ -n "$web_pid" ]] && wait "$web_pid" 2>/dev/null || true
    [[ -n "$api_pid" ]] && wait "$api_pid" 2>/dev/null || true
    [[ -n "$agent_pid" ]] && wait "$agent_pid" 2>/dev/null || true
}

printf '5G-DPOP development services\n'
printf 'Agent: http://localhost:9100\n'
printf 'API:   http://localhost:8080\n'
printf 'Web:   http://localhost:3000\n\n'

# Authenticate before backgrounding the privileged eBPF agent.
sudo -v

trap cleanup EXIT
trap 'exit 130' INT TERM

sudo "$AGENT_BIN" &
agent_pid=$!

"$API_BIN" &
api_pid=$!

(
    cd "$PROJECT_DIR/web"
    exec "$VITE_BIN"
) &
web_pid=$!

set +e
wait -n "$agent_pid" "$api_pid" "$web_pid"
exit_status=$?
set -e

if [[ "$exit_status" -ne 0 ]]; then
    printf '\nA 5G-DPOP service exited with status %d.\n' "$exit_status" >&2
else
    printf '\nA 5G-DPOP service stopped.\n'
fi

exit "$exit_status"
