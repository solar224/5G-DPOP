#!/usr/bin/env bash

set -u

AGENT_URL="${AGENT_URL:-http://127.0.0.1:9100}"
API_URL="${API_URL:-http://127.0.0.1:8080/api/v1}"
EXPECTED_GNB_N3="${EXPECTED_GNB_N3:-192.168.56.101}"
EXPECTED_UPF_N3="${EXPECTED_UPF_N3:-192.168.56.103}"
EXPECTED_UPF_N4="${EXPECTED_UPF_N4:-127.0.0.8}"

passes=0
warnings=0
failures=0

pass() {
    printf 'PASS  %s\n' "$1"
    passes=$((passes + 1))
}

warn() {
    printf 'WARN  %s\n' "$1"
    warnings=$((warnings + 1))
}

fail() {
    printf 'FAIL  %s\n' "$1"
    failures=$((failures + 1))
}

printf '5G-DPOP architecture verification\n'
printf 'Expected N3: gNB %s -> UPF %s; N4 UPF %s\n\n' \
    "$EXPECTED_GNB_N3" "$EXPECTED_UPF_N3" "$EXPECTED_UPF_N4"

if [[ -r /sys/module/gtp5g/version ]]; then
    gtp5g_version="$(< /sys/module/gtp5g/version)"
    pass "gtp5g module loaded (version ${gtp5g_version})"
else
    fail "gtp5g module is not loaded"
fi

for symbol in gtp5g_trace_drop gtp5g_encap_recv gtp5g_dev_xmit pdr_find_by_gtp1u pdr_find_by_ipv4; do
    if grep -Eq "[[:space:]]${symbol}([[:space:]]|$)" /proc/kallsyms 2>/dev/null; then
        pass "kernel hook available: ${symbol}"
    else
        fail "kernel hook missing: ${symbol}"
    fi
done

if grep -Eq 'bpf_prog_.*_kprobe_gtp5g_encap_recv' /proc/kallsyms 2>/dev/null &&
   grep -Eq 'bpf_prog_.*_kprobe_gtp5g_dev_xmit' /proc/kallsyms 2>/dev/null; then
    pass "eBPF traffic programs are attached"
else
    fail "eBPF traffic programs are not attached"
fi

if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]]; then
    pass "IPv4 forwarding is enabled"
else
    fail "IPv4 forwarding is disabled"
fi

if ip link show upfgtp >/dev/null 2>&1; then
    pass "upfgtp interface exists"
else
    fail "upfgtp interface is missing"
fi

for subnet in 10.60.0.0/16 10.61.0.0/16; do
    if ip route show "$subnet" 2>/dev/null | grep -Eq 'dev upfgtp'; then
        pass "${subnet} is routed through upfgtp"
    else
        fail "${subnet} is not routed through upfgtp"
    fi
done

if ss -lun 2>/dev/null | grep -Eq "${EXPECTED_UPF_N3}:2152"; then
    pass "UPF GTP-U socket listens on ${EXPECTED_UPF_N3}:2152"
else
    fail "UPF GTP-U socket is not listening on ${EXPECTED_UPF_N3}:2152"
fi

if ss -lun 2>/dev/null | grep -Eq "${EXPECTED_UPF_N4}:8805"; then
    pass "UPF PFCP socket listens on ${EXPECTED_UPF_N4}:8805"
else
    fail "UPF PFCP socket is not listening on ${EXPECTED_UPF_N4}:8805"
fi

agent_health="$(curl -fsS "${AGENT_URL}/health" 2>/dev/null || true)"
if [[ "$agent_health" == "OK" ]]; then
    pass "5G-DPOP agent is healthy"
else
    fail "5G-DPOP agent is unavailable at ${AGENT_URL}"
fi

interfaces_json="$(curl -fsS "${AGENT_URL}/api/interfaces" 2>/dev/null || true)"
if [[ -n "$interfaces_json" ]]; then
    capture_iface="$(
        python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("active_capture") or d.get("current_config") or "")' \
            <<< "$interfaces_json" 2>/dev/null || true
    )"
    if [[ "$capture_iface" == "lo" || "$capture_iface" == "any" ]]; then
        pass "PFCP capture interface includes native loopback traffic (${capture_iface})"
    else
        warn "PFCP capture reports '${capture_iface}'; native free5GC should use lo or any"
    fi
else
    fail "agent interface API is unavailable"
fi

metrics="$(curl -fsS "${AGENT_URL}/metrics" 2>/dev/null || true)"
if grep -Eq '^upf_packets_total\{direction="uplink"\}' <<< "$metrics" &&
   grep -Eq '^upf_packets_total\{direction="downlink"\}' <<< "$metrics"; then
    pass "eBPF uplink/downlink counters are exported"
else
    fail "eBPF traffic counters are missing"
fi

sessions_json="$(curl -fsS "${AGENT_URL}/api/sessions" 2>/dev/null || true)"
if [[ -n "$sessions_json" ]]; then
    session_summary="$(
        python3 -c '
import json, sys
d = json.load(sys.stdin)
c = d.get("counts", {})
print("active={active} stale={stale} pending={pending} failed={failed}".format(
    active=c.get("active", 0), stale=c.get("stale", 0),
    pending=c.get("pending", 0), failed=c.get("failed", 0)))
' <<< "$sessions_json" 2>/dev/null || true
    )"
    pass "agent session API is valid (${session_summary})"
else
    fail "agent session API is unavailable"
fi

api_health="$(curl -fsS "${API_URL}/health" 2>/dev/null || true)"
if [[ -n "$api_health" ]]; then
    pass "5G-DPOP topology API is healthy"
else
    fail "5G-DPOP API is unavailable at ${API_URL}"
fi

topology_json="$(curl -fsS "${API_URL}/topology" 2>/dev/null || true)"
if [[ -n "$topology_json" ]]; then
    topology_result="$(
        EXPECTED_GNB_N3="$EXPECTED_GNB_N3" \
        EXPECTED_UPF_N3="$EXPECTED_UPF_N3" \
        EXPECTED_UPF_N4="$EXPECTED_UPF_N4" \
        python3 -c '
import json, os, sys
d = json.load(sys.stdin)
nodes = d.get("nodes", [])
links = d.get("links", [])
gnb = os.environ["EXPECTED_GNB_N3"]
upf_n3 = os.environ["EXPECTED_UPF_N3"]
upf_n4 = os.environ["EXPECTED_UPF_N4"]

upf = next((n for n in nodes if n.get("type") == "upf" and n.get("id") == upf_n4), None)
n3 = next((l for l in links if l.get("type") == "n3" and
           l.get("source") == gnb and l.get("target") == upf_n4), None)
radio = any(l.get("type") == "radio" for l in links)
n6 = any(l.get("type") == "n6" and l.get("source") == upf_n4 for l in links)

if not upf or not n3 or not radio or not n6:
    print("missing required UE-Radio-gNB-N3-UPF-N6-DN structure")
    raise SystemExit(1)
if upf.get("n3_ip") != upf_n3 or upf.get("n4_ip") != upf_n4:
    print("path is connected, but UPF N3/N4 metadata is not populated; restart the rebuilt agent before UE registration")
    raise SystemExit(2)
print("UE -> gNB -> UPF -> DN is connected and N3/N4 metadata is correct")
' <<< "$topology_json" 2>/dev/null
    )"
    topology_status=$?
    if [[ $topology_status -eq 0 ]]; then
        pass "$topology_result"
    elif [[ $topology_status -eq 2 ]]; then
        warn "$topology_result"
    else
        fail "$topology_result"
    fi
else
    fail "topology endpoint returned no data"
fi

printf '\nSummary: %d pass, %d warning, %d failure\n' "$passes" "$warnings" "$failures"

if [[ $failures -gt 0 ]]; then
    exit 1
fi
