echo "=========================================="
echo "5G-DPOP Data Plane Observability Verification"
echo "=========================================="
echo ""

# Ports configuration
AGENT_PORT=9100
API_SERVER_PORT=8080

# 1. Check if agent is running
echo "1. Checking Agent Status..."
if pgrep -f "./bin/agent" > /dev/null; then
    echo "   ✓ Agent is running"
else
    echo "   ⚠ Agent not running. Start with: sudo ./bin/agent"
fi

# 2. Check gtp5g module
echo ""
echo "2. Checking gtp5g Kernel Module..."
if ls /proc/gtp5g/ > /dev/null 2>&1; then
    echo "   ✓ gtp5g proc files available"
    ls -la /proc/gtp5g/
else
    echo "   ⚠ gtp5g proc files not accessible"
fi

# 3. Test API endpoints
echo ""
echo "3. Testing API Endpoints..."

# Agent sessions (port 9100)
echo "   - Agent sessions (port $AGENT_PORT)..."
AGENT_SESSIONS=$(curl -s http://localhost:$AGENT_PORT/api/sessions 2>/dev/null || echo "")
if [[ $AGENT_SESSIONS == *"sessions"* ]]; then
    TOTAL=$(echo "$AGENT_SESSIONS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total', 0))" 2>/dev/null || echo "0")
    echo "     ✓ Agent sessions OK (Total: $TOTAL)"
else
    echo "     ⚠ Agent sessions not available"
fi

# API Server health (port 8080)
echo "   - API Server health (port $API_SERVER_PORT)..."
API_HEALTH=$(curl -s http://localhost:$API_SERVER_PORT/api/v1/health 2>/dev/null || echo "")
if [[ $API_HEALTH == *"status"* ]] || [[ $API_HEALTH == *"ok"* ]]; then
    echo "     ✓ API Server health OK"
else
    echo "     ⚠ API Server not available (start ./bin/api-server)"
fi

# Topology endpoint (api-server port 8080)
echo "   - Topology (port $API_SERVER_PORT)..."
TOPOLOGY=$(curl -s http://localhost:$API_SERVER_PORT/api/v1/topology 2>/dev/null || echo "")
if [[ $TOPOLOGY == *"nodes"* ]]; then
    NODES=$(echo "$TOPOLOGY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('nodes', [])))" 2>/dev/null || echo "0")
    echo "     ✓ Topology OK (Nodes: $NODES)"
else
    echo "     ⚠ Topology not available"
fi

# 4. Check gtp5g PDR/FAR data
echo ""
echo "4. Checking gtp5g Data..."
if [[ -r /proc/gtp5g/pdr ]]; then
    PDR_DATA=$(cat /proc/gtp5g/pdr 2>/dev/null || echo "")
    if [[ -n "$PDR_DATA" ]]; then
        PDR_COUNT=$(echo "$PDR_DATA" | grep -c "pdr_id" || echo "0")
        echo "   PDRs in kernel: $PDR_COUNT"
    else
        echo "   PDRs in kernel: 0"
    fi
else
    echo "   ⚠ Cannot read /proc/gtp5g/pdr"
fi

if [[ -r /proc/gtp5g/far ]]; then
    FAR_DATA=$(cat /proc/gtp5g/far 2>/dev/null || echo "")
    if [[ -n "$FAR_DATA" ]]; then
        FAR_COUNT=$(echo "$FAR_DATA" | grep -c "far_id" || echo "0")
        echo "   FARs in kernel: $FAR_COUNT"
    else
        echo "   FARs in kernel: 0"
    fi
else
    echo "   ⚠ Cannot read /proc/gtp5g/far"
fi

# 5. Check eBPF Metrics
echo ""
echo "5. Checking eBPF Metrics..."
METRICS=$(curl -s http://localhost:$AGENT_PORT/metrics 2>/dev/null || echo "")
if [[ -n "$METRICS" ]]; then
    UPF_METRICS=$(echo "$METRICS" | grep -E "upf_packets_total|upf_bytes_total|upf_active_sessions" | head -10)
    if [[ -n "$UPF_METRICS" ]]; then
        echo "$UPF_METRICS"
    else
        echo "   No UPF traffic metrics yet (no sessions active)"
    fi
    echo "   ✓ Metrics endpoint available"
else
    echo "   ⚠ Metrics endpoint not available"
fi

echo ""
echo "=========================================="
echo "Verification Complete"
echo "=========================================="
