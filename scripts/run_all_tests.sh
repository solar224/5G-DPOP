#!/bin/bash

echo "============================================"
echo "  CNDI-Final Complete Test Suite"
echo "============================================"
echo ""

TARGET="192.168.56.103"
CNDI_DIR="/home/ubuntu25/CNDI-Final"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[ERROR] Please run as root (sudo)"
    exit 1
fi

# Function to show metrics
show_metrics() {
    echo ""
    echo "[METRICS] Current stats:"
    curl -s http://localhost:8080/api/v1/metrics/traffic 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "API not available"
    echo ""
}

# Test 1: Traffic mode
echo "[TEST 1] Normal GTP Traffic..."
$CNDI_DIR/bin/fault-injector -mode traffic -count 50 -target $TARGET
sleep 1
show_metrics

# Test 2: Invalid TEID
echo "[TEST 2] Invalid TEID Injection..."
$CNDI_DIR/bin/fault-injector -mode invalid-teid -count 30 -target $TARGET
sleep 1
echo "[DROPS] Current drop stats:"
curl -s http://localhost:8080/api/v1/metrics/drops 2>/dev/null | python3 -m json.tool 2>/dev/null

# Test 3: Malformed packets
echo ""
echo "[TEST 3] Malformed Packets..."
$CNDI_DIR/bin/fault-injector -mode malformed -count 20 -target $TARGET
sleep 1

# Test 4: Short flood test
echo ""
echo "[TEST 4] Short Flood Test (3 seconds)..."
$CNDI_DIR/bin/fault-injector -mode flood -duration 3 -rate 1000 -target $TARGET
sleep 1

echo ""
echo "============================================"
echo "  Test Complete!"
echo "============================================"
show_metrics

echo ""
echo "[FINAL DROPS]"
curl -s http://localhost:8080/api/v1/metrics/drops 2>/dev/null | python3 -m json.tool 2>/dev/null
