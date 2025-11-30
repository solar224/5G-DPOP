#!/bin/bash
# ============================================================
# Drop Events 測試腳本 - 主選單
# 在 UERANSIM VM 上執行
# ============================================================

set -e

UPF_IP="192.168.56.103"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================================"
echo "       Drop Events 測試工具 - UERANSIM"
echo "============================================================"
echo ""
echo "目標 UPF: $UPF_IP"
echo ""

# 檢查 scapy 是否安裝
if ! python3 -c "from scapy.all import *" 2>/dev/null; then
    echo "⚠️  Scapy 未安裝，正在安裝..."
    sudo apt-get update && sudo apt-get install -y python3-scapy
fi

echo "當前 Sessions:"
echo "------------------------------------------------------------"
curl -s http://$UPF_IP:9100/api/sessions 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for s in data.get('sessions', []):
        print(f\"  SEID: {s['seid']}, UE IP: {s['ue_ip']}, TEIDs: {s['teids']}\")
except:
    print('  無法獲取 sessions')
" || echo "  無法連接到 UPF"
echo "------------------------------------------------------------"
echo ""

echo "選擇測試:"
echo "  1) NO_PDR_MATCH - 無效 TEID (deadbeef)"
echo "  2) INVALID_TEID - 特殊 TEID 值 (0, 0xFFFFFFFF, etc)"
echo "  3) NO_PDR_MATCH - 錯誤的 UE IP"
echo "  4) MALFORMED_GTP - 格式錯誤的 GTP"
echo "  5) MTU_EXCEEDED - 超大封包"
echo "  6) 合法流量 (驗證不會 drop)"
echo "  7) 執行所有測試"
echo "  8) 查看 Drop Events"
echo "  9) 清除 Drop Events (重啟 agent)"
echo "  0) 退出"
echo ""
read -p "請選擇 [0-9]: " choice

case $choice in
    1)
        echo "執行測試 1: NO_PDR_MATCH..."
        sudo python3 "$SCRIPT_DIR/test_1_no_pdr_match.py"
        ;;
    2)
        echo "執行測試 2: INVALID_TEID..."
        sudo python3 "$SCRIPT_DIR/test_2_invalid_teid.py"
        ;;
    3)
        echo "執行測試 3: 錯誤的 UE IP..."
        read -p "請輸入有效的 TEID (hex, e.g., 0x1e): " valid_teid
        sed -i "s/VALID_TEID = 0x[0-9a-fA-F]*/VALID_TEID = $valid_teid/" "$SCRIPT_DIR/test_3_wrong_ue_ip.py"
        sudo python3 "$SCRIPT_DIR/test_3_wrong_ue_ip.py"
        ;;
    4)
        echo "執行測試 4: MALFORMED_GTP..."
        sudo python3 "$SCRIPT_DIR/test_4_malformed_gtp.py"
        ;;
    5)
        echo "執行測試 5: MTU_EXCEEDED..."
        read -p "請輸入有效的 TEID (hex, e.g., 0x1e): " valid_teid
        read -p "請輸入有效的 UE IP (e.g., 10.60.0.8): " valid_ue_ip
        sed -i "s/VALID_TEID = 0x[0-9a-fA-F]*/VALID_TEID = $valid_teid/" "$SCRIPT_DIR/test_5_large_packet.py"
        sed -i "s/VALID_UE_IP = \"[^\"]*\"/VALID_UE_IP = \"$valid_ue_ip\"/" "$SCRIPT_DIR/test_5_large_packet.py"
        sudo python3 "$SCRIPT_DIR/test_5_large_packet.py"
        ;;
    6)
        echo "執行測試 6: 合法流量..."
        read -p "請輸入有效的 TEID (hex, e.g., 0x1e): " valid_teid
        read -p "請輸入有效的 UE IP (e.g., 10.60.0.8): " valid_ue_ip
        sed -i "s/VALID_TEID = 0x[0-9a-fA-F]*/VALID_TEID = $valid_teid/" "$SCRIPT_DIR/test_6_valid_traffic.py"
        sed -i "s/VALID_UE_IP = \"[^\"]*\"/VALID_UE_IP = \"$valid_ue_ip\"/" "$SCRIPT_DIR/test_6_valid_traffic.py"
        sudo python3 "$SCRIPT_DIR/test_6_valid_traffic.py"
        ;;
    7)
        echo "執行所有測試..."
        sudo python3 "$SCRIPT_DIR/test_1_no_pdr_match.py"
        sleep 1
        sudo python3 "$SCRIPT_DIR/test_2_invalid_teid.py"
        sleep 1
        sudo python3 "$SCRIPT_DIR/test_4_malformed_gtp.py"
        ;;
    8)
        echo "當前 Drop Events:"
        curl -s http://$UPF_IP:9100/api/drops | python3 -m json.tool
        ;;
    9)
        echo "請在 UPF VM 上重啟 agent 來清除 drops"
        echo "指令: sudo pkill -f bin/agent && sudo ./bin/agent"
        ;;
    0)
        echo "退出"
        exit 0
        ;;
    *)
        echo "無效選擇"
        exit 1
        ;;
esac

echo ""
echo "============================================================"
echo "查看 Drop Events 結果:"
echo "  curl http://$UPF_IP:9100/api/drops | jq '.'"
echo "============================================================"
