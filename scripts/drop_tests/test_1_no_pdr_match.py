#!/usr/bin/env python3
"""
測試 1: NO_PDR_MATCH - 無效 TEID
發送帶有不存在 TEID 的 GTP-U 封包，UPF 找不到對應的 PDR 規則
"""

from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import time

# ============ 設定 ============
UPF_IP = "192.168.56.103"      # UPF 的 N3 介面 IP
GTP_PORT = 2152                 # GTP-U port
INVALID_TEID = 0xDEADBEEF       # 不存在的 TEID
PACKET_COUNT = 5                # 發送封包數量
# ==============================

print("=" * 60)
print("測試 1: NO_PDR_MATCH - 無效 TEID")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print(f"使用無效 TEID: {hex(INVALID_TEID)}")
print(f"發送封包數: {PACKET_COUNT}")
print("-" * 60)

for i in range(PACKET_COUNT):
    # 構建 GTP-U 封包，包含內部 IP/ICMP
    pkt = (
        IP(dst=UPF_IP) /
        UDP(sport=GTP_PORT, dport=GTP_PORT) /
        GTP_U_Header(teid=INVALID_TEID, gtp_type=255) /
        IP(src="10.60.0.99", dst="8.8.8.8") /
        ICMP(type=8)  # Echo Request
    )
    
    send(pkt, verbose=False)
    print(f"[{i+1}/{PACKET_COUNT}] 發送 TEID={hex(INVALID_TEID)} -> UPF")
    time.sleep(0.2)

print("-" * 60)
print("✓ 測試完成！")
print("預期結果: UPF 應記錄 NO_PDR_MATCH drop events")
print("檢查指令: curl http://192.168.56.103:9100/api/drops | jq '.'")
