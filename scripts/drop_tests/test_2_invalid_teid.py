#!/usr/bin/env python3
"""
測試 2: INVALID_TEID - 特殊/邊界 TEID 值
發送帶有特殊 TEID 值的封包 (0, 全 F, 等)
"""

from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import time

# ============ 設定 ============
UPF_IP = "192.168.56.103"
GTP_PORT = 2152
# 各種特殊 TEID 值
SPECIAL_TEIDS = [
    (0x00000000, "Zero TEID"),
    (0xFFFFFFFF, "Max TEID (all 1s)"),
    (0x12345678, "Random invalid"),
    (0xCAFEBABE, "Random invalid 2"),
    (0xBAADF00D, "Random invalid 3"),
]
# ==============================

print("=" * 60)
print("測試 2: INVALID_TEID - 特殊 TEID 值測試")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print("-" * 60)

for teid, desc in SPECIAL_TEIDS:
    pkt = (
        IP(dst=UPF_IP) /
        UDP(sport=GTP_PORT, dport=GTP_PORT) /
        GTP_U_Header(teid=teid, gtp_type=255) /
        IP(src="10.60.0.99", dst="8.8.8.8") /
        ICMP(type=8)
    )
    
    send(pkt, verbose=False)
    print(f"[✓] 發送 TEID={hex(teid)} ({desc})")
    time.sleep(0.3)

print("-" * 60)
print("✓ 測試完成！")
print("預期結果: 所有封包應被 drop (NO_PDR_MATCH 或 INVALID_TEID)")
