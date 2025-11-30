#!/usr/bin/env python3
"""
測試 3: NO_PDR_MATCH - 錯誤的 UE IP
使用有效 TEID 但內部封包的 UE IP 不匹配
這會導致 PDR 的 UE IP filter 不匹配
"""

from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import time

# ============ 設定 ============
UPF_IP = "192.168.56.103"
GTP_PORT = 2152

# 請先從 sessions API 獲取有效的 TEID
# curl http://192.168.56.103:9100/api/sessions | jq '.sessions[0].teids[0]'
VALID_TEID = 0x1e  # <-- 請替換為實際的有效 TEID

# 使用不存在的 UE IP (不在任何 PDR 的 UE IP range 中)
WRONG_UE_IPS = [
    "10.60.0.200",   # 超出範圍的 UE IP
    "10.99.99.99",   # 完全不同的子網
    "192.168.1.100", # 私有 IP，非 UE 範圍
]
# ==============================

print("=" * 60)
print("測試 3: NO_PDR_MATCH - 錯誤的 UE IP")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print(f"使用有效 TEID: {hex(VALID_TEID)}")
print("-" * 60)
print("⚠️  請確認 VALID_TEID 是從 sessions API 獲取的有效值！")
print("-" * 60)

for wrong_ip in WRONG_UE_IPS:
    # 使用有效 TEID 但錯誤的 UE Source IP
    pkt = (
        IP(dst=UPF_IP) /
        UDP(sport=GTP_PORT, dport=GTP_PORT) /
        GTP_U_Header(teid=VALID_TEID, gtp_type=255) /
        IP(src=wrong_ip, dst="8.8.8.8") /  # 錯誤的 UE IP
        ICMP(type=8)
    )
    
    send(pkt, verbose=False)
    print(f"[✓] 發送 TEID={hex(VALID_TEID)}, 內部 SRC IP={wrong_ip}")
    time.sleep(0.3)

print("-" * 60)
print("✓ 測試完成！")
print("預期結果: 封包應被 drop，因為 UE IP 不匹配 PDR filter")
