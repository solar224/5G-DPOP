#!/usr/bin/env python3
"""
測試 6: 使用正確的 Session 發送合法流量
這個測試用來確認正常流量不會被 drop
"""

from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import time

# ============ 設定 ============
UPF_IP = "192.168.56.103"
GTP_PORT = 2152

# 請從 sessions API 獲取有效值:
# curl http://192.168.56.103:9100/api/sessions | jq '.sessions[0]'
VALID_TEID = 0x1e           # <-- 替換為有效 TEID
VALID_UE_IP = "10.60.0.8"   # <-- 替換為有效 UE IP
PACKET_COUNT = 5
# ==============================

print("=" * 60)
print("測試 6: 合法流量測試 (不應該有 drop)")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print(f"使用有效 TEID: {hex(VALID_TEID)}")
print(f"使用有效 UE IP: {VALID_UE_IP}")
print("-" * 60)
print("⚠️  請確認 VALID_TEID 和 VALID_UE_IP 是正確的！")
print("-" * 60)

for i in range(PACKET_COUNT):
    # 構建合法的 GTP-U 封包
    pkt = (
        IP(dst=UPF_IP) /
        UDP(sport=GTP_PORT, dport=GTP_PORT) /
        GTP_U_Header(teid=VALID_TEID, gtp_type=255) /
        IP(src=VALID_UE_IP, dst="8.8.8.8") /
        ICMP(type=8, seq=i)
    )
    
    send(pkt, verbose=False)
    print(f"[{i+1}/{PACKET_COUNT}] 發送合法封包 TEID={hex(VALID_TEID)}, UE={VALID_UE_IP}")
    time.sleep(0.2)

print("-" * 60)
print("✓ 測試完成！")
print("預期結果: 這些封包應該被正常轉發，不應該出現在 drop events 中")
