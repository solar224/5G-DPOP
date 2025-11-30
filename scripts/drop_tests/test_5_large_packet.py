#!/usr/bin/env python3
"""
測試 5: MTU_EXCEEDED - 超大封包
發送超過 MTU 限制的大封包
"""

from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import time

# ============ 設定 ============
UPF_IP = "192.168.56.103"
GTP_PORT = 2152
VALID_TEID = 0x1e  # <-- 請替換為實際的有效 TEID
VALID_UE_IP = "10.60.0.8"  # <-- 請替換為實際的有效 UE IP

# 測試不同大小的封包
PACKET_SIZES = [
    (1400, "正常大小"),
    (1500, "接近 MTU"),
    (2000, "超過 MTU"),
    (4000, "大幅超過 MTU"),
    (8000, "極大封包"),
]
# ==============================

print("=" * 60)
print("測試 5: MTU_EXCEEDED - 超大封包")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print(f"使用 TEID: {hex(VALID_TEID)}")
print(f"使用 UE IP: {VALID_UE_IP}")
print("-" * 60)
print("⚠️  請確認 VALID_TEID 和 VALID_UE_IP 是有效值！")
print("-" * 60)

for size, desc in PACKET_SIZES:
    # 計算需要的 payload 大小 (扣除 IP + UDP + GTP + inner IP + ICMP headers)
    # 大約需要扣除 70+ bytes 的 headers
    payload_size = max(0, size - 80)
    
    pkt = (
        IP(dst=UPF_IP) /
        UDP(sport=GTP_PORT, dport=GTP_PORT) /
        GTP_U_Header(teid=VALID_TEID, gtp_type=255) /
        IP(src=VALID_UE_IP, dst="8.8.8.8") /
        ICMP(type=8) /
        Raw(load='X' * payload_size)
    )
    
    actual_size = len(pkt)
    send(pkt, verbose=False)
    print(f"[✓] 發送 {actual_size} bytes 封包 - {desc}")
    time.sleep(0.3)

print("-" * 60)
print("✓ 測試完成！")
print("預期結果: 超大封包可能觸發 MTU_EXCEEDED")
print("注意: 某些環境下大封包可能被分片而非 drop")
