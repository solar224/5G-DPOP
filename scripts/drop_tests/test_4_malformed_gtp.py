#!/usr/bin/env python3
"""
測試 4: MALFORMED_GTP - 格式錯誤的 GTP 封包
發送各種格式錯誤的 GTP-U 封包
"""

from scapy.all import *
import time

# ============ 設定 ============
UPF_IP = "192.168.56.103"
GTP_PORT = 2152
# ==============================

print("=" * 60)
print("測試 4: MALFORMED_GTP - 格式錯誤的 GTP 封包")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print("-" * 60)

# 測試 4.1: 太短的 GTP 標頭 (少於 8 bytes)
print("[4.1] 發送過短的 GTP 標頭 (4 bytes)...")
short_gtp = bytes([0x30, 0xff, 0x00, 0x04])  # 只有 4 bytes
pkt1 = IP(dst=UPF_IP) / UDP(sport=GTP_PORT, dport=GTP_PORT) / Raw(load=short_gtp)
send(pkt1, verbose=False)
print("     ✓ 已發送")
time.sleep(0.3)

# 測試 4.2: 錯誤的 GTP 版本
print("[4.2] 發送錯誤的 GTP 版本 (version=0)...")
wrong_version = bytes([
    0x00,  # Version=0 (應該是 1), PT=0, E=0, S=0, PN=0
    0xff,  # Message Type: G-PDU
    0x00, 0x14,  # Length: 20
    0x00, 0x00, 0x00, 0x01,  # TEID: 1
    # 內部 IP
    0x45, 0x00, 0x00, 0x14,  # IP header
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x01, 0x00, 0x00,
    0x0a, 0x3c, 0x00, 0x63,  # src: 10.60.0.99
    0x08, 0x08, 0x08, 0x08,  # dst: 8.8.8.8
])
pkt2 = IP(dst=UPF_IP) / UDP(sport=GTP_PORT, dport=GTP_PORT) / Raw(load=wrong_version)
send(pkt2, verbose=False)
print("     ✓ 已發送")
time.sleep(0.3)

# 測試 4.3: 長度欄位不匹配
print("[4.3] 發送長度欄位錯誤的 GTP 封包...")
wrong_length = bytes([
    0x30,  # Version=1, PT=1, E=0, S=0, PN=0
    0xff,  # Message Type: G-PDU
    0x00, 0xff,  # Length: 255 (但實際內容很短)
    0x00, 0x00, 0x00, 0x01,  # TEID: 1
    # 只有很少的 payload
    0x45, 0x00, 0x00, 0x14,
])
pkt3 = IP(dst=UPF_IP) / UDP(sport=GTP_PORT, dport=GTP_PORT) / Raw(load=wrong_length)
send(pkt3, verbose=False)
print("     ✓ 已發送")
time.sleep(0.3)

# 測試 4.4: 錯誤的 Message Type
print("[4.4] 發送不支援的 Message Type...")
wrong_type = bytes([
    0x30,  # Version=1, PT=1
    0x00,  # Message Type: 0 (Echo Request，但 PT=1 時不應該用)
    0x00, 0x14,  # Length
    0x00, 0x00, 0x00, 0x01,  # TEID
    0x45, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x01, 0x00, 0x00,
    0x0a, 0x3c, 0x00, 0x63,
    0x08, 0x08, 0x08, 0x08,
])
pkt4 = IP(dst=UPF_IP) / UDP(sport=GTP_PORT, dport=GTP_PORT) / Raw(load=wrong_type)
send(pkt4, verbose=False)
print("     ✓ 已發送")
time.sleep(0.3)

# 測試 4.5: 空的 GTP payload
print("[4.5] 發送空 payload 的 GTP 封包...")
empty_payload = bytes([
    0x30, 0xff,  # Version=1, Type=G-PDU
    0x00, 0x00,  # Length: 0
    0x00, 0x00, 0x00, 0x01,  # TEID
    # 沒有 payload
])
pkt5 = IP(dst=UPF_IP) / UDP(sport=GTP_PORT, dport=GTP_PORT) / Raw(load=empty_payload)
send(pkt5, verbose=False)
print("     ✓ 已發送")

print("-" * 60)
print("✓ 測試完成！")
print("預期結果: 各種 MALFORMED_GTP 或其他 drop reasons")
