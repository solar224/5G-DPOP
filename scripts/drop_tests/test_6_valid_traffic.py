#!/usr/bin/env python3
"""
測試 6: 使用正確的 Session 發送合法流量 (含 Downlink 監聽)
這個測試用來確認正常流量不會被 drop，並驗證雙向通信

流程:
1. 發送 Uplink GTP-U 封包 (模擬 gNB → UPF → DN)
2. 監聽 Downlink GTP-U 封包 (DN → UPF → gNB)
"""

from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header
import time
import threading
import requests
import sys

# ============ 設定 ============
UPF_IP = "192.168.56.103"
GNB_IP = "192.168.56.104"  # 你的 UERANSIM VM IP
GTP_PORT = 2152

# 請從 sessions API 獲取有效值:
# curl http://192.168.56.103:9100/api/sessions | jq '.sessions[0]'
VALID_TEID = 0x7e           # <-- Uplink TEID (gNB → UPF)
VALID_UE_IP = "10.60.0.32"  # <-- 有效 UE IP
PACKET_COUNT = 5
LISTEN_TIMEOUT = 5          # 監聽 DL 封包的超時時間
# ==============================

# 全域變數追蹤收到的 DL 封包
dl_packets_received = []
stop_sniffing = False

def get_session_stats(ue_ip):
    """獲取指定 UE IP 的 session 統計"""
    try:
        resp = requests.get(f"http://{UPF_IP}:9100/api/sessions", timeout=5)
        data = resp.json()
        for s in data.get('sessions', []):
            if s.get('ue_ip') == ue_ip:
                return s
    except Exception as e:
        print(f"[WARN] 無法獲取 session 統計: {e}")
    return None

def sniff_downlink():
    """監聽 Downlink GTP-U 封包"""
    global dl_packets_received, stop_sniffing
    
    def packet_callback(pkt):
        if stop_sniffing:
            return
        # 檢查是否是 GTP-U 封包
        if pkt.haslayer(UDP) and pkt[UDP].dport == GTP_PORT:
            if pkt.haslayer(GTP_U_Header):
                gtp = pkt[GTP_U_Header]
                dl_packets_received.append({
                    'teid': gtp.teid,
                    'src': pkt[IP].src,
                    'dst': pkt[IP].dst
                })
                print(f"  ↓ [DL] 收到 GTP-U: TEID=0x{gtp.teid:x}, from {pkt[IP].src}")
    
    # 只監聽發往本機 GTP-U port 的封包
    filter_str = f"udp dst port {GTP_PORT} and src host {UPF_IP}"
    print(f"[監聽] 開始監聽 Downlink 封包 (filter: {filter_str})")
    
    try:
        sniff(filter=filter_str, prn=packet_callback, timeout=LISTEN_TIMEOUT, store=0)
    except Exception as e:
        print(f"[WARN] 監聽錯誤: {e}")

print("=" * 60)
print("測試 6: 合法流量測試 (雙向驗證)")
print("=" * 60)
print(f"目標 UPF: {UPF_IP}:{GTP_PORT}")
print(f"本機 gNB: {GNB_IP}")
print(f"使用 Uplink TEID: {hex(VALID_TEID)}")
print(f"使用 UE IP: {VALID_UE_IP}")
print("-" * 60)

# 獲取測試前的統計
print("\n📊 測試前 Session 狀態:")
before_stats = get_session_stats(VALID_UE_IP)
if before_stats:
    print(f"  SEID: {before_stats.get('seid')}")
    print(f"  UE IP: {before_stats.get('ue_ip')}")
    print(f"  Uplink TEID: {before_stats.get('teid_ul')} (你發送時使用)")
    print(f"  Downlink TEID: {before_stats.get('teid_dl')} (你應該收到的)")
    print(f"  gNB IP: {before_stats.get('gnb_ip')} (DL 封包發往這裡)")
    print(f"  Packets UL/DL: {before_stats.get('packets_ul')}/{before_stats.get('packets_dl')}")
    
    expected_dl_teid = before_stats.get('teid_dl')
    if expected_dl_teid:
        print(f"\n⚠️  你應該會收到 TEID={expected_dl_teid} 的 Downlink 封包")
else:
    print("  [無法獲取 session 資訊]")
    expected_dl_teid = None

print("-" * 60)

# 啟動 Downlink 監聽執行緒
print("\n🎧 啟動 Downlink 封包監聽...")
sniffer_thread = threading.Thread(target=sniff_downlink, daemon=True)
sniffer_thread.start()
time.sleep(0.5)  # 等待監聽啟動

# 發送 Uplink 封包
print("\n📤 發送 Uplink 封包 (UE → gNB → UPF → DN)...")
print("-" * 60)

for i in range(PACKET_COUNT):
    # 構建合法的 GTP-U 封包
    # 外層: 你的機器 → UPF
    # 內層: UE IP → 8.8.8.8 (ICMP Echo Request)
    pkt = (
        IP(src=GNB_IP, dst=UPF_IP) /
        UDP(sport=GTP_PORT, dport=GTP_PORT) /
        GTP_U_Header(teid=VALID_TEID, gtp_type=255) /
        IP(src=VALID_UE_IP, dst="8.8.8.8", ttl=64) /
        ICMP(type=8, id=0x1234, seq=i)  # Echo Request
    )
    
    send(pkt, verbose=False)
    print(f"  ↑ [{i+1}/{PACKET_COUNT}] 發送 UL: TEID=0x{VALID_TEID:x}, {VALID_UE_IP} → 8.8.8.8")
    time.sleep(0.3)

print("-" * 60)
print(f"\n⏳ 等待 Downlink 回應 ({LISTEN_TIMEOUT} 秒)...")

# 等待監聽完成
sniffer_thread.join(timeout=LISTEN_TIMEOUT + 1)
stop_sniffing = True
time.sleep(0.5)

# 獲取測試後的統計
print("\n📊 測試後 Session 狀態:")
after_stats = get_session_stats(VALID_UE_IP)
if after_stats:
    print(f"  Packets UL/DL: {after_stats.get('packets_ul')}/{after_stats.get('packets_dl')}")
    print(f"  Bytes UL/DL: {after_stats.get('bytes_ul')}/{after_stats.get('bytes_dl')}")

# 結果分析
print("\n" + "=" * 60)
print("📈 測試結果:")
print("=" * 60)

# Uplink 分析
if before_stats and after_stats:
    ul_diff = after_stats.get('packets_ul', 0) - before_stats.get('packets_ul', 0)
    dl_diff = after_stats.get('packets_dl', 0) - before_stats.get('packets_dl', 0)
    
    if ul_diff >= PACKET_COUNT:
        print(f"✅ Uplink:   +{ul_diff} packets (成功)")
    else:
        print(f"⚠️  Uplink:   +{ul_diff} packets (預期 {PACKET_COUNT})")
    
    if dl_diff > 0:
        print(f"✅ Downlink: +{dl_diff} packets (成功)")
    else:
        print(f"❌ Downlink: +{dl_diff} packets (未增加)")

# Downlink 監聽分析
print(f"\n🎧 本機監聽到的 Downlink 封包: {len(dl_packets_received)}")
if dl_packets_received:
    for pkt in dl_packets_received:
        print(f"  - TEID=0x{pkt['teid']:x}, from {pkt['src']} → {pkt['dst']}")
    print("✅ 成功收到 Downlink GTP-U 封包！")
else:
    print("❌ 未監聽到任何 Downlink 封包")
    print("\n可能原因:")
    print("  1. 8.8.8.8 未回應 ICMP (防火牆)")
    print("  2. UPF 未正確轉發封包到 DN")
    print("  3. UPF → gNB 路由問題")
    print("  4. gNB IP 不匹配 (UPF 發到了別的地址)")
    print("\n診斷指令 (在 UPF 主機執行):")
    print(f"  sudo tcpdump -i any host 8.8.8.8 -n")
    print(f"  sudo tcpdump -i any udp port 2152 and host {GNB_IP} -n")

print("\n" + "=" * 60)
print("✓ 測試完成！")
print("=" * 60)
print(f"\n查看 Drop Events: curl http://{UPF_IP}:9100/api/drops | jq '.recent_drops[:5]'")
