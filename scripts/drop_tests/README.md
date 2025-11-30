# Drop Events 測試指南

本目錄包含各種 Drop Events 的測試腳本，用於在 UERANSIM VM 上執行。

## 前置需求

在 UERANSIM VM 上安裝必要工具：
```bash
sudo apt-get update
sudo apt-get install -y python3-scapy hping3 iperf3
```

## 測試類型

| 測試 | Drop Reason | 說明 |
|------|-------------|------|
| test_1_no_pdr_match.py | NO_PDR_MATCH | 無效 TEID，PDR 表中找不到 |
| test_2_invalid_teid.py | INVALID_TEID | 格式錯誤的 TEID |
| test_3_wrong_ue_ip.py | NO_PDR_MATCH | UE IP 不匹配 |
| test_4_malformed_gtp.py | MALFORMED_GTP | GTP 標頭格式錯誤 |
| test_5_large_packet.py | MTU_EXCEEDED | 封包過大 |

## 執行方式

將腳本複製到 UERANSIM VM 後執行：
```bash
sudo python3 test_1_no_pdr_match.py
```

## UPF 資訊

- UPF IP: 192.168.56.103
- GTP-U Port: 2152
- 有效 TEIDs: 查看 `curl http://<UPF_IP>:9100/api/sessions`
