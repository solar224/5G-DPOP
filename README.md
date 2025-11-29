# CNDI-Final: 5G UPF Data Plane Observability Platform

一個基於 **eBPF** 技術的非侵入式 5G 核心網用戶平面（User Plane）可觀測平台。本專案透過 Linux eBPF kprobe 機制直接 hook `gtp5g` 內核模組函數，實現對 free5GC UPF 的即時流量監控、封包丟失偵測與 PFCP Session 關聯分析，完全不需要修改任何 free5GC 或 gtp5g 的原始碼。

---

## 系統架構

### 整體架構概覽

本平台採用分層式架構設計，主要由以下四個核心層次組成：

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              VM 1: free5GC Host (Ubuntu 25.04)                    │
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                           Linux Kernel Space                                 │  │
│  │  ┌───────────────────┐    ┌─────────────────────────────────────────────┐   │  │
│  │  │                   │    │              gtp5g Kernel Module             │   │  │
│  │  │   Network Stack   │◄──►│  ┌─────────────────┐  ┌─────────────────┐   │   │  │
│  │  │   (N3/N6/N9)      │    │  │ gtp5g_encap_recv│  │ gtp5g_dev_xmit  │   │   │  │
│  │  │                   │    │  │   (Uplink RX)   │  │  (Downlink TX)  │   │   │  │
│  │  └───────────────────┘    │  └────────┬────────┘  └────────┬────────┘   │   │  │
│  │                           │           │                    │            │   │  │
│  │  ┌────────────────────────┼───────────┼────────────────────┼────────────┼─┐ │  │
│  │  │                        │    eBPF   │    Probes          │            │ │ │  │
│  │  │  ┌─────────────────────▼───────────▼────────────────────▼──────────┐ │ │ │  │
│  │  │  │                    kprobe Hooks                                  │ │ │ │  │
│  │  │  │  - kprobe/gtp5g_encap_recv  (Uplink 封包進入點)                 │ │ │ │  │
│  │  │  │  - kprobe/gtp5g_dev_xmit    (Downlink 封包發送點)               │ │ │ │  │
│  │  │  │  - tracepoint/skb/kfree_skb (封包丟棄事件)                      │ │ │ │  │
│  │  │  └─────────────────────────────────────────────────────────────────┘ │ │ │  │
│  │  │                                    │                                  │ │ │  │
│  │  │  ┌─────────────────────────────────▼──────────────────────────────┐  │ │ │  │
│  │  │  │                     eBPF Maps (Kernel)                         │  │ │ │  │
│  │  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │  │ │ │  │
│  │  │  │  │ traffic_stats│  │ drop_events  │  │ teid_session_map     │ │  │ │ │  │
│  │  │  │  │ (PERCPU_ARRAY)│  │ (RINGBUF)    │  │ (HASH)               │ │  │ │ │  │
│  │  │  │  │ UL/DL 計數器 │  │ 丟包事件佇列 │  │ TEID↔Session 對應   │ │  │ │ │  │
│  │  │  │  └──────────────┘  └──────┬───────┘  └──────────────────────┘ │  │ │ │  │
│  │  │  └───────────────────────────┼────────────────────────────────────┘  │ │ │  │
│  │  └──────────────────────────────┼───────────────────────────────────────┘ │ │  │
│  └─────────────────────────────────┼─────────────────────────────────────────┘ │  │
│                                    │ Ring Buffer                               │  │
│  ┌─────────────────────────────────▼─────────────────────────────────────────┐ │  │
│  │                           User Space                                       │ │  │
│  │                                                                            │ │  │
│  │  ┌──────────────────────────────────────────────────────────────────────┐ │ │  │
│  │  │                     CNDI-Final Agent (Go)                             │ │ │  │
│  │  │                                                                        │ │ │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────┐  │ │ │  │
│  │  │  │   eBPF Loader   │  │  PFCP Sniffer   │  │  Metrics Collector   │  │ │ │  │
│  │  │  │  (cilium/ebpf)  │  │  (gopacket)     │  │  (Prometheus)        │  │ │ │  │
│  │  │  │                 │  │                 │  │                      │  │ │ │  │
│  │  │  │ - Load BPF prog │  │ - Listen :8805  │  │ - upf_packets_total  │  │ │ │  │
│  │  │  │ - Attach kprobe │  │ - Parse PFCP    │  │ - upf_bytes_total    │  │ │ │  │
│  │  │  │ - Read maps     │  │ - Extract SEID  │  │ - upf_drops_total    │  │ │ │  │
│  │  │  │ - Poll ringbuf  │  │ - Map TEID↔UE   │  │ - Export :9100       │  │ │ │  │
│  │  │  └────────┬────────┘  └────────┬────────┘  └───────────┬──────────┘  │ │ │  │
│  │  │           │                    │                       │             │ │ │  │
│  │  │           └────────────────────┴───────────────────────┘             │ │ │  │
│  │  │                                │                                      │ │ │  │
│  │  └────────────────────────────────┼──────────────────────────────────────┘ │ │  │
│  │                                   │ HTTP/WebSocket                         │ │  │
│  │  ┌────────────────────────────────▼──────────────────────────────────────┐ │ │  │
│  │  │                     Backend API Server (Go/Gin)                       │ │ │  │
│  │  │                                                                        │ │ │  │
│  │  │  REST Endpoints:                    WebSocket Endpoints:               │ │ │  │
│  │  │  - GET  /api/v1/health              - /ws/metrics  (即時指標串流)     │ │ │  │
│  │  │  - GET  /api/v1/metrics/traffic     - /ws/events   (即時事件串流)     │ │ │  │
│  │  │  - GET  /api/v1/metrics/drops                                          │ │ │  │
│  │  │  - GET  /api/v1/sessions            Port: 8080                         │ │ │  │
│  │  │  - POST /api/v1/fault/inject                                           │ │ │  │
│  │  └────────────────────────────────┬──────────────────────────────────────┘ │ │  │
│  │                                   │                                        │ │  │
│  └───────────────────────────────────┼────────────────────────────────────────┘ │  │
│                                      │                                          │  │
│  ┌───────────────────────────────────┼────────────────────────────────────────┐ │  │
│  │             Docker Compose Observability Stack                              │ │  │
│  │                                   │                                         │ │  │
│  │  ┌──────────────────┐    ┌────────▼─────────┐    ┌──────────────────────┐  │ │  │
│  │  │   Prometheus     │◄───│ OpenTelemetry    │    │      Redis           │  │ │  │
│  │  │     :9090        │    │   Collector      │    │     :6379            │  │ │  │
│  │  │                  │    │     :4317        │    │  (Session Cache)     │  │ │  │
│  │  │ - Scrape /metrics│    │ - OTLP Receiver  │    │                      │  │ │  │
│  │  │ - Store TSDB     │    │ - Export to Prom │    │                      │  │ │  │
│  │  └──────────────────┘    └──────────────────┘    └──────────────────────┘  │ │  │
│  └─────────────────────────────────────────────────────────────────────────────┘ │  │
│                                      │                                           │  │
│  ┌───────────────────────────────────▼─────────────────────────────────────────┐ │  │
│  │                     Web Frontend (React + TypeScript + Vite)                 │ │  │
│  │                                   Port: 3000                                 │ │  │
│  │  ┌───────────────────────────────────────────────────────────────────────┐  │ │  │
│  │  │                          Dashboard.tsx                                 │  │ │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │  │ │  │
│  │  │  │ TrafficChart    │  │ DropAlertPanel  │  │   SessionTable      │   │  │ │  │
│  │  │  │ (Recharts)      │  │ (即時告警)      │  │   (SEID/TEID)       │   │  │ │  │
│  │  │  │                 │  │                 │  │                     │   │  │ │  │
│  │  │  │ - UL/DL 趨勢圖 │  │ - Drop 事件列表│  │ - Session 對應表   │   │  │ │  │
│  │  │  │ - 即時更新     │  │ - 原因分類     │  │ - UE IP 顯示       │   │  │ │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘   │  │ │  │
│  │  │                                                                        │  │ │  │
│  │  │  ┌─────────────────────────────────────────────────────────────────┐  │  │ │  │
│  │  │  │                       Topology.tsx                               │  │  │ │  │
│  │  │  │            [UE] ─── [gNB] ═══N3═══ [UPF] ═══N6═══ [DN]          │  │  │ │  │
│  │  │  └─────────────────────────────────────────────────────────────────┘  │  │ │  │
│  │  └───────────────────────────────────────────────────────────────────────┘  │ │  │
│  └─────────────────────────────────────────────────────────────────────────────┘ │  │
└──────────────────────────────────────────────────────────────────────────────────┘  │
                                         │                                            │
                                         │ N3 Interface (GTP-U, UDP 2152)             │
                                         ▼                                            │
┌──────────────────────────────────────────────────────────────────────────────────┐  │
│                              VM 2: UERANSIM                                       │  │
│  ┌──────────────────────────┐    ┌──────────────────────────┐                    │  │
│  │        nr-gnb            │◄──►│         nr-ue            │                    │  │
│  │    (gNodeB Simulator)    │    │     (UE Simulator)       │                    │  │
│  │                          │    │                          │                    │  │
│  │    - N2 Interface (AMF)  │    │    - PDU Session         │                    │  │
│  │    - N3 Interface (UPF)  │    │    - Data Traffic        │                    │  │
│  └──────────────────────────┘    └──────────────────────────┘                    │  │
└──────────────────────────────────────────────────────────────────────────────────┘  │
```

### 資料流詳解

#### 1. Uplink 封包流程 (UE → DN)
```
UE 發送資料
    │
    ▼
[UERANSIM gNB] ─── N3 (GTP-U encapsulated) ───► [gtp5g kernel module]
                                                        │
                                                        ▼
                                               gtp5g_encap_recv()
                                                        │
                                            ┌───────────┴───────────┐
                                            │   eBPF kprobe 觸發    │
                                            │   記錄: timestamp,    │
                                            │   skb_len, TEID,      │
                                            │   src_ip, dst_ip      │
                                            └───────────┬───────────┘
                                                        │
                                                        ▼
                                               解封裝 GTP-U Header
                                                        │
                                                        ▼
                                               [UPF 處理/轉發] ───► [DN]
```

#### 2. Downlink 封包流程 (DN → UE)
```
DN 回應資料
    │
    ▼
[UPF 接收] ───► gtp5g_dev_xmit()
                       │
           ┌───────────┴───────────┐
           │   eBPF kprobe 觸發    │
           │   記錄: timestamp,    │
           │   skb_len, ue_ip      │
           └───────────┬───────────┘
                       │
                       ▼
              封裝 GTP-U Header
                       │
                       ▼
              [N3 Interface] ───► [gNB] ───► [UE]
```

#### 3. 封包丟棄偵測流程
```
封包處理過程中發生錯誤
    │
    ▼
內核呼叫 kfree_skb()
    │
    ▼
┌─────────────────────────────────┐
│  eBPF tracepoint/skb/kfree_skb  │
│  捕獲丟包事件                   │
│  記錄: drop_reason, skb_len,    │
│        location                 │
└─────────────────┬───────────────┘
                  │
                  ▼
         寫入 Ring Buffer
                  │
                  ▼
    ┌─────────────────────────────┐
    │  User-space Agent 讀取      │
    │  解析 drop_reason:          │
    │  - NO_PDR_MATCH            │
    │  - INVALID_TEID            │
    │  - QOS_DROP                │
    │  - KERNEL_DROP             │
    └─────────────────────────────┘
```

### 元件說明

| 元件 | 技術 | 功能 | 連接埠 |
|------|------|------|--------|
| **eBPF Agent** | Go + cilium/ebpf | 載入 eBPF 程式、讀取 kernel maps、匯出 metrics | 9100 (Prometheus) |
| **PFCP Sniffer** | Go + gopacket | 監聽 PFCP 訊息、解析 Session、建立 TEID 對應 | 8805 (監聽) |
| **API Server** | Go + Gin | REST API + WebSocket 即時串流 | 8080 |
| **Web Frontend** | React + TypeScript + Vite | 可視化儀表板 | 3000 (dev) |
| **Prometheus** | Docker | 時序資料庫、指標儲存 | 9090 |
| **Otel Collector** | Docker | OpenTelemetry 收集器 | 4317 |

---

## 環境需求

### 硬體需求

| 項目 | 最低需求 | 建議配置 |
|------|----------|----------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| 硬碟 | 20 GB | 50+ GB SSD |
| 網路 | 1 Gbps | 1 Gbps |

### 軟體需求

| 軟體 | 版本 | 說明 |
|------|------|------|
| **作業系統** | Ubuntu 25.04 (Plucky Puffin) | 需要 Kernel 6.14+ 支援 BTF |
| **Linux Kernel** | 6.14.0-36-generic | 需啟用 CONFIG_BPF, CONFIG_BTF |
| **Go** | 1.21+ | 編譯 Agent 與 API Server |
| **Node.js** | 18+ LTS | 編譯前端 |
| **Docker** | 24+ | 運行 Observability Stack |
| **Docker Compose** | v2+ | 容器編排 |
| **Clang/LLVM** | 14+ | 編譯 eBPF C 程式 |
| **libbpf** | 1.0+ | eBPF 函式庫 |
| **bpftool** | Latest | 生成 vmlinux.h |

### free5GC 環境

| 元件 | 版本 | 狀態 |
|------|------|------|
| **free5GC** | v4.1.0 | Host 模式運行 |
| **gtp5g** | Latest | 需為當前 kernel 編譯 |
| **UERANSIM** | Latest | 於 VM2 運行 |

### 驗證 eBPF 支援

執行以下指令確認系統支援 eBPF：

```bash
# 檢查 BTF 支援
ls -la /sys/kernel/btf/vmlinux

# 檢查 gtp5g 模組已載入
lsmod | grep gtp5g

# 確認可 hook 的符號存在
sudo cat /proc/kallsyms | grep gtp5g_encap_recv
sudo cat /proc/kallsyms | grep gtp5g_dev_xmit
```

預期輸出：
```
ffffffffc11a7aa0 t gtp5g_encap_recv     [gtp5g]
ffffffffc11a6420 t gtp5g_dev_xmit       [gtp5g]
```

---

## 使用步驟

### Step 1: 環境準備

#### 1.1 安裝系統依賴

```bash
# 更新套件列表
sudo apt-get update

# 安裝編譯工具與 eBPF 開發依賴
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    libelf-dev \
    libpcap-dev \
    pkg-config \
    bpftool \
    bpftrace
```

#### 1.2 安裝 Go

```bash
# 下載 Go 1.21+
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# 解壓縮到 /usr/local
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 設定環境變數 (加入 ~/.bashrc)
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# 驗證安裝
go version
# 輸出: go version go1.21.5 linux/amd64
```

#### 1.3 安裝 Node.js

```bash
# 使用 NodeSource 安裝 Node.js 18 LTS
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 驗證安裝
node -v  # v18.x.x
npm -v   # 9.x.x
```

#### 1.4 安裝 Docker

```bash
# 使用官方腳本安裝 Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# 將當前使用者加入 docker 群組
sudo usermod -aG docker $USER

# 重新登入或執行
newgrp docker

# 驗證安裝
docker --version
docker compose version
```

#### 1.5 確認 gtp5g 模組

```bash
# 如果 gtp5g 未載入，需要先編譯並載入
cd ~/gtp5g

# 為當前 kernel 重新編譯
make clean
make

# 載入模組
sudo insmod gtp5g.ko

# 驗證載入成功
lsmod | grep gtp5g
# 輸出: gtp5g    159744  1
```

---

### Step 2: 專案建置

#### 2.1 取得專案

```bash
cd ~
# 若尚未 clone 專案
git clone https://github.com/solar224/CNDI-Final.git
cd CNDI-Final

# 若已有專案，確認在正確目錄
cd ~/CNDI-Final
```

#### 2.2 執行環境設定腳本

```bash
# 執行一鍵設定腳本 (可選，會自動安裝所有依賴)
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh
```

#### 2.3 生成 vmlinux.h

```bash
# 從運行中的 kernel 生成 BTF 類型定義
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
```

#### 2.4 編譯 eBPF 程式

```bash
# 編譯 eBPF C 程式為 .o 檔
make ebpf

# 輸出:
# clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c internal/ebpf/bpf/upf_monitor.bpf.c -o internal/ebpf/bpf/upf_monitor.bpf.o
```

#### 2.5 編譯 Go 程式

```bash
# 下載 Go 依賴
make deps

# 編譯所有 Go binary
make build

# 輸出:
# go build -o bin/agent ./cmd/agent
# go build -o bin/api-server ./cmd/api-server

# 確認編譯結果
ls -la bin/
# -rwxrwxr-x 1 user user 16M Nov 29 10:00 agent
# -rwxrwxr-x 1 user user 13M Nov 29 10:00 api-server
```

#### 2.6 安裝前端依賴

```bash
cd web
npm install
cd ..
```

---

### Step 3: 啟動 Observability Stack

#### 3.1 啟動 Docker Compose

```bash
# 啟動 Prometheus + Otel Collector + Redis
docker compose -f deployments/docker-compose.yaml up -d

# 檢查容器狀態
docker compose -f deployments/docker-compose.yaml ps

# 預期輸出:
# NAME                COMMAND                  SERVICE             STATUS
# prometheus          "/bin/prometheus..."     prometheus          running
# otel-collector      "/otelcol-contrib..."    otel-collector      running
# redis               "docker-entrypoint..."   redis               running
```

#### 3.2 驗證服務

```bash
# 檢查 Prometheus
curl http://localhost:9090/-/healthy
# 輸出: Prometheus Server is Healthy.

# 檢查 Otel Collector health
curl http://localhost:13133
# 輸出: {"status":"Server available","upSince":"...","uptime":"..."}
```

---

### Step 4: 啟動 CNDI-Final Platform

#### 4.1 啟動 eBPF Agent (需要 root 權限)

```bash
# 開啟新的終端機
cd ~/CNDI-Final

# 以 root 權限執行 Agent
sudo ./bin/agent

# 預期輸出:
# ============================================================
#     CNDI-Final: UPF Data Plane Observability Agent
# ============================================================
# [OK] eBPF programs loaded successfully
# [OK] Event loop started
# [INFO] Prometheus metrics server listening on :9100
# [INFO] Agent is running. Press Ctrl+C to stop.
```

#### 4.2 驗證 Agent 運作

```bash
# 檢查 health endpoint
curl http://localhost:9100/health
# 輸出: OK

# 檢查 Prometheus metrics
curl http://localhost:9100/metrics | grep upf_
# 輸出:
# upf_packets_total{direction="uplink"} 0
# upf_packets_total{direction="downlink"} 0
# upf_bytes_total{direction="uplink"} 0
# upf_bytes_total{direction="downlink"} 0
# upf_packet_drops_total{reason="KERNEL_DROP"} 0
```

#### 4.3 啟動 API Server

```bash
# 開啟另一個終端機
cd ~/CNDI-Final

# 啟動 API Server
./bin/api-server

# 預期輸出:
# ============================================================
#     CNDI-Final: Backend API Server
# ============================================================
# [INFO] Starting API server on :8080
```

#### 4.4 驗證 API Server

```bash
# 檢查 health endpoint
curl http://localhost:8080/api/v1/health
# 輸出: {"status":"ok","timestamp":"2025-11-29T10:00:00Z","version":"1.0.0"}

# 取得流量統計
curl http://localhost:8080/api/v1/metrics/traffic
# 輸出: {"uplink":{"packets":0,"bytes":0},"downlink":{"packets":0,"bytes":0}}
```

#### 4.5 啟動 Web Frontend

```bash
# 開啟另一個終端機
cd ~/CNDI-Final/web

# 啟動開發伺服器
npm run dev

# 預期輸出:
#   VITE v5.4.x  ready in xxx ms
#   ➨  Local:   http://localhost:3000/
#   ➨  Network: use --host to expose
```

#### 4.6 開啟瀏覽器

在瀏覽器中開啟 http://localhost:3000，即可看到 CNDI-Final 監控儀表板。

> **注意**: Vite 開發服務器配置在 `web/vite.config.ts` 中，預設端口為 3000。

---

### Step 5: 產生測試流量

#### 5.1 確認 free5GC 運行中

```bash
# 檢查 free5GC 程序
ps aux | grep -E "(amf|smf|upf|nrf)" | grep -v grep

# 檢查 UPF 是否正常
curl http://localhost:8000  # NRF API
```

#### 5.2 使用 UERANSIM 產生流量

在 VM2 (UERANSIM) 上執行：

```bash
# 啟動 gNB
cd ~/UERANSIM
./build/nr-gnb -c config/free5gc-gnb.yaml &

# 啟動 UE
./build/nr-ue -c config/free5gc-ue.yaml &

# 等待 PDU Session 建立成功
sleep 5

# 使用 UE 的 tunnel interface 發送 ping
ping -I uesimtun0 8.8.8.8

# 或產生更大流量
iperf3 -c 8.8.8.8 -B 10.60.0.1 -t 60
```

#### 5.3 觀察監控數據

回到 Web Frontend (http://localhost:3000)，應該可以看到：

- **Traffic Chart**: Uplink/Downlink 流量圖表開始有數據
- **Stats Cards**: 封包數與位元組數持續增加
- **Session Table**: 顯示已建立的 PDU Session

---

### Step 6: 故障注入測試 (可選)

#### 6.1 透過 API 觸發故障注入

```bash
# 發送故障注入請求
curl -X POST http://localhost:8080/api/v1/fault/inject \
    -H "Content-Type: application/json" \
    -d '{"type":"invalid_teid","target":"upf","count":10}'
```

#### 6.2 觀察丟包告警

回到 Web Frontend，在 **Drop Alert Panel** 應該會看到新的丟包事件。

---

### 常用操作指令

```bash
# 一鍵啟動所有服務 (建議在不同終端機分別執行)
# 終端機 1: 啟動 Docker Stack
make compose-up

# 終端機 2: 啟動 Agent (需要 root)
sudo ./bin/agent

# 終端機 3: 啟動 API Server
./bin/api-server

# 終端機 4: 啟動 Web Frontend
cd web && npm run dev

# 停止所有服務
pkill -f agent
pkill -f api-server
make compose-down

# 查看 Agent 即時日誌
sudo ./bin/agent 2>&1 | tee agent.log

# 清理並重新編譯
make clean
make all
```

---

## 結論

CNDI-Final 提供了一個完整的 5G UPF 數據平面可觀測解決方案，其核心價值在於：

### 技術創新

1. **非侵入式監控**: 利用 Linux eBPF kprobe 技術，直接 hook `gtp5g` 內核模組的關鍵函數，完全不需要修改 free5GC 或 gtp5g 的任何原始碼，實現真正的零侵入監控。

2. **高效能低開銷**: 採用 Per-CPU eBPF Maps 避免鎖競爭，使用 Ring Buffer 非同步傳遞事件，將監控對 UPF 效能的影響降到最低。

3. **Control/Data Plane 關聯**: 透過 PFCP Sniffer 監聽 SMF-UPF 之間的 N4 介面，建立 SEID (Session Endpoint Identifier) 與 TEID (Tunnel Endpoint Identifier) 的對應關係，使封包層級的監控數據能夠關聯到具體的 PDU Session 與 UE。

### 實用價值

1. **即時可視化**: 自建的 React 前端儀表板提供即時流量監控、丟包告警、Session 狀態等關鍵資訊的可視化呈現，不依賴外部工具如 Grafana。

2. **問題快速定位**: 當發生封包丟失時，可以立即看到丟包原因（NO_PDR_MATCH、INVALID_TEID、QOS_DROP 等），大幅縮短問題排查時間。

3. **驗證與測試**: 內建的故障注入功能可以主動觸發各種異常場景，驗證監控平台的有效性，也可用於 Chaos Engineering 測試。

### 未來展望

- 支援更多 eBPF hook 點（如 QoS 處理、PDR/FAR 匹配等）
- 整合 Distributed Tracing（Jaeger/Tempo）
- 支援 Kubernetes 部署模式
- 增加 AI/ML 異常偵測能力

本專案展示了 eBPF 技術在 5G 核心網可觀測性領域的強大潛力，為電信網路的監控與維運提供了新的思路。
