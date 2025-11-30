# 5G-DPOP: 5G UPF Data Plane Observability Platform

> **Version**: 1.0.0  
> **Date**: 2025-11-29  
> **Author**: 5G-DPOP Team  

---

## 1. Executive Summary

本專案旨在建立一個**非侵入式 (Non-Invasive)** 的 5G 核心網數據平面可觀測平台，專注於監測 **free5GC UPF (User Plane Function)** 的即時流量、效能指標與異常事件（特別是封包丟失）。

### 核心技術亮點
- **eBPF Kprobe**: Hook `gtp5g` 內核模組，零修改原始碼
- **Control/Data Plane 關聯**: PFCP 監聽 + TEID Mapping
- **自建觀測平台**: 不依賴 Grafana，完全自主開發前端
- **故障注入驗證**: Chaos Engineering 驗證監控有效性

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VM 1: free5GC (Ubuntu 25.04)                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                        Host Network Stack                                │ │
│  │  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐          │ │
│  │  │   free5GC    │      │    gtp5g     │      │   upfgtp0    │          │ │
│  │  │  NFs (Host)  │◄────►│   Kernel     │◄────►│  Interface   │          │ │
│  │  │              │ N4   │   Module     │ N3   │              │          │ │
│  │  │ AMF,SMF,UPF  │PFCP  │              │GTP-U │              │          │ │
│  │  └──────────────┘      └──────┬───────┘      └──────────────┘          │ │
│  │                               │                                         │ │
│  │                        ┌──────┴───────┐                                 │ │
│  │                        │  eBPF Probes │ (kprobe)                        │ │
│  │                        │  ┌─────────┐ │                                 │ │
│  │                        │  │RingBuf  │ │                                 │ │
│  │                        └──┴────┬────┴─┘                                 │ │
│  └────────────────────────────────┼────────────────────────────────────────┘ │
│                                   │                                          │
│  ┌────────────────────────────────┼────────────────────────────────────────┐ │
│  │                    5G-DPOP Platform                                      │ │
│  │  ┌──────────────────┐   ┌──────┴───────┐   ┌──────────────────┐        │ │
│  │  │   PFCP Sniffer   │   │  eBPF Agent  │   │   Backend API    │        │ │
│  │  │  (Port 8805)     │──►│  (Go/libbpf) │──►│   (Go/Gin)       │        │ │
│  │  │                  │   │              │   │                  │        │ │
│  │  │ SEID↔TEID Map    │   │ Metrics Gen  │   │ REST Endpoints   │        │ │
│  │  └──────────────────┘   └──────────────┘   └────────┬─────────┘        │ │
│  │                                                      │                  │ │
│  └──────────────────────────────────────────────────────┼──────────────────┘ │
│                                                         │                    │
│  ┌──────────────────────────────────────────────────────┼──────────────────┐ │
│  │                   Docker Compose Stack                │                  │ │
│  │  ┌──────────────┐   ┌──────────────┐   ┌─────────────▼────────────┐     │ │
│  │  │  Prometheus  │◄──│Otel Collector│   │     Web Frontend        │     │ │
│  │  │   :9090      │   │    :4317     │   │   (React/Vue) :3000     │     │ │
│  │  └──────────────┘   └──────────────┘   └──────────────────────────┘     │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ N3 (GTP-U)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VM 2: UERANSIM                                     │
│  ┌──────────────┐      ┌──────────────┐                                     │
│  │     gNB      │◄────►│      UE      │                                     │
│  │              │      │              │                                     │
│  └──────────────┘      └──────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Environment Specifications

| Component | Version | Status |
|-----------|---------|--------|
| **OS** | Ubuntu 25.04 (Plucky Puffin) | Verified |
| **Kernel** | 6.14.0-36-generic | Verified |
| **free5GC** | v4.1.0 | Running |
| **gtp5g** | Latest (compiled for kernel 6.14) | Loaded |
| **UERANSIM** | Latest | Running on VM2 |
| **Go** | 1.21+ | Required |
| **Node.js** | 18+ LTS | Required |
| **Docker** | 24+ | Required |

### Verified eBPF Hook Points (from `/proc/kallsyms`)

```
ffffffffc11a6420 t gtp5g_dev_xmit       [gtp5g]  # Downlink entry
ffffffffc11a7aa0 t gtp5g_encap_recv     [gtp5g]  # Uplink entry
```

---

## 4. Project Objectives

### 4.1 Primary Goals

| ID | Objective | Priority |
|----|-----------|----------|
| O1 | 透過 eBPF 即時監測 UPF 的 GTP-U 流量 (Uplink/Downlink throughput) | P0 |
| O2 | 偵測並記錄封包丟失事件，包含丟包原因 | P0 |
| O3 | 建立 PFCP Session (SEID) 與 GTP Tunnel (TEID) 的關聯表 | P1 |
| O4 | 自建前端儀表板即時呈現監控數據 | P1 |
| O5 | 實作故障注入腳本驗證平台有效性 | P2 |

### 4.2 Non-Goals (Scope Exclusion)

- 修改 free5GC 或 gtp5g 原始碼
- 完整的 Distributed Tracing (Jaeger/Tempo)
- Kubernetes 部署 free5GC (保持 Host 模式)
- 商業級別的高可用架構

---

## 5. Technical Design

### 5.1 eBPF Agent Design

#### Hook Points & Data Collection

| Hook Point | Type | Purpose | Data Collected |
|------------|------|---------|----------------|
| `gtp5g_encap_recv` | kprobe | Uplink 封包入口 | timestamp, skb_len, TEID, src_ip |
| `gtp5g_dev_xmit` | kprobe | Downlink 封包入口 | timestamp, skb_len, ue_ip |
| `kfree_skb` | tracepoint | 封包丟棄事件 | drop_reason, location |
| `pdr_find_by_gtp1u` | kretprobe | PDR 查找失敗 | TEID (when return NULL) |

#### eBPF Maps

```c
// 流量統計 (Per-CPU 避免鎖競爭)
struct bpf_map_def SEC("maps") traffic_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),      // 0=uplink, 1=downlink
    .value_size = sizeof(struct traffic_counter),
    .max_entries = 2,
};

// 丟包事件 (Ring Buffer 傳送至 User-space)
struct bpf_map_def SEC("maps") drop_events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,    // 256KB
};

// TEID → Session 關聯 (從 user-space 寫入)
struct bpf_map_def SEC("maps") teid_session_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),      // TEID
    .value_size = sizeof(struct session_info),
    .max_entries = 1024,
};
```

### 5.2 PFCP Sniffer Design

```
┌─────────────────────────────────────────────────────────────┐
│                     PFCP Sniffer (gopacket)                 │
│  ┌───────────────────┐    ┌───────────────────────────────┐ │
│  │  Packet Capture   │    │    Session State Machine      │ │
│  │  (localhost:8805) │───►│  ┌─────────────────────────┐  │ │
│  │                   │    │  │ Session Establishment   │  │ │
│  └───────────────────┘    │  │ - Extract SEID          │  │ │
│                           │  │ - Extract F-TEID        │  │ │
│                           │  │ - Extract PDR/FAR IDs   │  │ │
│                           │  └─────────────────────────┘  │ │
│                           │              │                │ │
│                           │              ▼                │ │
│                           │  ┌─────────────────────────┐  │ │
│                           │  │   Correlation Store     │  │ │
│                           │  │   (In-Memory Map)       │  │ │
│                           │  │   SEID ↔ TEID ↔ UE_IP   │  │ │
│                           │  └─────────────────────────┘  │ │
│                           └───────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Metrics Definition

#### Prometheus Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `upf_packets_total` | Counter | direction, interface | 封包總數 |
| `upf_bytes_total` | Counter | direction, interface | 位元組總數 |
| `upf_packet_drops_total` | Counter | reason, teid | 丟包總數 |
| `upf_active_sessions` | Gauge | dnn | 活躍 PDU Session 數 |
| `upf_latency_histogram` | Histogram | direction | 處理延遲分佈 |

#### Drop Reasons (Enumeration)

| Code | Reason | Description |
|------|--------|-------------|
| 0 | `NO_PDR_MATCH` | 找不到匹配的 PDR |
| 1 | `INVALID_TEID` | TEID 無效或已過期 |
| 2 | `QOS_DROP` | QoS 限速丟棄 (Red packet) |
| 3 | `KERNEL_DROP` | 一般內核丟包 |

---

## 6. Project Structure

```
5G-DPOP/
├── README.md                       # 專案說明、快速開始
├── Makefile                        # 統一建置指令
├── go.mod                          # Go module definition
├── go.sum
│
├── docs/                           # 文件
│   ├── PROJECT_SPEC.md             # 本文件
│   ├── ARCHITECTURE.md             # 詳細架構說明
│   └── API.md                      # REST API 文件
│
├── cmd/                            # 主程式入口
│   ├── agent/                      # eBPF Observability Agent
│   │   └── main.go
│   ├── api-server/                 # Backend REST API
│   │   └── main.go
│   └── fault-injector/             # 故障注入工具
│       └── main.go
│
├── internal/                       # 內部程式庫 (不對外)
│   ├── ebpf/                       # eBPF 相關
│   │   ├── bpf/                    # eBPF C 程式碼
│   │   │   ├── upf_monitor.bpf.c   # 主要 eBPF 程式
│   │   │   └── vmlinux.h           # 內核類型定義
│   │   ├── loader.go               # eBPF 載入器
│   │   └── types.go                # 共用類型定義
│   │
│   ├── pfcp/                       # PFCP 解析
│   │   ├── sniffer.go              # Packet Sniffer
│   │   ├── parser.go               # PFCP Message Parser
│   │   └── correlation.go          # Session Correlation
│   │
│   ├── metrics/                    # Metrics 處理
│   │   ├── collector.go            # Prometheus Collector
│   │   └── exporter.go             # OTLP Exporter
│   │
│   └── api/                        # REST API Handlers
│       ├── handlers.go
│       └── routes.go
│
├── web/                            # 前端專案
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── Dashboard.tsx       # 主儀表板
│   │   │   ├── TrafficChart.tsx    # 流量圖表
│   │   │   ├── DropAlertPanel.tsx  # 丟包告警
│   │   │   ├── SessionTable.tsx    # Session 列表
│   │   │   └── Topology.tsx        # 拓樸圖
│   │   ├── hooks/
│   │   │   └── useMetrics.ts       # 資料 Hook
│   │   └── services/
│   │       └── api.ts              # API Client
│   └── public/
│
├── deployments/                    # 部署設定
│   ├── docker-compose.yaml         # Observability Stack
│   └── otel-collector-config.yaml  # Otel Collector 設定
│
├── scripts/                        # 輔助腳本
│   ├── setup_env.sh                # 環境安裝
│   ├── build_ebpf.sh               # 編譯 eBPF
│   └── run_experiment.sh           # 執行實驗
│
└── test/                           # 測試
    ├── integration/
    └── e2e/
```

---

## 7. Implementation Phases

### Phase 1: Infrastructure Setup (Week 1)
**目標**: 建立開發環境，驗證 eBPF 可行性

| Task | Description | Deliverable |
|------|-------------|-------------|
| 1.1 | 初始化 Go 專案結構 | `go.mod`, 目錄結構 |
| 1.2 | 安裝 eBPF 開發依賴 (libbpf, clang, bpftool) | `setup_env.sh` |
| 1.3 | 撰寫最小 eBPF 程式 hook `gtp5g_encap_recv` | `upf_monitor.bpf.c` v0.1 |
| 1.4 | 驗證能從 user-space 讀取 eBPF map | `loader.go` |
| 1.5 | 部署 Docker Compose (Prometheus + Otel) | `docker-compose.yaml` |

**驗收標準**: 執行 UERANSIM ping 測試時，能在終端看到封包計數增加

### Phase 2: Core eBPF Development (Week 2-3)
**目標**: 完成完整的 eBPF 監控邏輯

| Task | Description | Deliverable |
|------|-------------|-------------|
| 2.1 | 實作 Uplink/Downlink 流量統計 | Traffic counters |
| 2.2 | 實作 `kfree_skb` tracepoint 捕捉丟包 | Drop events |
| 2.3 | 實作 Ring Buffer 傳送事件至 user-space | Event streaming |
| 2.4 | 實作 TEID 提取邏輯 | GTP header parsing |
| 2.5 | 整合 Prometheus metrics export | `/metrics` endpoint |

**驗收標準**: Prometheus 能抓取到 UPF 流量 metrics

### Phase 3: PFCP Correlation (Week 3-4)
**目標**: 實現 Control/Data Plane 關聯

| Task | Description | Deliverable |
|------|-------------|-------------|
| 3.1 | 實作 PFCP packet sniffer (gopacket) | `sniffer.go` |
| 3.2 | 解析 Session Establishment Request | `parser.go` |
| 3.3 | 建立 SEID ↔ TEID ↔ UE_IP mapping | `correlation.go` |
| 3.4 | 將 mapping 注入 eBPF map | Integration |
| 3.5 | Enrich drop events with session info | Enhanced events |

**驗收標準**: 能顯示 "TEID 0x12345 belongs to Session SEID=xxx, UE_IP=10.60.0.1"

### Phase 4: Frontend Development (Week 4-5)
**目標**: 建立自訂監控儀表板

| Task | Description | Deliverable |
|------|-------------|-------------|
| 4.1 | 初始化 React/Vite 專案 | `web/` scaffold |
| 4.2 | 實作 Backend REST API | `api-server` |
| 4.3 | Dashboard 主頁面 (流量總覽) | `Dashboard.tsx` |
| 4.4 | 即時流量圖表 (WebSocket) | `TrafficChart.tsx` |
| 4.5 | 丟包告警面板 (紅色閃爍) | `DropAlertPanel.tsx` |
| 4.6 | Session 關聯表格 | `SessionTable.tsx` |
| 4.7 | 簡易拓樸圖 | `Topology.tsx` |

**驗收標準**: 瀏覽器訪問前端能看到即時更新的流量圖與告警

### Phase 5: Fault Injection & Validation (Week 5-6)
**目標**: 驗證平台能正確偵測異常

| Task | Description | Deliverable |
|------|-------------|-------------|
| 5.1 | 實作故障注入腳本 (Scapy) | `fault-injector` |
| 5.2 | 情境 1: 發送 Invalid TEID 封包 | Test script |
| 5.3 | 情境 2: 刪除 PDR 後持續發送流量 | Test script |
| 5.4 | 端到端測試 | E2E test suite |
| 5.5 | 撰寫實驗報告與分析 | Documentation |

**驗收標準**: 執行故障注入後，前端在 <5 秒內顯示紅色告警

---

## 8. API Specification

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | 健康檢查 |
| GET | `/api/v1/metrics/traffic` | 取得流量統計 |
| GET | `/api/v1/metrics/drops` | 取得丟包統計 |
| GET | `/api/v1/sessions` | 取得活躍 Session 列表 |
| GET | `/api/v1/sessions/:seid` | 取得特定 Session 詳情 |
| GET | `/api/v1/events` | 取得最近事件 (SSE 串流) |
| POST | `/api/v1/fault/inject` | 觸發故障注入 |

### WebSocket Endpoints

| Path | Description |
|------|-------------|
| `/ws/metrics` | 即時 metrics 串流 (1s interval) |
| `/ws/events` | 即時事件串流 |

---

## 9. Dashboard Design Mockup

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  5G-DPOP: UPF Data Plane Observability                       [Status: OK]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─── Traffic Overview ─────────────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │   Uplink:   ████████████░░░░░  125.4 Mbps                           │   │
│  │   Downlink: ███████████████░░  189.2 Mbps                           │   │
│  │                                                                       │   │
│  │   [========== Live Traffic Chart (Last 5 min) ==========]            │   │
│  │   300 ┤                          ╭─╮                                  │   │
│  │   200 ┤         ╭────────────────╯ ╰──────                           │   │
│  │   100 ┤    ╭────╯                                                    │   │
│  │     0 ┼────┴────────────────────────────────────────────             │   │
│  │        14:00  14:01  14:02  14:03  14:04  14:05                       │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── Drop Alert Panel ──────────────────────┐  ┌─── Active Sessions ───┐   │
│  │                                            │  │                       │   │
│   │ Drop Rate: 0.02%                      │  │  Total: 3 sessions    │   │
│  │                                            │  │                       │   │
│  │   Recent Drops:                            │  │  SEID     UE IP       │   │
│  │   ┌──────────────────────────────────────┐ │  │  ──────────────────── │   │
│  │   │ Time       TEID      Reason          │ │  │  0x001   10.60.0.1   │   │
│  │   │ 14:05:23   0x12345   NO_PDR_MATCH   │ │  │  0x002   10.60.0.2   │   │
│  │   │ 14:05:21   0x12346   INVALID_TEID   │ │  │  0x003   10.60.0.3   │   │
│  │   └──────────────────────────────────────┘ │  │                       │   │
│  └────────────────────────────────────────────┘  └───────────────────────┘   │
│                                                                             │
│  ┌─── Network Topology ─────────────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │      [UE] ──── [gNB] ════N3════ [UPF] ════N6════ [DN]               │   │
│  │       *         *               *                *                │   │
│  │                                                                       │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Risk Assessment & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| gtp5g 函數被 inline 無法 hook | High | Low | 使用 XDP/TC 替代方案 |
| Kernel 6.14 eBPF 相容性問題 | High | Low | 測試驗證，回退到舊版 BPF helper |
| PFCP 解析不完整 | Medium | Medium | 優先處理 Session Establishment |
| 效能開銷過大影響 UPF | Medium | Low | 使用 Per-CPU maps, 採樣 |

---

## 11. Success Criteria

### Minimum Viable Product (MVP)
- eBPF Agent 能統計 Uplink/Downlink 封包數與位元組數
- 能偵測到至少一種類型的封包丟失
- 前端能即時顯示流量圖表
- 有一個可運作的故障注入測試情境

### Complete Deliverables
- 所有 5 種 eBPF hook 點都有實作
- PFCP 關聯能顯示 Session 詳情
- 前端包含流量圖、丟包告警、Session 表、拓樸圖
- 至少 2 種故障注入情境
- 完整的 README 與 API 文件

---

## 12. References

- [free5GC Official](https://free5gc.org/)
- [gtp5g GitHub](https://github.com/free5gc/gtp5g)
- [cilium/ebpf Go Library](https://github.com/cilium/ebpf)
- [3GPP TS 29.244 (PFCP)](https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/)
- [3GPP TS 29.281 (GTP-U)](https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/)
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)

---

## Appendix A: Key gtp5g Source Locations

| Function | File | Line (approx) |
|----------|------|---------------|
| `gtp5g_encap_recv` | `src/gtpu/encap.c` | ~150 |
| `gtp5g_dev_xmit` | `src/gtpu/dev.c` | ~100 |
| `gtp1u_udp_encap_recv` | `src/gtpu/encap.c` | ~200 |
| `pdr_find_by_gtp1u` | `src/pfcp/pdr.c` | ~80 |
| `gtp5g_fwd_skb_encap` | `src/gtpu/encap.c` | ~400 |

## Appendix B: Port Configuration

| Protocol | Port | Interface |
|----------|------|-----------|
| GTP-U | 2152/UDP | N3 (RAN ↔ UPF) |
| PFCP | 8805/UDP | N4 (SMF ↔ UPF) |
| SBI | 8000/TCP | Control Plane |
