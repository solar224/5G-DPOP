目前情況 (free5gc (ubuntu25@free5gc:~/free5gc) 及 UERANSIM ubuntu25@UERANSIM:~/UERANSIM-開源專案)
我自己在 github 建立了一個新的 Project (CNDI-Final (ubuntu25@free5gc:~/CNDI-Final)-目前是空的，只有一個 READ.md 檔案)
目前結構:
```
VM 1:
free5GC25
    ├──  ./free5gc
    └── ./CNDI-Final
VM 2:
UERANSIM
    └── ./UERANSIM
```
目前進度:
(
free5gc 更新到v4.1.0
ueransim 啟動成功，free5gc 啟動成功
確認ueransim 能夠通過 free5gc ping 到外網
目前能夠看到Uplink Traffic、Downlink Traffic、Live Traffic
)
以下是我目前的想法，請問你能提供詳細的實作分配及流程還有專案架構給我嗎?
觀測平台我希望能夠改成自己建一個前端網頁，用來顯示。

1. Project Objectives 
建立一個即時性可觀測性非侵入式平台 (./CNDI-Final)，用以深入監測與分析 free5gc 的核心
數據平面(Data Plane)。我們不僅關注正常數據流的傳輸，更將重點放在數據平面異常時的故
障檢測與分析，特別是針對 UPF (User Plane Function) 因 GTP-U 通道或 PFCP 規則不匹配
而導致的封包丟失 (Packet Drop) 情境。 

3. Key Research Areas 
3.1. UPF (User Plane Function) 效能分析： 
* 研究 free5gc UPF 的內部架構，分析其如何處理封包。 
* 監測 UPF 的關鍵效能指標 (KPIs)，如吞吐量、延遲、PDU Session 處理量等。 
3.2. GTP-U (GPRS Tunneling Protocol - User Plane) 流量可視化： 
* 追蹤 GTP-U 通道的建立、資料傳輸與終止的完整生命週期。 
* 分析通過 UPF 的 Uplink 與 Downlink 數據流量。 
3.3. PFCP (Packet Forwarding Control Protocol) 規則與數據關聯： 
* 分析 SMF 如何透過 PFCP 協定下發 PDR (Packet Detection Rules) 和 FAR (Forwarding 
Action Rules) 來控制 UPF。 
* 嘗試將數據平面的流量 (GTP-U) 與控制平面的指令(PFCP)進行關聯 (知道每一筆流量是
依據哪一條規則在轉發)。 
3.4. Data Plane Observability 平台建構： 
* 在 Kubernetes (k8s) 叢集上部署 free5gc 與 OpenTelemetry 生態系 (包含 Otel Collector, 
Prometheus, Grafana)。 
* 研究如何對 free5gc UPF 進行 Instrumentation，使其能導出 Otel 格式的 Metrics, Logs, 
和 Traces。(可能需要 eBPF 或修改 UPF source code)。 
3.5. Failure Scenario & Analysis： 
* 情境： 模擬 Data plan 找不到 gtp5g (drop package) 的狀況。 
* 模擬方式 1 (無匹配 PDR)： 建立一個 PDU Session，然後透過腳本修改 SMF 的行為，使
其不安裝 (或移除) 針對特定流量的 PDR/FAR。此時，該流量抵達 UPF 將會被 Drop。 
* 模擬方式 2 (無匹配 TEID)： 手動 (或使用 Scapy 等工具) 發送帶有隨機或已失效 TEID 的 
GTP-U 封包到 UPF。 
* 分析： 利用我們建構的 Otel 平台，即時偵測到這些 Packet Drop 事件，並定位出 Drop 的
原因(例如：Metrics 顯示 "Packet Drops - No PDR Match" 計數器上升)。 
4. Methodology & Tools 
* 5G 核心網： free5gc (v4.1.0) 
* RAN/UE 模擬器： UERANSIM 
* eBPF (使用 Cilium/Tetragon 或 BPFTrace) 來無侵入式地監控 UPF 的內核行為。 
5. Expected Deliverables 
* 一個完整部署在 Kubernetes 上、並整合了監控的 free5gc 運作環境。 
* 一組儀表板，用於實時視覺化 UPF 的效能、GTP-U 流量統計、以及 PFCP 規則的命中情況。 
* 如何利用平台快速偵測並診斷UPF 丟包問題的完整步驟與分析。

!! 我的實作想法:
```
「可觀測性（Observability）」與「故障注入（Chaos Engineering）」整合進去，並且滿足你「自建前端監控平台」的需求。
針對你的目標，我為你規劃了以下的 專案架構、GitHub 目錄結構 以及 詳細實作流程。
________________________________________
1. 系統高層架構設計 (System Architecture)
為了達成非侵入式監控且不破壞現有 free5GC 的穩定性，我們採用 Sidecar / Agent 模式 搭配 eBPF。
•	VM 1 (Core & Observability Node):
o	Infrastructure: Kubernetes (建議使用 MicroK8s，輕量且適合單節點開發) 或 Docker Compose。
o	5G Core (SUT - System Under Test): free5GC Control Plane (AMF, SMF, etc.) + UPF (需載入 gtp5g kernel module)。
o	Observability Agent (核心開發項目): 一個自行開發的 Go 程式，負責：
1.	透過 eBPF 掛載到 UPF 的網路介面或 Kernel Hook (gtp5g functions)，捕捉丟包 (kfree_skb) 與流量統計。
2.	透過 PCAP/Socket 監聽 N4 介面 (PFCP Port 8805)，建立 TEID 與 Session 的關聯表 (Control/Data Plane Correlation)。
3.	將數據轉換為 OTLP (OpenTelemetry Protocol) 格式發送。
o	Observability Backend:
	Otel Collector: 接收 Agent 數據，分流處理。
	Prometheus: 儲存 Metrics (吞吐量、丟包數)。
o	Frontend App (你的新需求):
	Backend API (Go/Python): 負責向 Prometheus 查詢數據，並提供 API 給前端。
	Web UI (React/Vue): 顯示自定義儀表板。
•	VM 2 (RAN Node):
o	UERANSIM (gnb + ue)。
________________________________________
2. GitHub 專案目錄結構建議 (CNDI-Final)
請依照 Golang 標準專案結構 (Standard Go Project Layout) 來組織你的 CNDI-Final：
Plaintext
CNDI-Final/
├── README.md                   # 專案說明、架構圖、啟動教學
├── Makefile                    # 自動化編譯、部署指令
├── cmd/                        # 主程式入口
│   ├── agent/                  # [核心] eBPF Observability Agent
│   │   └── main.go
│   ├── backend-api/            # [自建] 前端所需的後端 API Server
│   │   └── main.go
│   └── fault-injector/         # [核心] 故障模擬工具 (Go or Python script)
├── pkg/                        # 共用程式庫
│   ├── ebpf/                   # eBPF C code 與生成的 Go scaffold
│   │   ├── c/
│   │   │   └── upf_monitor.bpf.c  # eBPF C 程式碼 (監控 gtp5g)
│   │   └── loader.go           # 負責載入 eBPF 到 Kernel
│   ├── correlation/            # PFCP 關聯分析邏輯 (TEID Map)
│   └── otel/                   # OpenTelemetry Export 封裝
├── web/                        # [自建] 前端網頁專案 (Vue/React)
│   ├── src/
│   ├── public/
│   └── package.json
├── deployments/                # 部署設定檔
│   ├── k8s/                    # Kubernetes Manifests (Otel, Prom, App)
│   ├── docker-compose/         # (可選) 快速測試環境
│   └── otel-collector-config.yaml
└── scripts/                    # 輔助腳本
    ├── setup_env.sh            # 安裝 gtp5g, 環境依賴
    └── run_experiment_1.sh     # 自動化執行測試情境 1
________________________________________
3. 實作分配與流程 (Implementation Roadmap)
我將專案拆分為 五個階段 (Sprints)，確保循序漸進。
Phase 1: 基礎設施與環境容器化
目標： 將 observability stack 跑起來，並讓 free5GC 與其共存。
1.	K8s 部署： 在 VM1 安裝 microK8s。
2.	Otel Stack 部署： 撰寫 Helm Chart 或 Manifests 部署 Prometheus, Otel Collector 到 K8s。
3.	free5GC 策略： 為了簡化 eBPF 開發，建議 UPF 暫時保留在 Host Process (或者 Privileged Container)，這樣 eBPF 程式比較容易掛載到 upfgtp 介面。
4.	驗證： 確認 Prometheus UI 可以訪問。
Phase 2: eBPF 監控開發 (Core Logic)
目標： 能夠從 Kernel 抓到封包並統計。
1.	工具選型： 使用 cilium/ebpf (Go library) 來開發。
2.	eBPF Hook 點 (關鍵技術)：
o	Tracepoint / Kprobe: Hook gtp5g 模組的關鍵函數 (如 gtp_encap_recv, gtp_dev_xmit)。
o	Traffic Control (TC) or XDP: 掛載在實體網卡或 upfgtp0 介面，過濾 GTP-U Header (UDP Port 2152)。
3.	Packet Drop 偵測：
o	使用 kfree_skb tracepoint 來捕捉核心丟棄封包的事件。
o	在 eBPF map 中記錄丟包原因與來源 IP/TEID。
Phase 3: 控制面關聯與數據導出
目標： 讓數據有意義 (不只是看到 TEID 0x123，而是知道這是哪個 Session)。
1.	PFCP Sniffer: 在 Agent 中實作一個 Packet Sniffer (使用 gopacket) 監聽 localhost:8805。
2.	關聯邏輯： 解析 PFCP Session Establishment Request，提取 SEID (Session ID) 與 TEID (Tunnel ID) 的對應關係。
3.	Otel Integration: 使用 Go Otel SDK，將 eBPF 收集到的 Map 數據 (Counter/Gauge) 轉為 Metrics，發送給 Otel Collector。
Phase 4: 前端平台與 API 開發
目標： 取代 Grafana，建立自己的觀測平台。
1.	Backend API: 寫一個簡單的 Go Web Server (Gin/Echo)，提供 REST API：
o	GET /api/metrics/throughput: 查詢 Prometheus。
o	GET /api/drops: 查詢 Prometheus 的 Drop counter。
o	GET /api/sessions: 顯示目前活躍的 PDU Sessions (從 Agent 記憶體或 Redis 讀取)。
2.	Frontend UI:
o	Dashboard: 顯示即時流量折線圖 (Recharts/Chart.js)。
o	Topology: 畫出 UE -> RAN -> UPF -> DN 的拓樸圖，並用顏色標示健康度。
o	Alert List: 顯示 "Detected Packet Drop: Reason X"。
Phase 5: 故障模擬與整合測試
目標： 驗證你的平台能抓到錯誤。
1.	實作故障腳本 (Fault Injector)：
o	情境 1 (No PDR Match): 使用 scapy 偽造一個全新的 GTP-U 封包 (隨機 TEID)，直接打入 UPF 的 UDP 2152 port。預期 UPF 核心層丟棄。
o	情境 2 (SMF Misconfig): 撰寫腳本修改 free5GC 的 config 或直接透過 API 刪除 Session，但繼續讓 UERANSIM 送流量。
2.	驗證： 當腳本執行時，你的前端網頁應該要即時出現紅色的 Drop 告警。
________________________________________
4. 針對 UPF 監測的關鍵技術細節 (Trace UERANSIM & free5GC)
既然你已經有 UERANSIM 和 free5gc 的 source code，在開發 Agent 時請特別注意：
1.	UERANSIM (Packet Generation):
o	查看 src/ue/ue.cpp 或 src/gnb/gnb.cpp，了解它是如何封裝 GTP 封包的。你在做故障模擬時，可以用類似的邏輯寫一個 Python Scapy 腳本。
2.	free5GC (UPF/gtp5g):
o	重點不在 Go code，而在 kernel module (gtp5g)。
o	你需要去 trace gtp5g 的 C code (如果你的 UPF 是用 kernel mode)。
o	Drop 的關鍵位置： 在 gtp5g 原始碼中搜尋 return 錯誤代碼的地方，或者 kfree_skb 的呼叫點。你的 eBPF 程式需要監控這些點。
5. 預期成果展示 (Dashboard 設計構想)
你的自建網頁應該包含以下區塊：
1.	Header: 系統狀態 (K8s Cluster Status, UPF Status)。
2.	Main Chart (Live Traffic):
o	X軸：時間
o	Y軸：Mbps
o	線條：Uplink 流量, Downlink 流量。
3.	Anomaly Panel (Drop Monitor):
o	顯示 "Drop Rate"。如果 > 0，變紅色並閃爍。
o	Table 顯示：Timestamp, Source IP, Dest IP, TEID, Drop Reason (例如：Kernel Drop)。
4.	Correlation View:
o	顯示目前的 PDU Session ID 與 TEID 的對應表 (證明你有做到 Control/Data plane 關聯)。
這個架構既符合你的課程/專案要求，又具有高度的技術含金量 (eBPF + Custom Observability Stack)。我們可以從 Phase 1 開始，你需要我先提供哪部分的初始代碼或設定檔嗎？
```