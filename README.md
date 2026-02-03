# 5G-DPOP: 5G UPF Data Plane Observability Platform

A 5G Core Network User Plane observability platform based on eBPF technology. This project leverages Linux eBPF kprobe mechanisms to directly hook `gtp5g` kernel module functions, enabling real-time traffic monitoring, packet drop detection, and PFCP session correlation analysis.

## System Architecture

| Component | Technology | Function | Port |
|-----------|------------|----------|------|
| eBPF Agent | Go + cilium/ebpf | Load eBPF programs, read kernel maps, export metrics | 9100 |
| PFCP Sniffer | Go + gopacket | Listen to PFCP messages, parse sessions, build TEID mappings | 8805 |
| API Server | Go + Gin | REST API + WebSocket real-time streaming | 8080 |
| Web Frontend | React + TypeScript + Vite | Visualization dashboard | 3000 |
| Prometheus | Docker | Time-series database, metrics storage | 9090 |
| Otel Collector | Docker | OpenTelemetry collector | 4317 |

## Requirements

### Operating System
- Ubuntu 25.04 (Kernel 6.14+ with BTF support)

### Software Requirements
| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.21+ | Compile Agent and API Server |
| Node.js | 18+ LTS | Build Web Frontend |
| Docker | 24+ | Run Observability Stack |
| Docker Compose | v2+ | Container orchestration |
| Clang/LLVM | 14+ | Compile eBPF programs |
| bpftool | Latest | Generate vmlinux.h |

### Prerequisites
- free5GC v4.1.0 or free5gc-compose environment ready
- gtp5g kernel module loaded

### Verify Environment

```bash
# Check BTF support
ls -la /sys/kernel/btf/vmlinux

# Check gtp5g module
lsmod | grep gtp5g
# Expected output: gtp5g   159744  0

# Verify hookable symbols exist
sudo cat /proc/kallsyms | grep gtp5g_encap_recv
sudo cat /proc/kallsyms | grep gtp5g_dev_xmit
# Expected output:
# ffffffffc11a7aa0 t gtp5g_encap_recv     [gtp5g]
# ffffffffc11a6420 t gtp5g_dev_xmit       [gtp5g]
```

## Quick Start

### Important: Startup Order

**You must start 5G-DPOP before starting free5GC**. 5G-DPOP needs to capture PFCP Session Establishment messages during UE registration to correctly build Session and Topology information.

### Step 1: Install Dependencies

Option 1: Use one-click setup script
```bash
cd ~/5G-DPOP
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh
```

Option 2: Manual installation
```bash
# Install build tools and eBPF development dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    libelf-dev \
    libpcap-dev \
    pkg-config \
    bpftool
```

### Step 2: Build Project

```bash
cd ~/5G-DPOP

# Generate vmlinux.h (required for first build)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h

# Compile eBPF programs and Go binaries
make all

# Expected output:
# clang -O2 -g -Wall -target bpf ... -o internal/ebpf/bpf/upf_monitor.bpf.o
# go build -o bin/agent ./cmd/agent
# go build -o bin/api-server ./cmd/api-server

# Verify build results
ls -la bin/
# Should see agent and api-server executables

# Install Web frontend dependencies
cd web && npm install && cd ..
```

### Step 3: Start Observability Stack

```bash
# Start Prometheus + Otel Collector + Redis
docker compose -f deployments/docker-compose.yaml up -d

# Check container status
docker compose -f deployments/docker-compose.yaml ps
# Expected: prometheus, otel-collector, redis all in running state

# Verify Prometheus
curl http://localhost:9090/-/healthy
# Expected output: Prometheus Server is Healthy.
```

### Step 4: Start 5G-DPOP Services

You need to open three terminals:

**Terminal 1 - Agent (requires root privileges)**
```bash
cd ~/5G-DPOP
sudo ./bin/agent

# Expected output:
# ============================================================
#     5G-DPOP: UPF Data Plane Observability Agent
# ============================================================
# [OK] eBPF programs loaded successfully
# [OK] Event loop started
# [INFO] Prometheus metrics server listening on :9100
```

**Terminal 2 - API Server**
```bash
cd ~/5G-DPOP
./bin/api-server

# Expected output:
# ============================================================
#     5G-DPOP: Backend API Server
# ============================================================
# [INFO] Starting API server on :8080
```

**Terminal 3 - Web Frontend**
```bash
cd ~/5G-DPOP/web
npm run dev

# Expected output:
#   VITE v5.4.x  ready in xxx ms
#   ➨  Local:   http://localhost:3000/
```

### Step 5: Start free5GC

After confirming all 5G-DPOP services are running, start free5GC:

```bash
cd ~/free5gc-compose

# Standard version
docker compose -f docker-compose.yaml up -d

# Or ULCL version (dual UPF)
docker compose -f docker-compose-ulcl.yaml up -d

# Verify gNB connection
docker logs ueransim 2>&1 | tail -5
# Expected: [ngap] [info] NG Setup procedure is successful
```

### Step 6: Start UE and Generate Traffic

```bash
# Start UE
docker exec -d ueransim ./nr-ue -c ./config/uecfg.yaml

# Wait for UE registration
sleep 15

# Check UE status
docker exec ueransim ./nr-cli -d
# Expected output:
# UERANSIM-gnb-208-93-1
# imsi-208930000000001

# Verify UE is registered
docker exec ueransim ./nr-cli imsi-208930000000001 -e "status"
# Expected: cm-state: CM-CONNECTED, rm-state: RM-REGISTERED

# Generate test traffic
docker exec ueransim ping -I uesimtun0 8.8.8.8 -c 5
# Expected: 5 packets transmitted, 5 received, 0% packet loss
```

### Step 7: View Monitoring Dashboard

Open browser and visit: **http://localhost:3000**

You should see:
- Traffic Chart: Uplink/Downlink traffic charts
- Stats Cards: Packet count and bytes continuously increasing
- Session Table: Established PDU Sessions
- Network Topology: UE → gNB → UPF → DN topology diagram

## Verify Service Status

```bash
# Check Agent
curl http://localhost:9100/health
# Expected output: OK

# Check API Server
curl http://localhost:8080/api/v1/health
# Expected output: {"status":"ok","timestamp":"...","version":"1.0.0"}

# Check Sessions
curl http://localhost:8080/api/v1/sessions
# Expected: PDU Session information displayed

# Check Topology
curl http://localhost:8080/api/v1/topology
# Expected: nodes (UE, gNB, UPF, DN) and links displayed

# Check Prometheus metrics
curl http://localhost:9100/metrics | grep upf_
# Expected output:
# upf_packets_total{direction="uplink"} ...
# upf_packets_total{direction="downlink"} ...
# upf_bytes_total{direction="uplink"} ...
# upf_bytes_total{direction="downlink"} ...
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/health` | Health check |
| `GET /api/v1/sessions` | Get all PDU Sessions |
| `GET /api/v1/topology` | Get network topology |
| `GET /api/v1/metrics/traffic` | Get traffic statistics |

## Common Commands

```bash
# One-click build
make all

# Start Observability Stack
make compose-up

# Stop Observability Stack
make compose-down

# Clean build artifacts
make clean

# Stop all 5G-DPOP services
pkill -f agent
pkill -f api-server
```

## Troubleshooting

### Session information is empty
- Confirm 5G-DPOP was started before free5GC
- Re-register UE to trigger new PFCP Session:
  ```bash
  docker exec ueransim ./nr-cli imsi-208930000000001 -e "deregister normal"
  sleep 3
  docker exec -d ueransim ./nr-ue -c ./config/uecfg.yaml
  ```

### Agent fails to start
- Confirm running with `sudo`
- Confirm `gtp5g` module is loaded: `lsmod | grep gtp5g`
- Confirm BTF support: `ls -la /sys/kernel/btf/vmlinux`
- Confirm hookable symbols exist: `sudo cat /proc/kallsyms | grep gtp5g_encap_recv`

### Topology only shows DN node
- Generate some traffic to update topology
- Wait a few seconds and refresh the page
- Confirm Session is established: `curl http://localhost:8080/api/v1/sessions`

### Cannot find traffic when using free5gc-compose
- Agent automatically detects `br-free5gc` network interface
- If issues persist, manually specify: `sudo ./bin/agent -pfcp-iface br-free5gc`
