# Quick Start

This path starts the free5GC ULCL example and 5G-DPOP on the same Ubuntu host. Start 5G-DPOP before creating the UE PDU session so that the agent can observe the PFCP session procedure.

## One-Time Preparation

The following assumes that the repositories exist at `~/gtp5g-DPOP`, `~/5G-DPOP`, and `~/free5gc-compose`. Stop any running UPFs before installing or reloading the kernel module.

```bash
cd ~/5G-DPOP
GTP5G_PATH=~/gtp5g-DPOP ./scripts/setup_env.sh
make all
make web-install
```

This installs and loads the 5G-DPOP-compatible `gtp5g-DPOP` module with BTF and the eBPF hook symbols required by the agent.

## Happy Path

### 1. Start free5GC ULCL — Terminal 1

```bash
cd ~/free5gc-compose
docker compose -f docker-compose-ulcl.yaml up -d
```

On the first run, open the free5GC WebUI at [http://localhost:5000](http://localhost:5000) and create the subscriber before starting the UE. Its SUPI, key, OP/OPC type and value, AMF, DNN, and S-NSSAI must match `config/uecfg-ulcl.yaml`. Skip this only when the matching subscriber already exists.

### 2. Start all 5G-DPOP services — Terminal 2

```bash
cd ~/5G-DPOP
./scripts/run_dev.sh
```

This one command starts the privileged agent, API server, and web development server. Wait until the terminal reports that the eBPF programs and PFCP sniffer are running and Vite is ready.

The default agent mode automatically selects a named free5GC Docker bridge when one is present and otherwise captures PFCP on `any`. Do not add `-pfcp-iface` to the normal startup command.

### 3. Start one UE and generate traffic — Terminal 1

Run the UE command once. Starting the same IMSI more than once creates competing UE processes and invalidates the test.

```bash
docker exec -d ueransim ./nr-ue -c ./config/uecfg.yaml
docker exec ueransim ping -I uesimtun0 1.1.1.1 -c 5
```

With one successfully registered UE, UERANSIM creates `uesimtun0`. If the configured interface name is different, obtain the actual name with the interface command in Diagnostics and use it with `ping -I`.

### 4. View the result

Open [http://localhost:3000](http://localhost:3000). A successful run has:

- a registered PDU session rather than only an uncorrelated traffic observation;
- packet and byte counters that increase while the ping runs;
- active topology links that follow the PFCP-derived ULCL route for the selected destination;
- no continuously active link after the traffic activity window expires.

Press Ctrl+C in Terminal 2 to stop all three 5G-DPOP services. Stop the core with:

```bash
cd ~/free5gc-compose
docker compose -f docker-compose-ulcl.yaml down
```

## Diagnostics

Use these only after the happy path does not produce the expected result.

### 5G-DPOP health and capture

```bash
curl -fsS http://localhost:9100/health
curl -fsS http://localhost:9100/api/interfaces
curl -fsS http://localhost:8080/api/v1/sessions
curl -fsS http://localhost:8080/api/v1/topology
```

`current_config` in the interface response is the active PFCP capture device. If the agent was restarted or missed session establishment, restart the UE so that a new PDU session is established.

### UE registration and tunnel

```bash
docker exec ueransim ./nr-cli -d
docker exec ueransim ./nr-cli imsi-208930000000001 -e status
docker exec ueransim ip -brief link
docker exec ueransim pgrep -a nr-ue
```

Proceed with data-plane testing only when the UE is registered and exactly one intended `nr-ue` process is running. No `uesimtun` interface means that PDU-session establishment did not complete; confirm subscriber credentials and slice/DNN values before investigating routing.

### Core and UPF logs

```bash
docker logs --tail 100 ueransim
docker logs --tail 100 amf
docker logs --tail 100 smf
docker logs --tail 100 i-upf
docker logs --tail 100 psa-upf
```

### Kernel module and eBPF prerequisites

```bash
lsmod | grep gtp5g
ls /sys/kernel/btf/vmlinux /sys/kernel/btf/gtp5g
sudo grep -E 'gtp5g_trace_drop|gtp5g_encap_recv|gtp5g_dev_xmit|pdr_find_by_gtp1u|pdr_find_by_ipv4' /proc/kallsyms
```

After a kernel or `gtp5g-DPOP` source update, stop the UPFs and rebuild/reload the module:

```bash
cd ~/5G-DPOP
GTP5G_PATH=~/gtp5g-DPOP ./scripts/setup_env.sh --gtp5g-only --force
make all
```

## Optional Metrics Stack

The live dashboard does not require Prometheus, OpenTelemetry Collector, or Redis. Start the optional metrics stack only when those services are needed:

```bash
cd ~/5G-DPOP
docker compose -f deployments/docker-compose.yaml up -d
```
