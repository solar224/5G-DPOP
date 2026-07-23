# System Architecture Requirements

## Purpose and Scope

5G-DPOP observes a Linux `gtp5g` user plane and reconstructs the topology from runtime evidence. It does not assume a fixed UPF count, UPF role, IP range, Docker Compose filename, container name, DN name, or traffic selector.

The supported deployment shapes include:

- native free5GC with PFCP on loopback and a host `upfgtp` device;
- free5GC and UERANSIM on separate hosts;
- `free5gc-compose` with a single UPF;
- `free5gc-compose` ULCL with I-UPF, PSA-UPF, N9, local breakout, and multiple DNs.

## Runtime Architecture

```text
                         N4 / PFCP (UDP 8805)
                    SMF ----------------------+
                                               |
UE -- Radio -- gNB -- N3 / GTP-U --> UPF(s) --+-- N6 --> DN
                                      |
                                      +-- N9 / GTP-U --> UPF

gtp5g kernel hooks + PFCP capture
              |
              v
       5G-DPOP agent :9100
              |
              v
       API server :8080
              |
              v
       Web dashboard :3000
```

| Component | Required role |
| --- | --- |
| `gtp5g-DPOP` | Forwards the free5GC user plane and exposes stable hook points required by the eBPF agent. |
| eBPF agent | Attaches to the kernel module, captures PFCP, correlates sessions and traffic, and exposes live APIs and Prometheus metrics. |
| API server | Normalizes agent data and builds session, drop, traffic, and topology responses. |
| Web dashboard | Renders only API evidence and omits unavailable identifiers rather than inventing placeholder values. |
| Prometheus, OpenTelemetry Collector, Redis | Optional supporting stack; not required by the live dashboard happy path. |

## Evidence and Topology Model

PFCP and eBPF provide different parts of the model:

- PFCP Session Establishment and Modification messages provide CP and UP F-SEIDs, UE IP, PDRs, FARs, F-TEIDs, outer-header creation, destination interfaces, network instances, and SDF destination selectors.
- `gtp5g_encap_recv` and `gtp5g_dev_xmit` provide observed GTP-U and inner-PDU traffic.
- `gtp5g_trace_drop` provides explicit module drop events. PDR lookup hooks provide lookup context.

The correlation rules are:

- A PDU-session observation is scoped to a specific local UPF and UP F-SEID. CP F-SEID, UP F-SEID, and TEID are distinct identifiers and must not be substituted for one another.
- A PDR local F-TEID identifies traffic received by the local UPF. A FAR outer-header TEID identifies the remote GTP-U endpoint used for forwarding.
- N3, N9, and N6 edges are derived from PDR/FAR interface and tunnelling evidence.
- UPF display roles such as I-UPF and PSA-UPF are inferred from graph position and forwarding behavior, not from an address or container name.
- A specific SDF destination may create a distinct DN node. A default N6 rule creates a DN based on observed network-instance/DNN evidence.
- Traffic is attached to the observed path and expires after the activity window. A packet seen at two UPFs is two UPF-hop observations and must not be presented as one end-to-end byte count.
- When evidence is missing or ambiguous, the API and frontend must omit the unsupported field or mark the observation uncorrelated; they must not fabricate a path.

Because 5G-DPOP reconstructs state from captured messages, the agent must be running before the UE establishes its PDU session. Restarting the agent requires re-establishing the session.

## Host Requirements

The current tested baseline is Ubuntu 25.04 with Linux 6.14 on x86-64. Other kernels require compatibility testing.

Required host capabilities:

- kernel BTF at `/sys/kernel/btf/vmlinux`;
- loadable kernel modules and BTF for the loaded `gtp5g` module;
- root privileges for loading eBPF programs and capturing PFCP;
- access to the host network namespaces/interfaces that carry PFCP and the `gtp5g` data path;
- IPv4 forwarding and the routes/NAT required by the selected free5GC deployment.

Required software:

| Software | Minimum or tested requirement |
| --- | --- |
| Go | 1.21 or newer |
| Node.js | 18 or newer |
| Docker Engine | 24 or newer for compose deployments |
| Docker Compose | v2 plugin |
| Clang/LLVM | 14 or newer |
| libbpf, bpftool, libelf | Needed to build and load eBPF |
| libpcap | Needed for PFCP capture |
| kernel headers, `pahole`, binutils | Needed to build `gtp5g-DPOP` with BTF |
| libmnl, libyaml | Needed to build the kernel module |

The current eBPF build target is x86 (`__TARGET_ARCH_x86`). Supporting another CPU architecture requires an appropriate target and regenerated bindings.

## Kernel Hook Contract

The loaded `gtp5g-DPOP` module must expose these symbols:

| Symbol | Observation purpose |
| --- | --- |
| `gtp5g_trace_drop` | Primary explicit drop event |
| `gtp5g_encap_recv` | Ingress GTP-U and uplink traffic |
| `gtp5g_dev_xmit` | Egress/downlink traffic |
| `pdr_find_by_gtp1u` | Uplink PDR lookup context |
| `pdr_find_by_ipv4` | Downlink PDR lookup context |

The module must be built from the compatible `gtp5g-DPOP` source, loaded with BTF, and remain the module used by every local UPF. An upstream module without these hooks cannot provide complete traffic and drop observability.

## Network and Capture Requirements

| Interface | Protocol and port | Requirement |
| --- | --- | --- |
| N3 | GTP-U, UDP 2152 | gNB-to-UPF traffic must traverse the observed host kernel. |
| N9 | GTP-U, UDP 2152 | Inter-UPF traffic must be visible to the relevant host agent. |
| N4 | PFCP, UDP 8805 | Session establishment and modification traffic must be captured by the agent. |
| N6 | Deployment-specific | Routing and NAT must permit the selected DN path. |

The default agent command is `sudo ./bin/agent`; `-pfcp-iface auto` is implicit. Auto mode selects an interface whose name identifies a free5GC Docker bridge and otherwise uses Linux capture device `any`, which includes native loopback PFCP. A manual `-pfcp-iface` override is for diagnostics only and can hide sessions carried on another interface.

For UPFs distributed across multiple physical hosts, one local agent can observe only the kernel hooks and PFCP interfaces on its own host. Complete multi-host aggregation is a future capability; until then, run and inspect an agent at each relevant host.

## Service Interfaces

| Service | Default listener | Purpose |
| --- | --- | --- |
| Agent | `:9100` | Health, metrics, session/drop data, capture status |
| API server | `:8080` | Dashboard REST API and WebSocket |
| Vite development server | `:3000` | Development dashboard |
| Prometheus | `:9090` | Optional historical metrics |
| OTLP | `:4317`, `:4318` | Optional telemetry ingestion |

When the API server and agent are on different hosts, set `DPOP_AGENT_URL` to the reachable agent base URL before starting the API server. Firewall and routing rules must permit the connection.

## Security and Production Boundary

The agent is privileged because eBPF loading and packet capture require host access. Restrict who can execute it and who can reach port 9100. The Vite server and unauthenticated default API are development services; do not expose them directly to an untrusted network. A production deployment requires TLS termination, authentication, authorization, firewall policy, and a managed service supervisor.

See the [Quick Start](quick-start.md) for the supported development startup path.
