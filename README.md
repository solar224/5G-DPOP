# 5G-DPOP

5G-DPOP is an eBPF-based observability platform for the free5GC user plane. It observes the `gtp5g` kernel data path and PFCP control messages to present live traffic, packet-drop evidence, PDU-session correlation, and a topology derived from the network that is actually observed.

## What It Does

- Measures uplink and downlink user-plane traffic at the `gtp5g` hooks.
- Captures `gtp5g` drop events with packet and hook context.
- Correlates PFCP sessions, SEIDs, PDRs, FARs, F-TEIDs, and observed GTP-U traffic.
- Discovers UE, gNB, UPF, N3, N9, N6, and DN paths without fixed UPF counts, addresses, container names, or DN selectors.
- Supports native free5GC and containerized free5GC deployments, including ULCL paths.

## Documentation

- [Quick Start](docs/quick-start.md)
- [System Architecture Requirements](docs/system-architecture-requirements.md)

## Future

- Aggregate observations from UPFs distributed across multiple hosts.
- Add IPv6 PDU-session and dual-stack data-plane support.
- Add authenticated production deployment profiles with TLS and access control.
- Add durable session and traffic history with configurable retention.
- Expand automated compatibility testing across free5GC, `gtp5g`, kernel, and container-network versions.
