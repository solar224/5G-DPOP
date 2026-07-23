package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/solar224/5G-DPOP/internal/ebpf"
	"github.com/solar224/5G-DPOP/internal/pfcp"
)

var (
	// Command line flags
	// Default to "auto" for automatic interface detection
	// The auto-detection will find the best interface for PFCP capture:
	// - Looks for br-free5gc, Docker bridges, interfaces with 5G network IPs
	// - Falls back to "any" (all interfaces) if no specific match
	// Use -pfcp-iface to override (e.g., "lo" for local testing, "br-free5gc" for specific bridge)
	pfcpIface           = flag.String("pfcp-iface", "auto", "Interface to capture PFCP packets (use 'auto' for automatic detection)")
	enableSyntheticData = flag.Bool(
		"enable-synthetic-data",
		false,
		"Enable explicitly labelled demo/manual session injection APIs (disabled by default)",
	)

	// Prometheus metrics
	packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upf_packets_total",
			Help: "Total number of successfully forwarded IPv4 PDU packets observed at gtp5g",
		},
		[]string{"direction"},
	)

	bytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upf_bytes_total",
			Help: "Total successfully forwarded IPv4 PDU bytes observed at gtp5g",
		},
		[]string{"direction"},
	)

	packetDropsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upf_packet_drops_total",
			Help: "Total number of dropped packets",
		},
		[]string{"reason", "direction"},
	)

	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "upf_active_sessions",
			Help: "Number of active PDU sessions",
		},
	)

	// Drop events storage
	dropEventsMu        sync.RWMutex
	recentDrops         = make([]DropEventJSON, 0)
	totalDrops          uint64
	userPlaneDrops      uint64
	infrastructureDrops uint64
	uncorrelatedDrops   uint64
	dropsByReason       = make(map[string]uint64)

	// PFCP correlation
	pfcpCorrelation *pfcp.Correlation

	// Global eBPF loader for API access
	ebpfLoader *ebpf.Loader

	// PFCP interface actually used after auto-detection/fallback
	activePFCPInterface = "not-started"

	// Previous counter values for calculating deltas
	prevUplinkPackets   uint64
	prevDownlinkPackets uint64
	prevUplinkBytes     uint64
	prevDownlinkBytes   uint64
)

// DropEventJSON is the JSON representation of a drop event
type DropEventJSON struct {
	Timestamp               string   `json:"timestamp"`
	KernelTimestampNS       uint64   `json:"kernel_timestamp_ns"`
	TEID                    string   `json:"teid,omitempty"`
	SrcIP                   string   `json:"src_ip,omitempty"`
	DstIP                   string   `json:"dst_ip,omitempty"`
	SrcPort                 uint16   `json:"src_port,omitempty"`
	DstPort                 uint16   `json:"dst_port,omitempty"`
	PktLen                  uint32   `json:"pkt_len"`
	Reason                  string   `json:"reason"`
	Direction               string   `json:"direction"`
	Family                  string   `json:"family"`
	Protocol                string   `json:"protocol"`
	Origin                  string   `json:"origin"`
	ICMPType                uint8    `json:"icmp_type,omitempty"`
	ValidFields             []string `json:"valid_fields"`
	Scope                   string   `json:"scope"`
	Classification          string   `json:"classification"`
	SessionCorrelated       bool     `json:"session_correlated"`
	CorrelatedObservationID string   `json:"correlated_observation_id,omitempty"`
}

type FlowRuleJSON struct {
	PDRID                uint16 `json:"pdr_id"`
	FARID                uint32 `json:"far_id"`
	Precedence           uint32 `json:"precedence"`
	SourceInterface      int    `json:"source_interface"`
	SourceInterfaceType  int    `json:"source_interface_type"`
	DestinationInterface int    `json:"destination_interface"`
	InterfaceType        int    `json:"interface_type"`
	LocalFTEID           string `json:"local_f_teid,omitempty"`
	LocalFTEIDIP         string `json:"local_f_teid_ip,omitempty"`
	SDFObserved          bool   `json:"sdf_observed"`
	SDF                  string `json:"sdf,omitempty"`
	DestinationSelector  string `json:"destination_selector,omitempty"`
	NetworkInstance      string `json:"network_instance,omitempty"`
	OuterDst             string `json:"outer_dst,omitempty"`
	OuterTEID            string `json:"outer_teid,omitempty"`
	PathType             string `json:"path_type,omitempty"`
}

type FlowTrafficJSON struct {
	DestIP     string `json:"dest_ip"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	LastActive string `json:"last_active,omitempty"`
	OuterSrc   string `json:"outer_src,omitempty"`
	OuterDst   string `json:"outer_dst,omitempty"`
	Direction  string `json:"direction"`
}

// SessionJSON is the JSON representation of a session (extended)
type SessionJSON struct {
	ObservationID string   `json:"observation_id"`
	CPSEID        string   `json:"cp_seid,omitempty"`
	UPSEID        string   `json:"up_seid,omitempty"`
	Source        string   `json:"source,omitempty"`
	UEIP          string   `json:"ue_ip,omitempty"`
	LocalFTEIDs   []string `json:"local_f_teids,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	PacketsUL     uint64   `json:"packets_ul"`
	PacketsDL     uint64   `json:"packets_dl"`

	// Extended fields
	UPFIP        string            `json:"upf_ip,omitempty"`
	UPFN3IP      string            `json:"upf_n3_ip,omitempty"`
	GNBIP        string            `json:"gnb_ip,omitempty"`
	AccessPeerIP string            `json:"access_peer_ip,omitempty"`
	UplinkPeerIP string            `json:"uplink_peer_ip,omitempty"`
	N9PeerIP     string            `json:"n9_peer_ip,omitempty"` // N9 peer UPF IP (for ULCL)
	N9Direction  string            `json:"n9_direction,omitempty"`
	N9Evidence   string            `json:"n9_evidence,omitempty"`
	HasN6        bool              `json:"has_n6,omitempty"`
	FlowRules    []FlowRuleJSON    `json:"flow_rules,omitempty"`
	FlowTraffic  []FlowTrafficJSON `json:"flow_traffic,omitempty"`
	SUPI         string            `json:"supi,omitempty"`
	DNN          string            `json:"dnn,omitempty"`
	SNssai       string            `json:"s_nssai,omitempty"`
	QFI          uint8             `json:"qfi,omitempty"`
	SessionType  string            `json:"session_type,omitempty"`
	SessionID    uint8             `json:"pdu_session_id,omitempty"`

	// Traffic statistics
	BytesUL uint64 `json:"bytes_ul"`
	BytesDL uint64 `json:"bytes_dl"`

	// QoS parameters
	GBRUplink   uint64 `json:"gbr_ul_kbps,omitempty"`
	GBRDownlink uint64 `json:"gbr_dl_kbps,omitempty"`
	MBRUplink   uint64 `json:"mbr_ul_kbps,omitempty"`
	MBRDownlink uint64 `json:"mbr_dl_kbps,omitempty"`

	// Status
	Status              string `json:"status,omitempty"`
	Duration            string `json:"duration,omitempty"`
	LastActive          string `json:"last_active,omitempty"`
	EstablishmentStatus string `json:"establishment_status,omitempty"` // Pending, Established, Failed

	// Data Plane status (based on actual packet activity)
	DataPlaneStatus string `json:"data_plane_status,omitempty"` // Active, Stale, Inactive
	LastPacketTime  string `json:"last_packet_time,omitempty"`  // Last packet activity timestamp
}

func init() {
	prometheus.MustRegister(packetsTotal)
	prometheus.MustRegister(bytesTotal)
	prometheus.MustRegister(packetDropsTotal)
	prometheus.MustRegister(activeSessions)
}

func main() {
	flag.Parse()

	log.Println("============================================================")
	log.Println("    5G-DPOP: UPF Data Plane Observability Agent")
	log.Println("============================================================")

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (for eBPF)")
	}

	// Initialize PFCP correlation
	pfcpCorrelation = pfcp.NewCorrelation()

	// Create eBPF loader
	loader := ebpf.NewLoader()

	// Set up event handler for drops
	loader.OnDropEvent = func(event ebpf.DropEvent) {
		reason := ebpf.FormatDropReason(event.Reason)
		direction := ebpf.FormatDirection(event.Direction)
		dropEvent := buildDropEventJSON(event, reason, direction)

		log.Printf("[DROP] reason=%s(code=%d) direction=%s origin=%s scope=%s teid=%s src=%s dst=%s len=%d",
			reason, event.Reason, direction,
			dropEvent.Origin, dropEvent.Scope,
			displayOrNA(dropEvent.TEID),
			displayOrNA(dropEvent.SrcIP),
			displayOrNA(dropEvent.DstIP),
			event.PktLen)

		// Update Prometheus metrics
		packetDropsTotal.WithLabelValues(reason, direction).Inc()

		dropEventsMu.Lock()
		recentDrops = append([]DropEventJSON{dropEvent}, recentDrops...)
		if len(recentDrops) > 100 {
			recentDrops = recentDrops[:100]
		}
		totalDrops++
		switch dropEvent.Scope {
		case "user-plane":
			userPlaneDrops++
		case "infrastructure":
			infrastructureDrops++
		default:
			uncorrelatedDrops++
		}
		dropsByReason[reason]++
		dropEventsMu.Unlock()
	}

	// Load eBPF programs
	log.Println("Loading eBPF programs...")
	if err := loader.Load(); err != nil {
		log.Fatalf("Failed to load eBPF programs: %v", err)
	}
	defer loader.Close()

	// Enable detailed tracing for topology discovery
	if err := loader.EnableDetailedTracing(true); err != nil {
		log.Printf("[WARN] Failed to enable detailed tracing: %v", err)
	} else {
		log.Println("[INFO] Detailed tracing enabled for topology discovery")
	}

	// Set up packet event handler
	loader.OnPacketEvent = func(event ebpf.PacketEvent) {
		// gtp5g_encap_recv observes ingress on both N3 and N9. The correlation
		// store derives actual PDU direction from the inner UE endpoint.
		if event.Direction == ebpf.DirectionUplink && event.TEID > 0 {
			srcIP := uint32ToIP(event.SrcIP)
			dstIP := uint32ToIP(event.DstIP)
			innerSrcIP := uint32ToIP(event.InnerSrcIP)
			innerDstIP := uint32ToIP(event.InnerDstIP)
			pfcpCorrelation.RecordGTPFlow(
				event.TEID, srcIP, dstIP, innerSrcIP, innerDstIP, event.PktLen)
		}
	}

	// Store loader globally for API access
	ebpfLoader = loader

	log.Println("[OK] eBPF programs loaded successfully")

	// NOTE: kfree_skb tracing is DISABLED by default because it captures ALL kernel drops
	// which creates too much noise. Only gtp5g-specific drops are captured via kprobes.
	// To enable kernel-wide drop tracing, use: POST /api/config/drop-tracing {"enabled": true}
	log.Println("[INFO] Kernel-wide drop tracing (kfree_skb) is DISABLED by default")
	log.Println("[INFO] Only GTP/UPF specific drops will be captured via kprobes")

	// Start PFCP sniffer
	pfcpSniffer := pfcp.NewSniffer(*pfcpIface, 8805, pfcpCorrelation)
	if err := pfcpSniffer.Start(); err != nil {
		log.Printf("[WARN] Failed to start PFCP sniffer: %v", err)
		log.Printf("       PDU session tracking will be limited")
	} else {
		defer pfcpSniffer.Stop()
		activePFCPInterface = pfcpSniffer.Interface()
		log.Printf("[OK] PFCP sniffer started on interface %s", activePFCPInterface)
		if *pfcpIface != "" && *pfcpIface != "auto" && *pfcpIface != "any" {
			detected, reason := pfcp.AutoDetectInterface()
			if detected != "any" && detected != activePFCPInterface {
				log.Printf("[WARN] PFCP capture interface mismatch: active=%s, detected=%s (%s)",
					activePFCPInterface, detected, reason)
				log.Printf("[WARN] Sessions on %s will not be visible. Restart without -pfcp-iface for compatible auto detection.",
					detected)
			}
		}
	}

	// Start event processing loop
	loader.StartEventLoop()
	log.Println("[OK] Event loop started")

	// Start Prometheus HTTP server with additional API endpoints
	go startHTTPServer()

	// Start periodic stats collection
	go collectStats(loader)

	// Start periodic session count update
	go updateSessionCount()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("[INFO] Agent is running. Press Ctrl+C to stop.")
	log.Println("   Metrics available at http://localhost:9100/metrics")
	log.Println("   Sessions API: http://localhost:9100/api/sessions")
	log.Println("   Drops API: http://localhost:9100/api/drops")
	log.Println("")

	<-sigChan
	log.Println("\n[INFO] Shutting down...")
}

func startHTTPServer() {
	// Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Drop events API
	http.HandleFunc("/api/drops", handleDropsAPI)

	// Sessions API
	http.HandleFunc("/api/sessions", handleSessionsAPI)

	if *enableSyntheticData {
		// Synthetic records are explicitly labelled and are never enabled in a
		// default production invocation.
		http.HandleFunc("/api/demo/inject-drop", handleDemoInjectDrop)
		http.HandleFunc("/api/demo/inject-session", handleDemoInjectSession)
		http.HandleFunc("/api/sync/sessions", handleSyncSessions)
		log.Println("[WARN] Synthetic data APIs are enabled")
	}

	// Drop tracing control API
	http.HandleFunc("/api/config/drop-tracing", handleDropTracingConfig)

	// Interface detection API - for debugging and configuration
	http.HandleFunc("/api/interfaces", handleInterfacesAPI)

	log.Println("[INFO] HTTP server listening on :9100")
	if err := http.ListenAndServe(":9100", nil); err != nil {
		log.Printf("HTTP server error: %v", err)
	}
}

func handleDropsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	dropEventsMu.RLock()
	defer dropEventsMu.RUnlock()

	// eBPF traffic counters contain successful PDU packets; traced user-plane
	// drops are added back to form the number of valid forwarding attempts.
	// Infrastructure and uncorrelated hook events do not participate.
	successfulPackets := prevUplinkPackets + prevDownlinkPackets
	dropRate := userPlaneDropRate(successfulPackets, userPlaneDrops)

	response := map[string]interface{}{
		"total":                totalDrops,
		"user_plane_total":     userPlaneDrops,
		"infrastructure_total": infrastructureDrops,
		"uncorrelated_total":   uncorrelatedDrops,
		"rate_percent":         dropRate,
		"rate_basis":           "user-plane drop events / valid gtp5g user-plane attempts",
		"recent_drops":         recentDrops,
		"by_reason":            dropsByReason,
	}

	json.NewEncoder(w).Encode(response)
}

func userPlaneDropRate(successfulPackets, droppedPackets uint64) float64 {
	attempts := successfulPackets + droppedPackets
	if attempts == 0 {
		return 0
	}
	return float64(droppedPackets) / float64(attempts) * 100
}

func uint32ToIP(encoded uint32) net.IP {
	if encoded == 0 {
		return nil
	}
	// Kernel packet fields are copied in network-byte order into a native
	// uint32; decode bytes in memory order, matching ebpf.FormatIP.
	return net.IPv4(
		byte(encoded),
		byte(encoded>>8),
		byte(encoded>>16),
		byte(encoded>>24),
	)
}

func buildDropEventJSON(event ebpf.DropEvent, reason, direction string) DropEventJSON {
	drop := DropEventJSON{
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		KernelTimestampNS: event.Timestamp,
		PktLen:            event.PktLen,
		Reason:            reason,
		Direction:         direction,
		Family:            ebpf.FormatFamily(event.Family),
		Protocol:          ebpf.FormatProtocol(event.L4Protocol),
		Origin:            ebpf.FormatOrigin(event.Origin),
		ICMPType:          event.ICMPType,
		ValidFields:       make([]string, 0, 5),
		Scope:             "uncorrelated",
		Classification:    "unclassified",
	}

	if event.HasField(ebpf.FieldTEID) {
		drop.TEID = fmt.Sprintf("0x%x", event.TEID)
		drop.ValidFields = append(drop.ValidFields, "teid")
	}
	if event.HasField(ebpf.FieldSrcIP) {
		drop.SrcIP = ebpf.FormatIP(event.SrcIP)
		drop.ValidFields = append(drop.ValidFields, "src_ip")
	}
	if event.HasField(ebpf.FieldDstIP) {
		drop.DstIP = ebpf.FormatIP(event.DstIP)
		drop.ValidFields = append(drop.ValidFields, "dst_ip")
	}
	if event.HasField(ebpf.FieldSrcPort) {
		drop.SrcPort = event.SrcPort
		drop.ValidFields = append(drop.ValidFields, "src_port")
	}
	if event.HasField(ebpf.FieldDstPort) {
		drop.DstPort = event.DstPort
		drop.ValidFields = append(drop.ValidFields, "dst_port")
	}

	var session *pfcp.Session
	var ok bool
	if pfcpCorrelation != nil && event.HasField(ebpf.FieldTEID) {
		session, ok = pfcpCorrelation.GetSessionByTEID(event.TEID)
	}
	if !ok && pfcpCorrelation != nil && event.HasField(ebpf.FieldSrcIP) {
		session, ok = pfcpCorrelation.GetSessionByUEIP(drop.SrcIP)
	}
	if !ok && pfcpCorrelation != nil && event.HasField(ebpf.FieldDstIP) {
		session, ok = pfcpCorrelation.GetSessionByUEIP(drop.DstIP)
	}
	if ok && session != nil {
		drop.SessionCorrelated = true
		drop.CorrelatedObservationID = fmt.Sprintf("obs-%x", session.SEID)
	}

	switch {
	case event.Origin == ebpf.OriginDevXmit &&
		event.Family == 6 &&
		event.L4Protocol == 58 &&
		event.ICMPType == 133:
		drop.Scope = "infrastructure"
		drop.Classification = "ipv6_router_solicitation"
	case event.Origin == ebpf.OriginDevXmit && event.Family != 4:
		drop.Scope = "infrastructure"
		drop.Classification = "unsupported_l3_protocol"
	case (event.Origin == ebpf.OriginEncapRecv && event.HasField(ebpf.FieldTEID)) ||
		(event.Origin == ebpf.OriginDevXmit && event.Family == 4):
		drop.Scope = "user-plane"
		if drop.SessionCorrelated {
			drop.Classification = "session_user_plane"
		} else {
			drop.Classification = "uncorrelated_user_plane"
		}
	default:
		drop.Scope = "uncorrelated"
		drop.Classification = "insufficient_context"
	}

	return drop
}

func displayOrNA(value string) string {
	if value == "" {
		return "N/A"
	}
	return value
}

// convertSessionToJSON converts a pfcp.Session to SessionJSON
func convertSessionToJSON(s *pfcp.Session) SessionJSON {
	localFTEIDs := make([]string, 0, len(s.TEIDs))
	for _, teid := range s.TEIDs {
		if teid != 0 {
			localFTEIDs = append(localFTEIDs, fmt.Sprintf("0x%x", teid))
		}
	}

	ueIP := ""
	if s.UEIP != nil {
		ueIP = s.UEIP.String()
	}

	upfIP := ""
	if s.UPFIP != nil {
		upfIP = s.UPFIP.String()
	}

	upfN3IP := ""
	if s.UPFN3IP != nil {
		upfN3IP = s.UPFN3IP.String()
	}

	gnbIP := ""
	if s.GNBIP != nil {
		gnbIP = s.GNBIP.String()
	}

	accessPeerIP := ""
	if s.AccessPeerIP != nil {
		accessPeerIP = s.AccessPeerIP.String()
	}

	uplinkPeerIP := ""
	if s.UplinkPeerIP != nil {
		uplinkPeerIP = s.UplinkPeerIP.String()
	}

	n9PeerIP := ""
	if s.N9PeerIP != nil {
		n9PeerIP = s.N9PeerIP.String()
	}

	flowRules := make([]FlowRuleJSON, 0, len(s.FlowRules))
	for _, rule := range s.FlowRules {
		localFTEID := ""
		if rule.LocalFTEID != 0 {
			localFTEID = fmt.Sprintf("0x%x", rule.LocalFTEID)
		}
		localFTEIDIP := ""
		if rule.LocalFTEIDIP != nil {
			localFTEIDIP = rule.LocalFTEIDIP.String()
		}
		outerDst := ""
		if rule.OuterDst != nil {
			outerDst = rule.OuterDst.String()
		}
		outerTEID := ""
		if rule.OuterTEID != 0 {
			outerTEID = fmt.Sprintf("0x%x", rule.OuterTEID)
		}
		flowRules = append(flowRules, FlowRuleJSON{
			PDRID:                rule.PDRID,
			FARID:                rule.FARID,
			Precedence:           rule.Precedence,
			SourceInterface:      rule.SourceInterface,
			SourceInterfaceType:  rule.SourceInterfaceType,
			DestinationInterface: rule.DestinationInterface,
			InterfaceType:        rule.InterfaceType,
			LocalFTEID:           localFTEID,
			LocalFTEIDIP:         localFTEIDIP,
			SDFObserved:          rule.SDFObserved,
			SDF:                  rule.SDF,
			DestinationSelector:  rule.DestinationSelector,
			NetworkInstance:      rule.NetworkInstance,
			OuterDst:             outerDst,
			OuterTEID:            outerTEID,
			PathType:             rule.PathType,
		})
	}
	flowTraffic := make([]FlowTrafficJSON, 0, len(s.FlowTraffic))
	for _, flow := range s.FlowTraffic {
		outerSrc := ""
		if flow.OuterSrc != nil {
			outerSrc = flow.OuterSrc.String()
		}
		outerDst := ""
		if flow.OuterDst != nil {
			outerDst = flow.OuterDst.String()
		}
		lastActive := ""
		if !flow.LastActive.IsZero() {
			lastActive = flow.LastActive.Format(time.RFC3339Nano)
		}
		flowTraffic = append(flowTraffic, FlowTrafficJSON{
			DestIP:     flow.DestIP.String(),
			Packets:    flow.Packets,
			Bytes:      flow.Bytes,
			LastActive: lastActive,
			OuterSrc:   outerSrc,
			OuterDst:   outerDst,
			Direction:  flow.Direction,
		})
	}

	createdAt := ""
	durationStr := ""
	if !s.CreatedAt.IsZero() {
		createdAt = s.CreatedAt.Format(time.RFC3339)
		durationStr = formatDuration(time.Since(s.CreatedAt))
	}

	lastActive := ""
	if !s.LastActive.IsZero() {
		lastActive = s.LastActive.Format(time.RFC3339)
	}

	// Format last packet time
	lastPacketTime := ""
	if !s.LastPacketTime.IsZero() {
		lastPacketTime = s.LastPacketTime.Format(time.RFC3339)
	}

	cpSEID := ""
	if s.CPSEID != 0 {
		cpSEID = fmt.Sprintf("0x%x", s.CPSEID)
	}
	upSEID := ""
	if s.UPSEID != 0 {
		upSEID = fmt.Sprintf("0x%x", s.UPSEID)
	}

	return SessionJSON{
		ObservationID: fmt.Sprintf("obs-%x", s.SEID),
		CPSEID:        cpSEID,
		UPSEID:        upSEID,
		Source:        s.Source,
		UEIP:          ueIP,
		LocalFTEIDs:   localFTEIDs,
		CreatedAt:     createdAt,
		PacketsUL:     s.PacketsUL,
		PacketsDL:     s.PacketsDL,

		// Extended fields
		UPFIP:        upfIP,
		UPFN3IP:      upfN3IP,
		GNBIP:        gnbIP,
		AccessPeerIP: accessPeerIP,
		UplinkPeerIP: uplinkPeerIP,
		N9PeerIP:     n9PeerIP,
		N9Direction:  s.N9Direction,
		N9Evidence:   s.N9Evidence,
		HasN6:        s.HasN6,
		FlowRules:    flowRules,
		FlowTraffic:  flowTraffic,
		SUPI:         s.SUPI,
		DNN:          s.DNN,
		SNssai:       s.SNssai,
		QFI:          s.QFI,
		SessionType:  s.SessionType,
		SessionID:    s.SessionID,

		// Traffic
		BytesUL: s.BytesUL,
		BytesDL: s.BytesDL,

		// QoS
		GBRUplink:   s.GBRUplink,
		GBRDownlink: s.GBRDownlink,
		MBRUplink:   s.MBRUplink,
		MBRDownlink: s.MBRDownlink,

		// Status
		Status:              s.Status,
		Duration:            durationStr,
		LastActive:          lastActive,
		EstablishmentStatus: s.EstablishmentStatus,

		// Data Plane status
		DataPlaneStatus: s.DataPlaneStatus,
		LastPacketTime:  lastPacketTime,
	}
}

func handleSessionsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	allSessions := pfcpCorrelation.GetAllSessions()

	// Separate sessions by establishment status AND data plane status
	activeSessions := make([]SessionJSON, 0)  // Established + Active data plane
	staleSessions := make([]SessionJSON, 0)   // Established but no recent traffic
	failedSessions := make([]SessionJSON, 0)  // Failed establishment
	pendingSessions := make([]SessionJSON, 0) // Pending establishment
	unclassifiedSessions := make([]SessionJSON, 0)

	for _, s := range allSessions {
		sessionJSON := convertSessionToJSON(s)

		switch s.EstablishmentStatus {
		case pfcp.EstablishmentFailed:
			failedSessions = append(failedSessions, sessionJSON)
		case pfcp.EstablishmentPending:
			pendingSessions = append(pendingSessions, sessionJSON)
		case pfcp.EstablishmentEstablished:
			if s.DataPlaneStatus == pfcp.DataPlaneActive {
				activeSessions = append(activeSessions, sessionJSON)
			} else if s.DataPlaneStatus == pfcp.DataPlaneStale ||
				s.DataPlaneStatus == pfcp.DataPlaneInactive {
				staleSessions = append(staleSessions, sessionJSON)
			} else {
				unclassifiedSessions = append(unclassifiedSessions, sessionJSON)
			}
		default:
			unclassifiedSessions = append(unclassifiedSessions, sessionJSON)
		}
	}

	// Response structure:
	// - "total": count of data plane active sessions only
	// - "sessions": sessions with active data plane (have recent traffic)
	// - "stale_sessions": established but no recent traffic (possibly disconnected)
	// - "failed_sessions": failed establishments
	// - "pending_sessions": waiting for establishment confirmation
	// - "total_all": total count including all states
	response := map[string]interface{}{
		"total":                 len(activeSessions), // Only count data plane active for "Active Sessions" metric
		"sessions":              activeSessions,      // Sessions with active data plane
		"stale_sessions":        staleSessions,       // Established but no recent traffic
		"failed_sessions":       failedSessions,      // Failed establishments
		"pending_sessions":      pendingSessions,     // Still waiting for confirmation
		"unclassified_sessions": unclassifiedSessions,
		"total_all":             len(allSessions), // Total including all states
		"counts": map[string]int{
			"active":       len(activeSessions),
			"stale":        len(staleSessions),
			"failed":       len(failedSessions),
			"pending":      len(pendingSessions),
			"unclassified": len(unclassifiedSessions),
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handleDropTracingConfig handles enabling/disabling kernel drop tracing
func handleDropTracingConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == "GET" {
		// Return current status
		json.NewEncoder(w).Encode(map[string]interface{}{
			"drop_tracing_enabled": true, // We enable it by default now
			"message":              "Kernel drop tracing (kfree_skb) is active",
		})
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Enabled = true // Default to enable
	}

	if ebpfLoader == nil {
		http.Error(w, "eBPF loader not initialized", http.StatusInternalServerError)
		return
	}

	if err := ebpfLoader.EnableDropTracing(req.Enabled); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Failed to set drop tracing: %v", err),
		})
		return
	}

	state := "disabled"
	if req.Enabled {
		state = "enabled"
	}
	log.Printf("[CONFIG] Drop tracing %s", state)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Drop tracing %s", state),
		"enabled": req.Enabled,
	})
}

// handleInterfacesAPI returns information about network interfaces
// Useful for debugging and manual configuration
func handleInterfacesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Get the auto-detected interface
	autoDetected, reason := pfcp.AutoDetectInterface()

	response := map[string]interface{}{
		"requested_config": *pfcpIface,
		"current_config":   activePFCPInterface,
		"active_capture":   activePFCPInterface,
		"auto_detected":    autoDetected,
		"detection_reason": reason,
	}
	if r.URL.Query().Get("compact") != "1" {
		response["available_interfaces"] = pfcp.DetectAndListInterfaces()
		response["help"] = map[string]string{
			"auto":        "Use a named free5GC bridge when present, otherwise capture on any",
			"any":         "Capture from all interfaces (may include irrelevant traffic)",
			"br-free5gc":  "Docker bridge for free5gc-compose (common setup)",
			"lo":          "Loopback interface for native all-in-one free5GC",
			"<interface>": "Specify any interface name from the available_interfaces list",
		}
	}

	json.NewEncoder(w).Encode(response)
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

func updateSessionCount() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		count := pfcpCorrelation.SessionCount()
		activeSessions.Set(float64(count))
	}
}

func collectStats(loader *ebpf.Loader) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		uplink, downlink, err := loader.GetTrafficStats()
		if err != nil {
			log.Printf("Error getting stats: %v", err)
			continue
		}

		// Calculate deltas. eBPF maps are recreated when the agent restarts and
		// may also roll back an entry count when gtp5g reports a synchronous
		// drop. Never let a decreasing uint64 counter become a huge spike.
		uplinkPktDelta := monotonicCounterDelta(uplink.Packets, prevUplinkPackets)
		downlinkPktDelta := monotonicCounterDelta(downlink.Packets, prevDownlinkPackets)
		uplinkBytesDelta := monotonicCounterDelta(uplink.Bytes, prevUplinkBytes)
		downlinkBytesDelta := monotonicCounterDelta(downlink.Bytes, prevDownlinkBytes)

		// Update previous values
		prevUplinkPackets = uplink.Packets
		prevDownlinkPackets = downlink.Packets
		prevUplinkBytes = uplink.Bytes
		prevDownlinkBytes = downlink.Bytes

		// Update Prometheus counters
		if uplinkPktDelta > 0 {
			packetsTotal.WithLabelValues("uplink").Add(float64(uplinkPktDelta))
			bytesTotal.WithLabelValues("uplink").Add(float64(uplinkBytesDelta))
		}
		if downlinkPktDelta > 0 {
			packetsTotal.WithLabelValues("downlink").Add(float64(downlinkPktDelta))
			bytesTotal.WithLabelValues("downlink").Add(float64(downlinkBytesDelta))
		}

		// Update per-session stats from eBPF TEID counters
		updateSessionStatsFromEBPF(loader)

		// Print stats if there's activity
		if uplinkPktDelta > 0 || downlinkPktDelta > 0 {
			fmt.Printf("\rUL: %d pkts (%s)  DL: %d pkts (%s)          ",
				uplink.Packets, formatBytes(uplink.Bytes),
				downlink.Packets, formatBytes(downlink.Bytes))
		}
	}
}

func monotonicCounterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

// updateSessionStatsFromEBPF synchronizes hop-correlated flow observations.
// Global eBPF maps still drive global metrics, but TEID-only counters cannot
// safely be assigned to sessions when ULCL reuses a TEID across N3 and N9.
func updateSessionStatsFromEBPF(_ *ebpf.Loader) {
	pfcpCorrelation.RefreshSessionTrafficFromFlows()
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// Demo API handlers for testing purposes

// handleDemoInjectDrop injects a test drop event
func handleDemoInjectDrop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body or use defaults
	var req struct {
		Reason    string `json:"reason"`
		Direction string `json:"direction"`
		Count     int    `json:"count"`
	}
	req.Reason = "NO_PDR"
	req.Direction = "uplink"
	req.Count = 1

	json.NewDecoder(r.Body).Decode(&req)

	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 100 {
		req.Count = 100
	}

	// Realistic drop reasons with weighted probabilities
	// Direct 1:1 mapping with gtp5g error codes (codes 1-17)
	type dropReasonWeight struct {
		reason string
		weight int // Higher weight = more likely to occur
	}
	weightedReasons := []dropReasonWeight{
		// Common drops (high probability)
		{"NO_PDR", 25},    // Code 6: Most common - no matching PDR
		{"NO_F_TEID", 20}, // Code 11: Common - TEID not found
		{"NO_ROUTE", 15},  // Code 3: Common - routing issues
		{"GENERAL", 10},   // Code 7: Generic errors
		{"PDR_NULL", 8},   // Code 10: PDR pointer null

		// Moderately common drops
		{"INVALID_EXT_HDR", 5}, // Code 5: Extension header issues
		{"PULL_FAILED", 4},     // Code 4: skb_pull failed
		{"PULL_HDR_FAIL", 4},   // Code 16: Header pull failed
		{"IP_XMIT_FAIL", 3},    // Code 14: IP transmit failed
		{"NETIF_RX_FAIL", 3},   // Code 17: netif_rx failed

		// QoS related drops
		{"RED_PACKET", 5},     // Code 13: QoS RED drop
		{"UL_GATE_CLOSED", 3}, // Code 8: Uplink gate closed
		{"DL_GATE_CLOSED", 3}, // Code 9: Downlink gate closed

		// Rare drops
		{"NOT_TPDU", 2},         // Code 15: Not a T-PDU
		{"PKT_DROPPED", 1},      // Code 1: Generic drop
		{"ECHO_RESP_CREATE", 1}, // Code 2: Echo response failed
		{"URR_REPORT_FAIL", 1},  // Code 12: URR report failed
	}

	// Calculate total weight
	totalWeight := 0
	for _, wr := range weightedReasons {
		totalWeight += wr.weight
	}

	// Helper function to select weighted random reason
	selectWeightedReason := func() string {
		r := int(time.Now().UnixNano() % int64(totalWeight))
		cumulative := 0
		for _, wr := range weightedReasons {
			cumulative += wr.weight
			if r < cumulative {
				return wr.reason
			}
		}
		return "NO_PDR" // fallback
	}

	// Direction distribution: Uplink drops are slightly more common in real scenarios
	// (UE mobility, handover issues)
	selectDirection := func() string {
		if time.Now().UnixNano()%100 < 55 { // 55% uplink, 45% downlink
			return "uplink"
		}
		return "downlink"
	}

	// Realistic IP pools
	ueIPPool := "10.60.0." // UE IP pool (free5gc default)
	dnIPPools := []string{ // External destinations
		"8.8.8.",       // Google DNS
		"1.1.1.",       // Cloudflare
		"142.250.185.", // Google services
		"31.13.72.",    // Facebook
		"157.240.1.",   // Facebook
		"104.244.42.",  // Twitter
		"151.101.1.",   // Reddit/Fastly
	}

	for i := 0; i < req.Count; i++ {
		reason := req.Reason
		direction := req.Direction
		if reason == "random" || reason == "" {
			reason = selectWeightedReason()
		}
		if direction == "random" || direction == "" {
			direction = selectDirection()
		}

		// Generate realistic IPs based on direction
		var srcIP, dstIP string
		ueIP := fmt.Sprintf("%s%d", ueIPPool, 1+time.Now().UnixNano()%254)
		dnIP := fmt.Sprintf("%s%d", dnIPPools[time.Now().UnixNano()%int64(len(dnIPPools))], 1+time.Now().UnixNano()%254)

		if direction == "uplink" {
			srcIP = ueIP // UE -> DN
			dstIP = dnIP
		} else {
			srcIP = dnIP // DN -> UE
			dstIP = ueIP
		}

		// Generate realistic TEID (random 32-bit with some structure)
		// Real TEIDs are allocated by SMF, usually in a range per UPF
		teid := uint32(0x00000001 + time.Now().UnixNano()%0x0000FFFF)

		// Realistic port numbers
		var srcPort, dstPort uint16
		commonPorts := []uint16{80, 443, 8080, 53, 123, 5060, 3478}
		if direction == "uplink" {
			srcPort = uint16(49152 + time.Now().UnixNano()%16383) // Ephemeral port
			dstPort = commonPorts[time.Now().UnixNano()%int64(len(commonPorts))]
		} else {
			srcPort = commonPorts[time.Now().UnixNano()%int64(len(commonPorts))]
			dstPort = uint16(49152 + time.Now().UnixNano()%16383)
		}

		// Realistic packet sizes (based on common traffic patterns)
		// Small: DNS, SIP signaling; Medium: HTTP headers; Large: video streaming
		pktSizes := []uint32{64, 128, 256, 512, 576, 1024, 1280, 1400, 1460, 1500}
		pktLen := pktSizes[time.Now().UnixNano()%int64(len(pktSizes))]

		dropEvent := DropEventJSON{
			Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
			TEID:              fmt.Sprintf("0x%08x", teid),
			SrcIP:             srcIP,
			DstIP:             dstIP,
			SrcPort:           srcPort,
			DstPort:           dstPort,
			PktLen:            pktLen,
			Reason:            reason,
			Direction:         direction,
			Family:            "ipv4",
			Protocol:          "udp",
			Origin:            "demo",
			ValidFields:       []string{"teid", "src_ip", "dst_ip", "src_port", "dst_port"},
			Scope:             "user-plane",
			Classification:    "demo_user_plane",
			SessionCorrelated: true,
		}

		// Update metrics
		packetDropsTotal.WithLabelValues(reason, direction).Inc()

		// Store drop event
		dropEventsMu.Lock()
		recentDrops = append([]DropEventJSON{dropEvent}, recentDrops...)
		if len(recentDrops) > 100 {
			recentDrops = recentDrops[:100]
		}
		totalDrops++
		userPlaneDrops++
		dropsByReason[reason]++
		dropEventsMu.Unlock()

		log.Printf("[DEMO DROP] reason=%s direction=%s teid=%s", reason, direction, dropEvent.TEID)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Injected %d drop event(s)", req.Count),
	})
}

// handleDemoInjectSession injects a test session
func handleDemoInjectSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body - support both random and specific sessions
	var req struct {
		Count int `json:"count"`
		// For specific session injection
		ObservationID string   `json:"observation_id"`
		UEIP          string   `json:"ue_ip"`
		LocalFTEIDs   []string `json:"local_f_teids"`
		SUPI          string   `json:"supi"`
		// Extended session info
		DNN         string `json:"dnn"`
		SNssai      string `json:"s_nssai"`
		SessionType string `json:"session_type"`
		SessionID   uint8  `json:"pdu_session_id"`
		UPFIP       string `json:"upf_ip"`
		GNBIP       string `json:"gnb_ip"`
	}
	req.Count = 1

	json.NewDecoder(r.Body).Decode(&req)

	// If specific session info provided, use it
	if req.ObservationID != "" || req.UEIP != "" {
		var observationID uint64
		switch {
		case strings.HasPrefix(req.ObservationID, "obs-"):
			fmt.Sscanf(req.ObservationID, "obs-%x", &observationID)
		case strings.HasPrefix(req.ObservationID, "0x"):
			fmt.Sscanf(req.ObservationID, "0x%x", &observationID)
		case req.ObservationID != "":
			fmt.Sscanf(req.ObservationID, "%d", &observationID)
		}

		ueIP := net.ParseIP(req.UEIP)
		if ueIP == nil {
			http.Error(w, "demo session requires a valid ue_ip", http.StatusBadRequest)
			return
		}

		teids := make([]uint32, 0)
		for _, teidStr := range req.LocalFTEIDs {
			var teid uint32
			if len(teidStr) > 2 && teidStr[:2] == "0x" {
				fmt.Sscanf(teidStr, "0x%x", &teid)
			} else {
				fmt.Sscanf(teidStr, "%d", &teid)
			}
			if teid > 0 {
				teids = append(teids, teid)
			}
		}
		// Set defaults for extended fields
		dnn := req.DNN
		if dnn == "" {
			dnn = "internet"
		}
		sNssai := req.SNssai
		if sNssai == "" {
			sNssai = "SST:1, SD:010203"
		}
		sessionType := req.SessionType
		if sessionType == "" {
			sessionType = "IPv4"
		}
		session := &pfcp.Session{
			SEID:                observationID,
			Source:              "demo",
			UEIP:                ueIP,
			TEIDs:               teids,
			CreatedAt:           time.Now(),
			SUPI:                req.SUPI,
			DNN:                 dnn,
			SNssai:              sNssai,
			SessionType:         sessionType,
			SessionID:           req.SessionID,
			UPFIP:               net.ParseIP(req.UPFIP),
			GNBIP:               net.ParseIP(req.GNBIP),
			Status:              "Active",
			LastActive:          time.Now(),
			EstablishmentStatus: pfcp.EstablishmentEstablished,
			// Default QoS values for non-GBR
			MBRUplink:   100000, // 100 Mbps
			MBRDownlink: 100000,
		}

		pfcpCorrelation.AddSession(session)

		log.Printf("[INJECT SESSION] observation=obs-%x UEIP=%s local_FTEIDs=%v SUPI=%s DNN=%s",
			session.SEID, ueIP, teids, req.SUPI, dnn)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": "Injected specific session",
			"session": map[string]interface{}{
				"observation_id": fmt.Sprintf("obs-%x", session.SEID),
				"ue_ip":          ueIP.String(),
				"local_f_teids":  teids,
				"supi":           req.SUPI,
				"dnn":            dnn,
				"s_nssai":        sNssai,
				"session_type":   sessionType,
			},
		})
		return
	}

	// Random session generation with realistic 5G data
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 10 {
		req.Count = 10
	}

	dnns := []string{"internet", "ims", "mec", "iot"}
	slices := []string{"SST:1, SD:010203", "SST:1, SD:112233", "SST:2, SD:000001"}
	for i := 0; i < req.Count; i++ {
		seid := uint64(0x100000 + time.Now().UnixNano()%0xFFFFFF)
		teid1 := uint32(0x1000 + time.Now().UnixNano()%0xFFFF)
		teid2 := uint32(0x2000 + time.Now().UnixNano()%0xFFFF)
		ueIP := net.ParseIP(fmt.Sprintf("10.60.0.%d", 1+i+int(time.Now().UnixNano())%254))

		session := &pfcp.Session{
			SEID:                seid,
			Source:              "demo",
			UEIP:                ueIP,
			UPFIP:               net.ParseIP("10.200.200.101"),
			GNBIP:               net.ParseIP("10.200.200.1"),
			TEIDs:               []uint32{teid1, teid2},
			CreatedAt:           time.Now(),
			SUPI:                fmt.Sprintf("imsi-20893000000000%d", 1+i),
			DNN:                 dnns[time.Now().UnixNano()%int64(len(dnns))],
			SNssai:              slices[time.Now().UnixNano()%int64(len(slices))],
			SessionType:         "IPv4",
			SessionID:           uint8(1 + i),
			Status:              "Active",
			LastActive:          time.Now(),
			EstablishmentStatus: pfcp.EstablishmentEstablished,
			MBRUplink:           100000,
			MBRDownlink:         100000,
			PacketsUL:           uint64(time.Now().UnixNano() % 10000),
			PacketsDL:           uint64(time.Now().UnixNano() % 10000),
			BytesUL:             uint64(time.Now().UnixNano() % 10000000),
			BytesDL:             uint64(time.Now().UnixNano() % 10000000),
		}

		pfcpCorrelation.AddSession(session)

		log.Printf("[DEMO SESSION] SEID=0x%x UEIP=%s TEIDs=[0x%x, 0x%x] DNN=%s",
			seid, session.UEIP, teid1, teid2, session.DNN)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Injected %d session(s)", req.Count),
	})
}

// handleSyncSessions syncs sessions from free5GC logs or allows manual session creation
func handleSyncSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body for manual session creation
	var req struct {
		Sessions []struct {
			UPSEID      string   `json:"up_seid"`
			UEIP        string   `json:"ue_ip"`
			LocalFTEIDs []string `json:"local_f_teids"`
			SUPI        string   `json:"supi"`
		} `json:"sessions"`
		// Or auto-sync from free5GC log
		LogPath string `json:"log_path"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	syncedCount := 0

	// If manual sessions provided
	if len(req.Sessions) > 0 {
		for _, s := range req.Sessions {
			// Parse the explicitly supplied UP F-SEID.
			var upSEID uint64
			if len(s.UPSEID) > 2 && s.UPSEID[:2] == "0x" {
				fmt.Sscanf(s.UPSEID, "0x%x", &upSEID)
			} else {
				fmt.Sscanf(s.UPSEID, "%d", &upSEID)
			}

			// Parse explicitly supplied local F-TEIDs.
			teids := make([]uint32, 0)
			for _, teidStr := range s.LocalFTEIDs {
				var teid uint32
				if len(teidStr) > 2 && teidStr[:2] == "0x" {
					fmt.Sscanf(teidStr, "0x%x", &teid)
				} else {
					fmt.Sscanf(teidStr, "%d", &teid)
				}
				if teid > 0 {
					teids = append(teids, teid)
				}
			}

			session := &pfcp.Session{
				UPSEID:              upSEID,
				Source:              "manual",
				UEIP:                net.ParseIP(s.UEIP),
				TEIDs:               teids,
				CreatedAt:           time.Now(),
				EstablishmentStatus: pfcp.EstablishmentEstablished,
			}

			pfcpCorrelation.AddSession(session)
			syncedCount++

			log.Printf("[SYNC] Session added: UP_F-SEID=0x%x UEIP=%s local_FTEIDs=%v SUPI=%s",
				upSEID, s.UEIP, teids, s.SUPI)
		}
	}

	// If log path provided, try to parse sessions from free5GC log
	if req.LogPath != "" {
		parsed, err := parseSessionsFromLog(req.LogPath)
		if err != nil {
			log.Printf("[SYNC] Failed to parse log: %v", err)
		} else {
			for _, session := range parsed {
				pfcpCorrelation.AddSession(session)
				syncedCount++
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Synced %d session(s)", syncedCount),
		"total":   pfcpCorrelation.SessionCount(),
	})
}

// parseSessionsFromLog attempts to parse session info from free5GC log
func parseSessionsFromLog(logPath string) ([]*pfcp.Session, error) {
	sessions := make([]*pfcp.Session, 0)

	// This is a simplified parser - in production, you'd want more robust parsing
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Track current session info being built
	var currentSEID uint64
	var currentUEIP net.IP

	for _, line := range lines {
		// Look for SEID assignments
		if strings.Contains(line, "UPSEID=") || strings.Contains(line, "CPSEID=") {
			// Extract SEID value (e.g., UPSEID="0x1")
			if idx := strings.Index(line, "UPSEID=\"0x"); idx >= 0 {
				var seid uint64
				fmt.Sscanf(line[idx+10:], "%x", &seid)
				if seid > 0 {
					currentSEID = seid
				}
			}
		}

		// Look for UE IP allocation
		if strings.Contains(line, "Allocated UE IP address:") || strings.Contains(line, "Allocated PDUAdress") {
			// Extract IP (e.g., "10.60.0.1")
			parts := strings.Fields(line)
			for _, part := range parts {
				if ip := net.ParseIP(strings.Trim(part, "[]\"'")); ip != nil && ip.To4() != nil {
					// Check if it looks like a UE IP (10.60.x.x or 10.61.x.x)
					if strings.HasPrefix(ip.String(), "10.60.") || strings.HasPrefix(ip.String(), "10.61.") {
						currentUEIP = ip
					}
				}
			}
		}

		// If we have both SEID and UE IP, create session
		if currentSEID > 0 && currentUEIP != nil {
			session := &pfcp.Session{
				UPSEID:              currentSEID,
				Source:              "log",
				UEIP:                currentUEIP,
				CreatedAt:           time.Now(),
				EstablishmentStatus: pfcp.EstablishmentEstablished,
			}
			sessions = append(sessions, session)
			log.Printf("[SYNC] Parsed session from log: SEID=0x%x UEIP=%s", currentSEID, currentUEIP)

			// Reset for next session
			currentSEID = 0
			currentUEIP = nil
		}
	}

	return sessions, nil
}
