package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target amd64 upfMonitor ./bpf/upf_monitor.bpf.c

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Direction constants
const (
	DirectionUplink   = 0
	DirectionDownlink = 1
	DirectionUnknown  = 255
)

const (
	FieldTEID    uint16 = 1 << 0
	FieldSrcIP   uint16 = 1 << 1
	FieldDstIP   uint16 = 1 << 2
	FieldSrcPort uint16 = 1 << 3
	FieldDstPort uint16 = 1 << 4
)

const (
	OriginUnknown   = 0
	OriginTraceDrop = 1
	OriginEncapRecv = 2
	OriginDevXmit   = 3
	OriginKfreeSKB  = 4
	OriginIPForward = 5
)

// Drop reason constants - Direct mapping from gtp5g error codes (1:1)
// These match exactly with gtp5g/src/gtpu/encap.c definitions
const (
	DropReasonPktDropped     = 1   // Generic packet dropped
	DropReasonEchoRespCreate = 2   // GTP Echo Response creation failed
	DropReasonNoRoute        = 3   // No route to destination
	DropReasonPullFailed     = 4   // skb_pull failed
	DropReasonInvalidExtHdr  = 5   // Invalid GTP extension header
	DropReasonNoPDR          = 6   // No PDR rule matched
	DropReasonGeneral        = 7   // General error
	DropReasonULGateClosed   = 8   // Uplink gate closed (QoS)
	DropReasonDLGateClosed   = 9   // Downlink gate closed (QoS)
	DropReasonPDRNull        = 10  // PDR pointer is NULL
	DropReasonNoFTEID        = 11  // No F-TEID found
	DropReasonURRReportFail  = 12  // URR report failed
	DropReasonREDPacket      = 13  // QoS RED drop
	DropReasonIPXmitFail     = 14  // IP transmit failed
	DropReasonNotTPDU        = 15  // Not a T-PDU
	DropReasonPullHdrFail    = 16  // Header pull failed
	DropReasonNetifRxFail    = 17  // netif_rx failed
	DropReasonUnsupportedL3  = 18  // Unsupported L3 protocol
	DropReasonSKBPrepareFail = 19  // skb headroom preparation failed
	DropReasonFARMissing     = 20  // PDR has no FAR
	DropReasonInvalidFAR     = 21  // Unsupported FAR apply action
	DropReasonOHRMissing     = 22  // Outer Header Removal missing
	DropReasonOHCMissing     = 23  // Outer Header Creation missing
	DropReasonUnknown        = 255 // Unknown/other reasons
)

// TrafficCounter represents per-direction traffic statistics
type TrafficCounter struct {
	Packets   uint64
	Bytes     uint64
	Timestamp uint64
}

// DropEvent represents a packet drop event from kernel
type DropEvent struct {
	Timestamp   uint64
	TEID        uint32
	SrcIP       uint32
	DstIP       uint32
	PktLen      uint32
	SrcPort     uint16
	DstPort     uint16
	ValidFields uint16
	Reason      uint8
	Direction   uint8
	Family      uint8
	L4Protocol  uint8
	Origin      uint8
	ICMPType    uint8
	_           [4]byte // padding to the 40-byte C struct
}

// PacketEvent represents a packet event for detailed tracing
type PacketEvent struct {
	Timestamp  uint64
	TEID       uint32
	SrcIP      uint32
	DstIP      uint32
	InnerSrcIP uint32
	InnerDstIP uint32
	PktLen     uint32
	Direction  uint8
	QFI        uint8
	_          [2]byte // padding
}

// SessionInfo represents a PFCP session
type SessionInfo struct {
	SEID      uint64
	UEIP      uint32
	UPFIP     uint32
	CreatedAt uint64
}

// PDRLookupEvent represents a PDR lookup result from kernel
// This is emitted by fentry/fexit hooks on pdr_find_by_gtp1u and pdr_find_by_ipv4
type PDRLookupEvent struct {
	Timestamp uint64
	TEID      uint32
	PDRFound  bool // true if PDR was found
	Direction uint8
	LatencyNs uint64
}

// Loader manages eBPF program loading and lifecycle
type Loader struct {
	objs         *upfMonitorObjects
	links        []link.Link
	reader       *ringbuf.Reader
	packetReader *ringbuf.Reader
	pdrReader    *ringbuf.Reader // Ring buffer for PDR lookup events
	stopChan     chan struct{}

	// Callbacks for events
	OnDropEvent      func(event DropEvent)
	OnPacketEvent    func(event PacketEvent)
	OnPDRLookupEvent func(event PDRLookupEvent)
}

// NewLoader creates a new eBPF loader
func NewLoader() *Loader {
	return &Loader{
		stopChan: make(chan struct{}),
	}
}

// Load loads the eBPF programs and attaches them to hooks
func (l *Loader) Load() error {
	// Allow the current process to lock memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled eBPF programs
	l.objs = &upfMonitorObjects{}
	if err := loadUpfMonitorObjects(l.objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// =========================================================================
	// PRIMARY DROP DETECTION: gtp5g_trace_drop
	// This is the most reliable hook for detecting all types of drops
	// =========================================================================
	kpTraceDrop, err := link.Kprobe("gtp5g_trace_drop", l.objs.KprobeGtp5gTraceDrop, nil)
	if err != nil {
		log.Printf("Warning: failed to attach kprobe to gtp5g_trace_drop: %v", err)
		log.Printf("  -> This is the primary drop detection hook!")
		log.Printf("  -> Make sure gtp5g module is compiled with EXPORT_SYMBOL_GPL(gtp5g_trace_drop)")
		log.Printf("  -> Rebuild gtp5g: cd /path/to/gtp5g && make clean && make && sudo rmmod gtp5g && sudo insmod gtp5g.ko")
	} else {
		l.links = append(l.links, kpTraceDrop)
		log.Println("✓ Attached kprobe to gtp5g_trace_drop (PRIMARY drop detection)")
	}

	// =========================================================================
	// TRAFFIC STATISTICS: gtp5g_encap_recv and gtp5g_dev_xmit
	// =========================================================================

	// Attach kprobe to gtp5g_encap_recv
	kpEncapRecv, err := link.Kprobe("gtp5g_encap_recv", l.objs.KprobeGtp5gEncapRecv, nil)
	if err != nil {
		log.Printf("Warning: failed to attach kprobe to gtp5g_encap_recv: %v", err)
		log.Printf("Make sure gtp5g module is loaded: sudo insmod /path/to/gtp5g.ko")
	} else {
		l.links = append(l.links, kpEncapRecv)
		log.Println("✓ Attached kprobe to gtp5g_encap_recv (uplink traffic stats)")
	}
	krpEncapCleanup, err := link.Kretprobe("gtp5g_encap_recv", l.objs.KretprobeGtp5gEncapRecvCleanup, nil)
	if err != nil {
		log.Printf("Warning: failed to attach gtp5g_encap_recv context cleanup: %v", err)
	} else {
		l.links = append(l.links, krpEncapCleanup)
	}

	// Attach kprobe to gtp5g_dev_xmit
	kpDevXmit, err := link.Kprobe("gtp5g_dev_xmit", l.objs.KprobeGtp5gDevXmit, nil)
	if err != nil {
		log.Printf("Warning: failed to attach kprobe to gtp5g_dev_xmit: %v", err)
	} else {
		l.links = append(l.links, kpDevXmit)
		log.Println("✓ Attached kprobe to gtp5g_dev_xmit (downlink traffic stats)")
	}
	krpDevCleanup, err := link.Kretprobe("gtp5g_dev_xmit", l.objs.KretprobeGtp5gDevXmitCleanup, nil)
	if err != nil {
		log.Printf("Warning: failed to attach gtp5g_dev_xmit context cleanup: %v", err)
	} else {
		l.links = append(l.links, krpDevCleanup)
	}

	// =========================================================================
	// SECONDARY DROP DETECTION: PDR lookup failures
	// These catch drops before gtp5g_trace_drop is called in some code paths
	// =========================================================================

	// Attach kretprobe to pdr_find_by_gtp1u for NO_PDR_MATCH detection (uplink)
	krpPdrFindGtp1u, err := link.Kretprobe("pdr_find_by_gtp1u", l.objs.KretprobePdrFindByGtp1u, nil)
	if err != nil {
		log.Printf("Warning: failed to attach kretprobe to pdr_find_by_gtp1u: %v", err)
	} else {
		l.links = append(l.links, krpPdrFindGtp1u)
		log.Println("✓ Attached kretprobe to pdr_find_by_gtp1u (uplink PDR lookup)")
	}

	// Attach kretprobe to pdr_find_by_ipv4 for NO_PDR_MATCH detection (downlink)
	krpPdrFindIpv4, err := link.Kretprobe("pdr_find_by_ipv4", l.objs.KretprobePdrFindByIpv4, nil)
	if err != nil {
		log.Printf("Warning: failed to attach kretprobe to pdr_find_by_ipv4: %v", err)
	} else {
		l.links = append(l.links, krpPdrFindIpv4)
		log.Println("✓ Attached kretprobe to pdr_find_by_ipv4 (downlink PDR lookup)")
	}

	// =========================================================================
	// OPTIONAL: General kernel drop tracing (disabled by default)
	// Enable with loader.EnableDropTracing(true)
	// =========================================================================

	// Attach tracepoint for kfree_skb
	tpKfreeSkb, err := link.Tracepoint("skb", "kfree_skb", l.objs.TracepointKfreeSkb, nil)
	if err != nil {
		log.Printf("Warning: failed to attach tracepoint to kfree_skb: %v", err)
	} else {
		l.links = append(l.links, tpKfreeSkb)
		log.Println("✓ Attached tracepoint to skb/kfree_skb (general kernel drops, disabled by default)")
	}

	// Open ring buffer for drop events
	l.reader, err = ringbuf.NewReader(l.objs.DropEvents)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	// Open ring buffer for packet events
	l.packetReader, err = ringbuf.NewReader(l.objs.PacketEvents)
	if err != nil {
		return fmt.Errorf("failed to create packet ring buffer reader: %w", err)
	}

	// Open ring buffer for PDR lookup events (from fentry/fexit hooks)
	l.pdrReader, err = ringbuf.NewReader(l.objs.PdrEvents)
	if err != nil {
		log.Printf("Warning: failed to create PDR ring buffer reader: %v", err)
		// Not fatal - may not be available if fentry not supported
	} else {
		log.Println("✓ Opened PDR lookup events ring buffer")
	}

	return nil
}

// StartEventLoop starts processing events from ring buffers
func (l *Loader) StartEventLoop() {
	go l.readDropEvents()
	go l.readPacketEvents()
	if l.pdrReader != nil {
		go l.readPDREvents()
	}
}

func (l *Loader) readDropEvents() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
		}

		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		event, ok := decodeDropEvent(record.RawSample)
		if !ok {
			continue
		}

		if l.OnDropEvent != nil {
			l.OnDropEvent(event)
		}
	}
}

// decodeDropEvent must match struct drop_event in upf_monitor.bpf.c.
func decodeDropEvent(raw []byte) (DropEvent, bool) {
	if len(raw) < 36 {
		return DropEvent{}, false
	}

	return DropEvent{
		Timestamp:   binary.LittleEndian.Uint64(raw[0:8]),
		TEID:        binary.LittleEndian.Uint32(raw[8:12]),
		SrcIP:       binary.LittleEndian.Uint32(raw[12:16]),
		DstIP:       binary.LittleEndian.Uint32(raw[16:20]),
		PktLen:      binary.LittleEndian.Uint32(raw[20:24]),
		SrcPort:     binary.LittleEndian.Uint16(raw[24:26]),
		DstPort:     binary.LittleEndian.Uint16(raw[26:28]),
		ValidFields: binary.LittleEndian.Uint16(raw[28:30]),
		Reason:      raw[30],
		Direction:   raw[31],
		Family:      raw[32],
		L4Protocol:  raw[33],
		Origin:      raw[34],
		ICMPType:    raw[35],
	}, true
}

// GetTrafficStats retrieves current traffic statistics
func (l *Loader) GetTrafficStats() (uplink, downlink TrafficCounter, err error) {
	if l.objs == nil {
		return uplink, downlink, fmt.Errorf("eBPF objects not loaded")
	}

	// Read uplink stats
	uplinkKey := uint32(DirectionUplink)
	var uplinkCounters []TrafficCounter
	if err := l.objs.TrafficStats.Lookup(&uplinkKey, &uplinkCounters); err != nil {
		return uplink, downlink, fmt.Errorf("failed to read uplink stats: %w", err)
	}
	// Sum per-CPU values
	for _, c := range uplinkCounters {
		uplink.Packets += c.Packets
		uplink.Bytes += c.Bytes
		if c.Timestamp > uplink.Timestamp {
			uplink.Timestamp = c.Timestamp
		}
	}

	// Read downlink stats
	downlinkKey := uint32(DirectionDownlink)
	var downlinkCounters []TrafficCounter
	if err := l.objs.TrafficStats.Lookup(&downlinkKey, &downlinkCounters); err != nil {
		return uplink, downlink, fmt.Errorf("failed to read downlink stats: %w", err)
	}
	// Sum per-CPU values
	for _, c := range downlinkCounters {
		downlink.Packets += c.Packets
		downlink.Bytes += c.Bytes
		if c.Timestamp > downlink.Timestamp {
			downlink.Timestamp = c.Timestamp
		}
	}

	return uplink, downlink, nil
}

// GetTEIDStats retrieves traffic statistics for a specific TEID
func (l *Loader) GetTEIDStats(teid uint32) (TrafficCounter, error) {
	var counter TrafficCounter

	if l.objs == nil {
		return counter, fmt.Errorf("eBPF objects not loaded")
	}

	if err := l.objs.TeidStats.Lookup(&teid, &counter); err != nil {
		return counter, err // Not found is also an error
	}

	return counter, nil
}

// GetAllTEIDStats retrieves traffic statistics for all TEIDs
func (l *Loader) GetAllTEIDStats() (map[uint32]TrafficCounter, error) {
	result := make(map[uint32]TrafficCounter)

	if l.objs == nil {
		return result, fmt.Errorf("eBPF objects not loaded")
	}

	var key uint32
	var value TrafficCounter

	iter := l.objs.TeidStats.Iterate()
	for iter.Next(&key, &value) {
		result[key] = value
	}

	if err := iter.Err(); err != nil {
		return result, fmt.Errorf("failed to iterate teid_stats: %w", err)
	}

	return result, nil
}

// GetAllUEIPStats retrieves traffic statistics for all UE IPs (downlink)
func (l *Loader) GetAllUEIPStats() (map[uint32]TrafficCounter, error) {
	result := make(map[uint32]TrafficCounter)

	if l.objs == nil {
		return result, fmt.Errorf("eBPF objects not loaded")
	}

	var key uint32
	var value TrafficCounter

	iter := l.objs.UeIpStats.Iterate()
	for iter.Next(&key, &value) {
		result[key] = value
	}

	if err := iter.Err(); err != nil {
		return result, fmt.Errorf("failed to iterate ue_ip_stats: %w", err)
	}

	return result, nil
}

// UpdateSessionMapping adds or updates a TEID to session mapping
func (l *Loader) UpdateSessionMapping(teid uint32, session SessionInfo) error {
	if l.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	return l.objs.TeidSessionMap.Update(&teid, &session, ebpf.UpdateAny)
}

// DeleteSessionMapping removes a TEID to session mapping
func (l *Loader) DeleteSessionMapping(teid uint32) error {
	if l.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	return l.objs.TeidSessionMap.Delete(&teid)
}

// EnableDetailedTracing enables or disables detailed packet tracing
func (l *Loader) EnableDetailedTracing(enabled bool) error {
	if l.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	key := uint32(0)
	value := uint32(0)
	if enabled {
		value = 1
	}

	return l.objs.AgentConfig.Update(&key, &value, ebpf.UpdateAny)
}

// EnableDropTracing enables or disables kfree_skb drop tracing
func (l *Loader) EnableDropTracing(enabled bool) error {
	if l.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	key := uint32(1) // config key 1 = drop tracing
	value := uint32(0)
	if enabled {
		value = 1
	}

	return l.objs.AgentConfig.Update(&key, &value, ebpf.UpdateAny)
}

// Close cleans up resources
func (l *Loader) Close() {
	close(l.stopChan)

	if l.reader != nil {
		l.reader.Close()
	}

	if l.packetReader != nil {
		l.packetReader.Close()
	}

	if l.pdrReader != nil {
		l.pdrReader.Close()
	}

	for _, lnk := range l.links {
		lnk.Close()
	}

	if l.objs != nil {
		l.objs.Close()
	}
}

// FormatIP converts a uint32 IP to string
func FormatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// FormatDropReason converts drop reason code to string
// Direct 1:1 mapping with gtp5g error codes
func FormatDropReason(reason uint8) string {
	switch reason {
	case DropReasonPktDropped:
		return "PKT_DROPPED"
	case DropReasonEchoRespCreate:
		return "ECHO_RESP_CREATE"
	case DropReasonNoRoute:
		return "NO_ROUTE"
	case DropReasonPullFailed:
		return "PULL_FAILED"
	case DropReasonInvalidExtHdr:
		return "INVALID_EXT_HDR"
	case DropReasonNoPDR:
		return "NO_PDR"
	case DropReasonGeneral:
		return "GENERAL"
	case DropReasonULGateClosed:
		return "UL_GATE_CLOSED"
	case DropReasonDLGateClosed:
		return "DL_GATE_CLOSED"
	case DropReasonPDRNull:
		return "PDR_NULL"
	case DropReasonNoFTEID:
		return "NO_F_TEID"
	case DropReasonURRReportFail:
		return "URR_REPORT_FAIL"
	case DropReasonREDPacket:
		return "RED_PACKET"
	case DropReasonIPXmitFail:
		return "IP_XMIT_FAIL"
	case DropReasonNotTPDU:
		return "NOT_TPDU"
	case DropReasonPullHdrFail:
		return "PULL_HDR_FAIL"
	case DropReasonNetifRxFail:
		return "NETIF_RX_FAIL"
	case DropReasonUnsupportedL3:
		return "UNSUPPORTED_L3"
	case DropReasonSKBPrepareFail:
		return "SKB_PREPARE_FAIL"
	case DropReasonFARMissing:
		return "FAR_MISSING"
	case DropReasonInvalidFAR:
		return "INVALID_FAR_ACTION"
	case DropReasonOHRMissing:
		return "OHR_MISSING"
	case DropReasonOHCMissing:
		return "OHC_MISSING"
	default:
		return "UNKNOWN"
	}
}

// FormatDirection converts direction code to string
func FormatDirection(direction uint8) string {
	switch direction {
	case DirectionUplink:
		return "uplink"
	case DirectionDownlink:
		return "downlink"
	default:
		return "unknown"
	}
}

// FormatFamily converts the parsed IP version to an API value.
func FormatFamily(family uint8) string {
	switch family {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// FormatProtocol converts an IP protocol number to a stable display value.
func FormatProtocol(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return "unknown"
	}
}

// FormatOrigin identifies the hook which supplied reliable packet context.
func FormatOrigin(origin uint8) string {
	switch origin {
	case OriginTraceDrop:
		return "gtp5g_trace_drop"
	case OriginEncapRecv:
		return "gtp5g_encap_recv"
	case OriginDevXmit:
		return "gtp5g_dev_xmit"
	case OriginKfreeSKB:
		return "kfree_skb"
	case OriginIPForward:
		return "ip_forward"
	default:
		return "unknown"
	}
}

// HasField reports whether a packet field was successfully parsed.
func (event DropEvent) HasField(field uint16) bool {
	return event.ValidFields&field != 0
}

// FormatTimestamp converts nanosecond timestamp to time.Time
func FormatTimestamp(ns uint64) time.Time {
	return time.Unix(0, int64(ns))
}

func (l *Loader) readPacketEvents() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
		}

		record, err := l.packetReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading from packet ring buffer: %v", err)
			continue
		}

		event, ok := decodePacketEvent(record.RawSample)
		if !ok {
			continue
		}

		if l.OnPacketEvent != nil {
			l.OnPacketEvent(event)
		}
	}
}

// decodePacketEvent must match struct packet_event in upf_monitor.bpf.c.
// The C struct has 36 meaningful bytes and is padded to 40 bytes.
func decodePacketEvent(raw []byte) (PacketEvent, bool) {
	if len(raw) < 36 {
		return PacketEvent{}, false
	}

	return PacketEvent{
		Timestamp:  binary.LittleEndian.Uint64(raw[0:8]),
		TEID:       binary.LittleEndian.Uint32(raw[8:12]),
		SrcIP:      binary.LittleEndian.Uint32(raw[12:16]),
		DstIP:      binary.LittleEndian.Uint32(raw[16:20]),
		InnerSrcIP: binary.LittleEndian.Uint32(raw[20:24]),
		InnerDstIP: binary.LittleEndian.Uint32(raw[24:28]),
		PktLen:     binary.LittleEndian.Uint32(raw[28:32]),
		Direction:  raw[32],
		QFI:        raw[33],
	}, true
}

// readPDREvents reads PDR lookup events from the ring buffer
func (l *Loader) readPDREvents() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
		}

		record, err := l.pdrReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading from PDR ring buffer: %v", err)
			continue
		}

		// Parse PDR lookup event
		// struct size: timestamp(8) + teid(4) + pdr_found(1) + direction(1) + pad(2) + latency(8) = 24 bytes
		if len(record.RawSample) < 24 {
			continue
		}

		event := PDRLookupEvent{
			Timestamp: binary.LittleEndian.Uint64(record.RawSample[0:8]),
			TEID:      binary.LittleEndian.Uint32(record.RawSample[8:12]),
			PDRFound:  record.RawSample[12] == 1,
			Direction: record.RawSample[13],
			LatencyNs: binary.LittleEndian.Uint64(record.RawSample[16:24]),
		}

		if l.OnPDRLookupEvent != nil {
			l.OnPDRLookupEvent(event)
		}
	}
}
