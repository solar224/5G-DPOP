package pfcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PFCP Message Types (3GPP TS 29.244)
const (
	MsgTypeHeartbeatRequest             = 1
	MsgTypeHeartbeatResponse            = 2
	MsgTypeSessionEstablishmentRequest  = 50
	MsgTypeSessionEstablishmentResponse = 51
	MsgTypeSessionModificationRequest   = 52
	MsgTypeSessionModificationResponse  = 53
	MsgTypeSessionDeletionRequest       = 54
	MsgTypeSessionDeletionResponse      = 55
	MsgTypeSessionReportRequest         = 56
	MsgTypeSessionReportResponse        = 57
)

// PFCP IE Types (3GPP TS 29.244)
const (
	IETypeCreatePDR            = 1   // Create PDR
	IETypePDI                  = 2   // PDI (Packet Detection Information)
	IETypeCreateFAR            = 3   // Create FAR
	IETypeForwardingParameters = 4   // Forwarding Parameters
	IETypeCreatedPDR           = 8   // Created PDR
	IETypeUpdatePDR            = 9   // Update PDR
	IETypeUpdateFAR            = 10  // Update FAR
	IETypeUpdateForwarding     = 11  // Update Forwarding Parameters
	IETypeRemovePDR            = 15  // Remove PDR
	IETypeRemoveFAR            = 16  // Remove FAR
	IETypeCreateURR            = 6   // Create URR
	IETypeCreateQER            = 7   // Create QER
	IETypeCause                = 19  // Cause
	IETypeSourceInterface      = 20  // Source Interface
	IETypeFTEID                = 21  // F-TEID
	IETypeNetworkInstance      = 22  // Network Instance (DNN)
	IETypeSDFFilter            = 23  // SDF Filter
	IETypeApplicationID        = 24  // Application ID
	IETypeDestinationInterface = 42  // Destination Interface
	IETypeApplyAction          = 44  // Apply Action
	IETypePDRID                = 56  // PDR ID
	IETypeFSEID                = 57  // F-SEID (Fully Qualified SEID)
	IETypeFARID                = 108 // FAR ID

	IETypeGateStatus          = 25  // Gate Status
	IETypeMBR                 = 26  // MBR (Maximum Bit Rate)
	IETypeGBR                 = 27  // GBR (Guaranteed Bit Rate)
	IETypeQERCorrelationID    = 28  // QER Correlation ID
	IETypePrecedence          = 29  // Precedence
	IETypePDNType             = 113 // PDN Type
	IETypeOuterHeaderRemoval  = 95  // Outer Header Removal
	IETypeOuterHeaderCreation = 84  // Outer Header Creation
	IETypeUEIPAddr            = 93  // UE IP Address
	IETypeQFI                 = 124 // QFI (QoS Flow Identifier)
	IETypeSNSSAI              = 257 // S-NSSAI (Network Slice Selection Assistance Information)
	IEType3GPPInterfaceType   = 160 // 3GPP Interface Type
)

// ForwardingRule is the FAR state needed to reconstruct a packet path. It is
// retained separately because later PFCP Update PDR/FAR messages may carry only
// one side of the PDR -> FAR relationship.
type ForwardingRule struct {
	FARID                uint32
	ApplyAction          uint8
	DestinationInterface int
	InterfaceType        int
	NetworkInstance      string
	OuterDst             net.IP
	OuterTEID            uint32
}

// FlowRule is one observed PFCP PDR joined to its FAR. DestinationSelector is
// derived from a decoded SDF filter. SDFObserved distinguishes a PDR with no
// SDF from one whose SDF was present but could not be decoded.
type FlowRule struct {
	PDRID                uint16
	FARID                uint32
	Precedence           uint32
	SourceInterface      int
	SourceInterfaceType  int
	DestinationInterface int
	InterfaceType        int
	LocalFTEID           uint32
	LocalFTEIDIP         net.IP
	SDFObserved          bool
	SDF                  string
	DestinationSelector  string
	PDINetworkInstance   string
	NetworkInstance      string
	OuterDst             net.IP
	OuterTEID            uint32
	PathType             string
}

type CreatedPDRFTEID struct {
	PDRID uint16
	TEID  uint32
	IP    net.IP
}

// FlowTraffic is flow-level PDU observation from the eBPF GTP-U hook. Counters
// are local to one UPF session/hop; they must not be summed across UPFs as
// end-to-end UE volume.
type FlowTraffic struct {
	DestIP     net.IP
	Packets    uint64
	Bytes      uint64
	LastActive time.Time
	OuterSrc   net.IP
	OuterDst   net.IP
	Direction  string
}

// Establishment status constants
const (
	EstablishmentPending     = "Pending"     // Session Establishment Request received, waiting for completion
	EstablishmentEstablished = "Established" // Successful establishment response or later modification received
	EstablishmentFailed      = "Failed"      // Session timed out without completion (likely N1N2 failure)
)

// Data Plane status constants - based on actual traffic activity
const (
	DataPlaneActive   = "Active"   // Has recent packet activity
	DataPlaneStale    = "Stale"    // No packets for longer than StaleTimeout
	DataPlaneInactive = "Inactive" // No packets seen yet (newly established)
)

// StaleTimeout defines how long without packets before a session is considered stale
const StaleTimeout = 60 * time.Second

// Session represents one observed PFCP session on one UPF.
//
// SEID is deliberately retained as an internal observation ID because it is
// used throughout the in-memory indexes. It is not a PFCP SEID and must never
// be exposed to users as one. CPSEID and UPSEID are the two endpoint-selected
// PFCP F-SEIDs observed on N4.
type Session struct {
	SEID            uint64
	CPSEID          uint64
	UPSEID          uint64
	Source          string
	UEIP            net.IP
	UPFIP           net.IP
	UPFN3IP         net.IP   // Local UPF GTP-U endpoint observed on N3
	GNBIP           net.IP   // Downlink Peer IP (gNB for N3)
	AccessPeerIP    net.IP   // Access-side peer; resolved as gNB or UPF by topology correlation
	UplinkPeerIP    net.IP   // Uplink Peer IP (gNB or prev UPF)
	N9PeerIP        net.IP   // N9 Peer UPF IP (for ULCL: i-upf <-> psa-upf)
	N9Direction     string   // "towards-core" or "towards-access"
	N9Evidence      string   // PFCP evidence used to classify the N9 peer
	HasN6           bool     // PFCP FAR forwards to SGi-LAN/N6-LAN
	TEIDs           []uint32 // Associated GTP TEIDs
	CreatedAt       time.Time
	ModifiedAt      time.Time
	PDRCount        int
	FARCount        int
	ForwardingRules []ForwardingRule
	FlowRules       []FlowRule
	FlowTraffic     []FlowTraffic

	// Extended session info
	SUPI        string // Subscriber Permanent ID (IMSI)
	DNN         string // Data Network Name (APN)
	SNssai      string // S-NSSAI (Network Slice)
	QFI         uint8  // QoS Flow Identifier
	SessionType string // IPv4, IPv6, IPv4v6
	SessionID   uint8  // PDU Session ID

	// Traffic statistics
	BytesUL   uint64
	BytesDL   uint64
	PacketsUL uint64
	PacketsDL uint64

	// QoS parameters
	GBRUplink   uint64 // Guaranteed Bit Rate UL (kbps)
	GBRDownlink uint64 // Guaranteed Bit Rate DL (kbps)
	MBRUplink   uint64 // Maximum Bit Rate UL (kbps)
	MBRDownlink uint64 // Maximum Bit Rate DL (kbps)

	// Status
	Status     string // Active, Idle, Releasing
	LastActive time.Time

	// Establishment tracking - distinguishes successful vs failed session establishments
	EstablishmentStatus string    // Pending, Established, Failed
	EstablishmentTime   time.Time // When establishment was first attempted

	// Data Plane status tracking - based on actual packet activity
	DataPlaneStatus string    // Active, Stale, Inactive
	LastPacketTime  time.Time // Last time a packet was seen (UL or DL)
}

// IsDataPlaneActive returns true if the session has an active data plane
// This method provides a comprehensive check combining multiple conditions:
// 1. Session must be in Established state
// 2. Must have recent packet activity (within StaleTimeout)
// 3. Must have at least one valid TEID (indicating GTP tunnel exists)
func (s *Session) IsDataPlaneActive() bool {
	// Condition 1: EstablishmentStatus must be Established
	if s.EstablishmentStatus != EstablishmentEstablished {
		return false
	}

	// Condition 2: Must have recent packet activity (within StaleTimeout)
	if s.LastPacketTime.IsZero() || time.Since(s.LastPacketTime) > StaleTimeout {
		return false
	}

	// Condition 3: Must have at least one valid TEID (GTP tunnel exists)
	hasValidTEID := false
	for _, teid := range s.TEIDs {
		if teid > 0 {
			hasValidTEID = true
			break
		}
	}

	return hasValidTEID
}

// HasValidGTPTunnel returns true if the session has at least one valid TEID
func (s *Session) HasValidGTPTunnel() bool {
	for _, teid := range s.TEIDs {
		if teid > 0 {
			return true
		}
	}
	return false
}

// Correlation manages the mapping between sessions and TEIDs
type Correlation struct {
	mu          sync.RWMutex
	sessions    map[uint64]*Session // observation ID -> Session
	teidMap     map[uint32]uint64   // local F-TEID -> observation ID
	ueIPMap     map[string]uint64   // UE IP + local UPF -> latest observation ID
	cpSEIDMap   map[string]uint64   // local UPF + CP F-SEID -> observation ID
	upSEIDMap   map[string]uint64   // local UPF + UP F-SEID -> observation ID
	seidCounter uint64              // counter for internal observation IDs
	// Track session creation timestamps to handle race conditions
	sessionCreationTime map[string]time.Time // UE IP + local UPF -> creation time
	// Timeout checker
	stopChan chan struct{}
}

// EstablishmentTimeout is the time to wait for a successful establishment
// response (or a later modification when the response was not captured).
const EstablishmentTimeout = 10 * time.Second

// NewCorrelation creates a new correlation store
func NewCorrelation() *Correlation {
	c := &Correlation{
		sessions:            make(map[uint64]*Session),
		teidMap:             make(map[uint32]uint64),
		ueIPMap:             make(map[string]uint64),
		cpSEIDMap:           make(map[string]uint64),
		upSEIDMap:           make(map[string]uint64),
		seidCounter:         0,
		sessionCreationTime: make(map[string]time.Time),
		stopChan:            make(chan struct{}),
	}
	// Start the establishment timeout checker
	go c.establishmentTimeoutChecker()
	// Start the data plane status checker
	go c.dataPlaneStatusChecker()
	return c
}

// establishmentTimeoutChecker periodically checks for pending sessions that have timed out
func (c *Correlation) establishmentTimeoutChecker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.checkEstablishmentTimeouts()
		}
	}
}

// checkEstablishmentTimeouts marks sessions as Failed if they've been Pending too long
func (c *Correlation) checkEstablishmentTimeouts() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for seid, session := range c.sessions {
		if session.EstablishmentStatus == EstablishmentPending {
			if now.Sub(session.EstablishmentTime) > EstablishmentTimeout {
				log.Printf("[PFCP] Session SEID=0x%x (UE IP=%s) marked as Failed - no successful establishment response or modification received within %v",
					seid, session.UEIP, EstablishmentTimeout)
				session.EstablishmentStatus = EstablishmentFailed
				session.Status = "Failed"
			}
		}
	}
}

// Stop stops the correlation checker
func (c *Correlation) Stop() {
	close(c.stopChan)
}

// dataPlaneStatusChecker periodically checks for stale sessions based on packet activity
func (c *Correlation) dataPlaneStatusChecker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.checkDataPlaneStatus()
		}
	}
}

// checkDataPlaneStatus updates DataPlaneStatus based on LastPacketTime
func (c *Correlation) checkDataPlaneStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for _, session := range c.sessions {
		// Only check established sessions
		if session.EstablishmentStatus != EstablishmentEstablished {
			continue
		}

		// If no packet has ever been seen
		if session.LastPacketTime.IsZero() {
			session.DataPlaneStatus = DataPlaneInactive
			continue
		}

		// Check if stale (no packets for longer than StaleTimeout)
		if now.Sub(session.LastPacketTime) > StaleTimeout {
			if session.DataPlaneStatus != DataPlaneStale {
				log.Printf("[PFCP] Session SEID=0x%x (UE IP=%s) marked as Stale - no packets for %v",
					session.SEID, session.UEIP, now.Sub(session.LastPacketTime).Round(time.Second))
			}
			session.DataPlaneStatus = DataPlaneStale
		} else {
			session.DataPlaneStatus = DataPlaneActive
		}
	}
}

// UpdatePacketActivity updates the LastPacketTime for a session identified by TEID
// Called when eBPF detects packet activity on a GTP tunnel
func (c *Correlation) UpdatePacketActivity(teid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if seid, ok := c.teidMap[teid]; ok {
		if session, ok := c.sessions[seid]; ok {
			session.LastPacketTime = time.Now()
			session.DataPlaneStatus = DataPlaneActive
			session.LastActive = session.LastPacketTime
		}
	}
}

// UpdatePacketActivityByUEIP updates the LastPacketTime for a session identified by UE IP
func (c *Correlation) UpdatePacketActivityByUEIP(ueIP string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, session := range c.sessions {
		if session.UEIP != nil && session.UEIP.String() == ueIP {
			session.LastPacketTime = time.Now()
			session.DataPlaneStatus = DataPlaneActive
			session.LastActive = session.LastPacketTime
		}
	}
}

// GetDataPlaneActiveSessions returns sessions with active data plane (recent packets)
func (c *Correlation) GetDataPlaneActiveSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0)
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentEstablished &&
			s.DataPlaneStatus == DataPlaneActive {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// GetStaleSessions returns sessions that are established but have no recent traffic
func (c *Correlation) GetStaleSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0)
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentEstablished &&
			(s.DataPlaneStatus == DataPlaneStale || s.DataPlaneStatus == DataPlaneInactive) {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// DataPlaneActiveCount returns count of sessions with active data plane
func (c *Correlation) DataPlaneActiveCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentEstablished &&
			s.DataPlaneStatus == DataPlaneActive {
			count++
		}
	}
	return count
}

// StaleSessionCount returns count of stale sessions
func (c *Correlation) StaleSessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentEstablished &&
			(s.DataPlaneStatus == DataPlaneStale || s.DataPlaneStatus == DataPlaneInactive) {
			count++
		}
	}
	return count
}

// UpdateFromPDRLookupEvent updates session status based on PDR lookup result from eBPF
// This is called when fentry/fexit hooks detect PDR lookup activity
// pdrFound: true if PDR was found in gtp5g, false if not
// teid: the TEID being looked up (for uplink)
// direction: 0 = uplink (by TEID), 1 = downlink (by IP)
func (c *Correlation) UpdateFromPDRLookupEvent(pdrFound bool, teid uint32, direction uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// For uplink, we can look up session by TEID
	if direction == 0 && teid > 0 {
		if seid, ok := c.teidMap[teid]; ok {
			if session, ok := c.sessions[seid]; ok {
				if pdrFound {
					// PDR found = data plane is working
					session.DataPlaneStatus = DataPlaneActive
					session.LastPacketTime = time.Now()
					session.LastActive = session.LastPacketTime
				} else {
					// PDR not found but TEID exists = control/data plane mismatch
					if session.DataPlaneStatus != DataPlaneStale {
						log.Printf("[PFCP] Session SEID=0x%x TEID=0x%x: PDR not found in gtp5g (control/data plane mismatch)",
							seid, teid)
					}
				}
			}
		}
	}
}

// ValidateSessionsAgainstGtp5g validates sessions against gtp5g kernel state
// Returns a list of sessions with validation discrepancies
func (c *Correlation) ValidateSessionsAgainstGtp5g(activeTEIDs map[uint32]bool) []uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	invalidSEIDs := make([]uint64, 0)

	for seid, session := range c.sessions {
		if session.EstablishmentStatus != EstablishmentEstablished {
			continue
		}

		// Check if any of the session's TEIDs are present in gtp5g
		hasActiveGtp5gTEID := false
		for _, teid := range session.TEIDs {
			if activeTEIDs[teid] {
				hasActiveGtp5gTEID = true
				break
			}
		}

		if !hasActiveGtp5gTEID && len(session.TEIDs) > 0 {
			// Session claims to be established but TEIDs not in gtp5g
			invalidSEIDs = append(invalidSEIDs, seid)
		}
	}

	return invalidSEIDs
}

// getNextSEID generates an internal observation ID. The historical name is
// retained to keep the refactor local; the value is not a PFCP SEID.
func (c *Correlation) getNextSEID() uint64 {
	c.seidCounter++
	return c.seidCounter
}

func sessionLookupKey(ueIP string, upfIP net.IP) string {
	upf := "unknown"
	if upfIP != nil {
		upf = upfIP.String()
	}
	return ueIP + "|" + upf
}

func pfcpSEIDLookupKey(upfIP net.IP, seid uint64) string {
	upf := "unknown"
	if upfIP != nil {
		upf = upfIP.String()
	}
	return fmt.Sprintf("%s|%016x", upf, seid)
}

func (c *Correlation) registerSessionIdentitiesLocked(session *Session) {
	if session == nil || session.SEID == 0 {
		return
	}
	if session.CPSEID != 0 {
		c.cpSEIDMap[pfcpSEIDLookupKey(session.UPFIP, session.CPSEID)] = session.SEID
	}
	if session.UPSEID != 0 {
		c.upSEIDMap[pfcpSEIDLookupKey(session.UPFIP, session.UPSEID)] = session.SEID
	}
}

func (c *Correlation) removeSessionLocked(observationID uint64) bool {
	session, ok := c.sessions[observationID]
	if !ok {
		return false
	}
	for _, teid := range session.TEIDs {
		if mapped, exists := c.teidMap[teid]; exists && mapped == observationID {
			delete(c.teidMap, teid)
		}
	}
	if session.UEIP != nil {
		key := sessionLookupKey(session.UEIP.String(), session.UPFIP)
		if mapped, exists := c.ueIPMap[key]; exists && mapped == observationID {
			delete(c.ueIPMap, key)
			delete(c.sessionCreationTime, key)
		}
	}
	if session.CPSEID != 0 {
		key := pfcpSEIDLookupKey(session.UPFIP, session.CPSEID)
		if mapped, exists := c.cpSEIDMap[key]; exists && mapped == observationID {
			delete(c.cpSEIDMap, key)
		}
	}
	if session.UPSEID != 0 {
		key := pfcpSEIDLookupKey(session.UPFIP, session.UPSEID)
		if mapped, exists := c.upSEIDMap[key]; exists && mapped == observationID {
			delete(c.upSEIDMap, key)
		}
	}
	delete(c.sessions, observationID)
	return true
}

func samePFCPIdentity(existing, incoming *Session) bool {
	if existing == nil || incoming == nil {
		return false
	}
	if existing.CPSEID != 0 && incoming.CPSEID != 0 {
		return existing.CPSEID == incoming.CPSEID
	}
	if existing.UPSEID != 0 && incoming.UPSEID != 0 {
		return existing.UPSEID == incoming.UPSEID
	}
	// An update captured without either F-SEID may still be merged by its
	// internal ID or UE+UPF key. Two different known identities never reach
	// this fallback.
	return true
}

func (c *Correlation) findSameSessionLocked(session *Session) (*Session, bool) {
	if session.SEID != 0 {
		if existing, ok := c.sessions[session.SEID]; ok {
			return existing, true
		}
	}
	if session.CPSEID != 0 {
		if observationID, ok := c.cpSEIDMap[pfcpSEIDLookupKey(session.UPFIP, session.CPSEID)]; ok {
			if existing, exists := c.sessions[observationID]; exists {
				return existing, true
			}
		}
	}
	if session.UPSEID != 0 {
		if observationID, ok := c.upSEIDMap[pfcpSEIDLookupKey(session.UPFIP, session.UPSEID)]; ok {
			if existing, exists := c.sessions[observationID]; exists {
				return existing, true
			}
		}
	}
	if session.UEIP == nil {
		return nil, false
	}
	if observationID, ok := c.ueIPMap[sessionLookupKey(session.UEIP.String(), session.UPFIP)]; ok {
		if existing, exists := c.sessions[observationID]; exists && samePFCPIdentity(existing, session) {
			return existing, true
		}
	}
	return nil, false
}

func (c *Correlation) mergeSessionLocked(existing, incoming *Session) {
	if existing.CPSEID == 0 && incoming.CPSEID != 0 {
		existing.CPSEID = incoming.CPSEID
	}
	if existing.UPSEID == 0 && incoming.UPSEID != 0 {
		existing.UPSEID = incoming.UPSEID
	}
	if existing.Source == "" && incoming.Source != "" {
		existing.Source = incoming.Source
	}

	teidSet := make(map[uint32]bool, len(existing.TEIDs))
	for _, teid := range existing.TEIDs {
		teidSet[teid] = true
	}
	for _, teid := range incoming.TEIDs {
		if teid != 0 && !teidSet[teid] {
			existing.TEIDs = append(existing.TEIDs, teid)
			c.teidMap[teid] = existing.SEID
			teidSet[teid] = true
		}
	}

	if incoming.DNN != "" {
		existing.DNN = incoming.DNN
	}
	if incoming.QFI != 0 {
		existing.QFI = incoming.QFI
	}
	if incoming.UPFIP != nil {
		existing.UPFIP = cloneIP(incoming.UPFIP)
	}
	if incoming.UPFN3IP != nil {
		existing.UPFN3IP = cloneIP(incoming.UPFN3IP)
	}
	if incoming.GNBIP != nil {
		existing.GNBIP = cloneIP(incoming.GNBIP)
	}
	if incoming.AccessPeerIP != nil {
		existing.AccessPeerIP = cloneIP(incoming.AccessPeerIP)
	}
	if incoming.N9PeerIP != nil {
		existing.N9PeerIP = cloneIP(incoming.N9PeerIP)
		existing.N9Direction = incoming.N9Direction
		existing.N9Evidence = incoming.N9Evidence
	}
	existing.HasN6 = existing.HasN6 || incoming.HasN6
	if len(incoming.ForwardingRules) > 0 {
		existing.ForwardingRules = append([]ForwardingRule(nil), incoming.ForwardingRules...)
	}
	if len(incoming.FlowRules) > 0 {
		existing.FlowRules = append([]FlowRule(nil), incoming.FlowRules...)
	}
	if len(incoming.FlowTraffic) > 0 {
		existing.FlowTraffic = append([]FlowTraffic(nil), incoming.FlowTraffic...)
	}
	if incoming.MBRUplink > 0 {
		existing.MBRUplink = incoming.MBRUplink
	}
	if incoming.MBRDownlink > 0 {
		existing.MBRDownlink = incoming.MBRDownlink
	}
	if incoming.ModifiedAt.After(existing.ModifiedAt) {
		existing.ModifiedAt = incoming.ModifiedAt
	}
	if incoming.EstablishmentStatus != "" {
		existing.EstablishmentStatus = incoming.EstablishmentStatus
	}
	if incoming.Status != "" {
		existing.Status = incoming.Status
	}
	existing.LastActive = time.Now()
	c.registerSessionIdentitiesLocked(existing)
}

// AddSession adds or updates a session
// PFCP identities take precedence over UE IP so a re-established PDU session
// cannot be silently merged with an older session that reused the same UE IP.
func (c *Correlation) AddSession(session *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if session.UEIP == nil {
		log.Printf("[WARN] AddSession: session without UE IP, skipping (observation=0x%x)", session.SEID)
		return
	}

	if existing, ok := c.findSameSessionLocked(session); ok {
		c.mergeSessionLocked(existing, session)
		return
	}

	if session.SEID == 0 {
		session.SEID = c.getNextSEID()
	} else if session.SEID > c.seidCounter {
		c.seidCounter = session.SEID
	}
	if session.Source == "" {
		session.Source = "pfcp"
	}
	ueIPStr := session.UEIP.String()
	sessionKey := sessionLookupKey(ueIPStr, session.UPFIP)
	c.ueIPMap[sessionKey] = session.SEID
	c.sessionCreationTime[sessionKey] = time.Now()
	c.sessions[session.SEID] = session
	c.registerSessionIdentitiesLocked(session)
	for _, teid := range session.TEIDs {
		if teid != 0 {
			c.teidMap[teid] = session.SEID
		}
	}

	log.Printf("[DEBUG] AddSession: New observation=0x%x for UE IP %s (total sessions: %d)",
		session.SEID, ueIPStr, len(c.sessions))
}

// RemoveSession removes a session
func (c *Correlation) RemoveSession(observationID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.removeSessionLocked(observationID) {
		log.Printf("[DEBUG] RemoveSession: Removed observation=0x%x (total sessions: %d)",
			observationID, len(c.sessions))
	}
}

// RegisterUPSEID records a UPF-selected F-SEID observed in a request header or
// Session Establishment Response.
func (c *Correlation) RegisterUPSEID(upfIP net.IP, upSEID, observationID uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	session, ok := c.sessions[observationID]
	if !ok || upSEID == 0 {
		return false
	}
	if session.UPSEID != 0 && session.UPSEID != upSEID {
		log.Printf("[PFCP-WARN] Refusing conflicting UP F-SEID for observation 0x%x: have=0x%x new=0x%x",
			observationID, session.UPSEID, upSEID)
		return false
	}
	if upfIP != nil && session.UPFIP != nil && !session.UPFIP.Equal(upfIP) {
		return false
	}
	session.UPSEID = upSEID
	c.upSEIDMap[pfcpSEIDLookupKey(session.UPFIP, upSEID)] = observationID
	return true
}

// ConfirmSessionEstablishment correlates a response by the CP F-SEID carried in
// its PFCP header. It intentionally has no "newest pending session" fallback:
// such a fallback can cross-wire concurrent establishments on the same UPF.
func (c *Correlation) ConfirmSessionEstablishment(
	upfIP net.IP,
	cpSEID, upSEID uint64,
) (*Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cpSEID == 0 {
		return nil, false
	}
	observationID, ok := c.cpSEIDMap[pfcpSEIDLookupKey(upfIP, cpSEID)]
	if !ok {
		return nil, false
	}
	session, ok := c.sessions[observationID]
	if !ok {
		return nil, false
	}
	if upSEID != 0 {
		if session.UPSEID != 0 && session.UPSEID != upSEID {
			return nil, false
		}
		session.UPSEID = upSEID
		c.upSEIDMap[pfcpSEIDLookupKey(upfIP, upSEID)] = observationID
	}
	now := time.Now()
	session.EstablishmentStatus = EstablishmentEstablished
	session.Status = "Active"
	session.ModifiedAt = now
	session.LastActive = now
	return session, true
}

// GetSessionByUPSEID looks up the PFCP session addressed by a CP-to-UPF
// session-level request.
func (c *Correlation) GetSessionByUPSEID(upfIP net.IP, upSEID uint64) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if observationID, ok := c.upSEIDMap[pfcpSEIDLookupKey(upfIP, upSEID)]; ok {
		if session, ok := c.sessions[observationID]; ok {
			return session, true
		}
	}
	return nil, false
}

// RemoveSessionByUPSEID removes the session addressed by the UPF-selected
// F-SEID in a Session Deletion Request.
func (c *Correlation) RemoveSessionByUPSEID(upfIP net.IP, upSEID uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	observationID, ok := c.upSEIDMap[pfcpSEIDLookupKey(upfIP, upSEID)]
	if !ok {
		return false
	}
	if c.removeSessionLocked(observationID) {
		log.Printf("[DEBUG] RemoveSessionByUPSEID: Removed UP F-SEID 0x%x (observation 0x%x, total: %d)",
			upSEID, observationID, len(c.sessions))
		return true
	}
	return false
}

// GetSessionByTEID looks up session by TEID
func (c *Correlation) GetSessionByTEID(teid uint32) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if seid, ok := c.teidMap[teid]; ok {
		return c.sessions[seid], true
	}
	return nil, false
}

// ApplyCreatedPDRFTEIDs records UPF-allocated Local F-TEIDs returned in
// Created PDR IEs. These values were not available in the establishment
// request when the CH (choose) flag was used.
func (c *Correlation) ApplyCreatedPDRFTEIDs(
	observationID uint64,
	endpoints []CreatedPDRFTEID,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	session, ok := c.sessions[observationID]
	if !ok {
		return
	}
	for _, endpoint := range endpoints {
		for index := range session.FlowRules {
			if session.FlowRules[index].PDRID != endpoint.PDRID {
				continue
			}
			if endpoint.TEID != 0 {
				session.FlowRules[index].LocalFTEID = endpoint.TEID
			}
			if endpoint.IP != nil {
				session.FlowRules[index].LocalFTEIDIP = cloneIP(endpoint.IP)
			}
			break
		}
		if endpoint.TEID == 0 {
			continue
		}
		found := false
		for _, teid := range session.TEIDs {
			if teid == endpoint.TEID {
				found = true
				break
			}
		}
		if !found {
			session.TEIDs = append(session.TEIDs, endpoint.TEID)
		}
		c.teidMap[endpoint.TEID] = observationID
	}
}

// GetSessionBySEID looks up session by SEID
func (c *Correlation) GetSessionBySEID(seid uint64) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	session, ok := c.sessions[seid]
	return session, ok
}

// GetSessionByUEIP looks up session by UE IP address
func (c *Correlation) GetSessionByUEIP(ueIP string) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, session := range c.sessions {
		if session.UEIP != nil && session.UEIP.String() == ueIP {
			return session, true
		}
	}
	return nil, false
}

// GetSessionByUEIPAndUPF returns the PFCP session local to a specific UPF.
func (c *Correlation) GetSessionByUEIPAndUPF(ueIP string, upfIP net.IP) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	seid, ok := c.ueIPMap[sessionLookupKey(ueIP, upfIP)]
	if !ok {
		return nil, false
	}
	session, ok := c.sessions[seid]
	return session, ok
}

// GetAllSessions returns all sessions
func (c *Correlation) GetAllSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// GetActiveSessions returns only successfully established sessions (not failed or pending)
func (c *Correlation) GetActiveSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0)
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentEstablished {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// GetFailedSessions returns sessions that failed to establish
func (c *Correlation) GetFailedSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0)
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentFailed {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// GetPendingSessions returns sessions still waiting for establishment confirmation
func (c *Correlation) GetPendingSessions() []*Session {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*Session, 0)
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentPending {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// SessionCount returns the total number of sessions (all states)
func (c *Correlation) SessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// ActiveSessionCount returns only successfully established sessions count
func (c *Correlation) ActiveSessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentEstablished {
			count++
		}
	}
	return count
}

// FailedSessionCount returns the count of failed sessions
func (c *Correlation) FailedSessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, s := range c.sessions {
		if s.EstablishmentStatus == EstablishmentFailed {
			count++
		}
	}
	return count
}

// Sniffer captures and parses PFCP packets
type Sniffer struct {
	handle      *pcap.Handle
	correlation *Correlation
	stopChan    chan struct{}
	iface       string
	port        uint16
}

// NewSniffer creates a new PFCP sniffer
func NewSniffer(iface string, port uint16, correlation *Correlation) *Sniffer {
	return &Sniffer{
		iface:       iface,
		port:        port,
		correlation: correlation,
		stopChan:    make(chan struct{}),
	}
}

// AutoDetectInterface automatically detects the safest interface for PFCP capture.
// A specifically named free5GC bridge is preferred. Otherwise "any" is used
// because native free5GC commonly carries PFCP over loopback, while an unrelated
// Docker bridge may belong only to the observability stack.
// Returns the interface name and a description of how it was detected
func AutoDetectInterface() (string, string) {
	// Get all available interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("[AUTO-DETECT] Failed to list interfaces: %v, falling back to 'any'", err)
		return "any", "fallback (interface enumeration failed)"
	}

	// Priority 1: Look for Docker bridge interfaces with free5gc-related names
	// These are the most specific and likely to be correct
	for _, dev := range devices {
		name := dev.Name
		// Check for common free5gc Docker bridge names
		if name == "br-free5gc" ||
			strings.HasPrefix(name, "br-free5gc") ||
			strings.Contains(name, "free5gc") {
			return name, "free5gc Docker bridge"
		}
	}

	return "any", "all interfaces (includes native free5GC loopback PFCP)"
}

// DetectAndListInterfaces lists all available interfaces with their details
// Useful for debugging and manual configuration
func DetectAndListInterfaces() []map[string]interface{} {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("[DETECT] Failed to list interfaces: %v", err)
		return nil
	}

	result := make([]map[string]interface{}, 0, len(devices))
	for _, dev := range devices {
		addresses := make([]string, 0)
		for _, addr := range dev.Addresses {
			addresses = append(addresses, addr.IP.String())
		}

		info := map[string]interface{}{
			"name":        dev.Name,
			"description": dev.Description,
			"addresses":   addresses,
			"flags":       dev.Flags,
		}
		result = append(result, info)
	}
	return result
}

// Start begins capturing PFCP packets
func (s *Sniffer) Start() error {
	var err error

	// Auto-detect interface if set to "auto"
	actualIface := s.iface
	if s.iface == "auto" || s.iface == "" {
		detected, reason := AutoDetectInterface()
		actualIface = detected
		log.Printf("[PFCP] Auto-detected interface: %s (%s)", actualIface, reason)
	}

	// Open the device for capturing
	s.handle, err = pcap.OpenLive(actualIface, 65535, true, pcap.BlockForever)
	if err != nil {
		// If the specified interface fails, try "any" as fallback
		if actualIface != "any" {
			log.Printf("[PFCP] Failed to open %s: %v, trying 'any' interface", actualIface, err)
			s.handle, err = pcap.OpenLive("any", 65535, true, pcap.BlockForever)
			if err != nil {
				return fmt.Errorf("failed to open any interface: %w", err)
			}
			actualIface = "any"
		} else {
			return fmt.Errorf("failed to open device %s: %w", actualIface, err)
		}
	}

	// Update the interface name to reflect what's actually being used
	s.iface = actualIface

	// Set BPF filter for PFCP (UDP port 8805)
	filter := fmt.Sprintf("udp port %d", s.port)
	if err := s.handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	log.Printf("PFCP Sniffer started on %s, filter: %s", actualIface, filter)

	go s.captureLoop()

	return nil
}

// Stop stops the sniffer
func (s *Sniffer) Stop() {
	close(s.stopChan)
	if s.handle != nil {
		s.handle.Close()
	}
}

// Interface returns the interface that is actually used for packet capture.
// This may differ from the requested interface when Start falls back to "any".
func (s *Sniffer) Interface() string {
	return s.iface
}

func (s *Sniffer) captureLoop() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			s.processPacket(packet)
		}
	}
}

func (s *Sniffer) processPacket(packet gopacket.Packet) {
	// Get IP layer to extract source and destination IPs
	var srcIP, dstIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	}

	// Get UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp, _ := udpLayer.(*layers.UDP)
	payload := udp.Payload

	if len(payload) < 8 {
		return
	}

	// Parse PFCP header (3GPP TS 29.244)
	// Byte 0: Version (3 bits) + Spare (3 bits) + MP (1 bit) + S (1 bit)
	// Byte 1: Message Type
	// Bytes 2-3: Message Length (excludes first 4 bytes of header)
	// If S=1: Bytes 4-11: SEID, then Bytes 12-15: Sequence Number + Spare
	// If S=0: Bytes 4-7: Sequence Number + Spare
	msgType := payload[1]
	msgLen := binary.BigEndian.Uint16(payload[2:4])

	// Check if it's a session message (has SEID) - S bit is bit 0
	hasSessionID := (payload[0] & 0x01) != 0

	var seid uint64
	var ieOffset int

	if hasSessionID {
		if len(payload) < 16 {
			return
		}
		seid = binary.BigEndian.Uint64(payload[4:12])
		ieOffset = 16 // Header (4) + SEID (8) + SeqNum (4) = 16
	} else {
		ieOffset = 8 // Header (4) + SeqNum (4) = 8
	}

	// Calculate IE data end position
	// msgLen is the length of everything after the first 4 bytes
	// So total packet should be: 4 + msgLen
	ieDataEnd := 4 + int(msgLen)
	if ieDataEnd > len(payload) {
		log.Printf("[PFCP-WARN] Message length (%d) exceeds payload (%d), truncating", ieDataEnd, len(payload))
		ieDataEnd = len(payload)
	}

	// Empty IE data is valid for messages such as Session Deletion Request.
	// Reject only malformed packets where the header extends past the message.
	if ieOffset > ieDataEnd {
		log.Printf("[PFCP-WARN] Invalid IE offset (offset=%d, end=%d)", ieOffset, ieDataEnd)
		return
	}

	ieData := payload[ieOffset:ieDataEnd]

	// Process based on message type
	// Only create sessions from Establishment Request (has complete data)
	// Response and Modification only update existing sessions
	// For Session Establishment Request: srcIP=SMF, dstIP=UPF
	switch msgType {
	case MsgTypeSessionEstablishmentRequest:
		log.Printf("[PFCP-DEBUG] Session Establishment Request: SEID=0x%x, SMF=%s, UPF=%s, msgLen=%d", seid, srcIP, dstIP, msgLen)
		s.handleSessionEstablishmentRequest(ieData, dstIP) // dstIP is the UPF receiving this request
	case MsgTypeSessionEstablishmentResponse:
		log.Printf("[PFCP-DEBUG] Session Establishment Response: SEID=0x%x (SMF's SEID)", seid)
		// Extract UPF's F-SEID from response to map UPF-SEID -> Internal-SEID
		// This is CRITICAL for Session Deletion, as SMF uses UPF's SEID in Deletion Request
		s.handleSessionEstablishmentResponse(seid, ieData, srcIP)
	case MsgTypeSessionModificationRequest:
		log.Printf("[PFCP-DEBUG] Session Modification Request: SEID=0x%x, UPF=%s", seid, dstIP)
		s.handleSessionModification(seid, ieData, dstIP)
	case MsgTypeSessionModificationResponse:
		log.Printf("[PFCP-DEBUG] Session Modification Response: SEID=0x%x (ignored)", seid)
	case MsgTypeSessionDeletionRequest:
		log.Printf("[PFCP-DEBUG] Session Deletion Request: SEID=0x%x", seid)
		s.handleSessionDeletion(seid, dstIP)
	case MsgTypeSessionDeletionResponse:
		log.Printf("[PFCP-DEBUG] Session Deletion Response: SEID=0x%x (ignored)", seid)
	case MsgTypeSessionReportRequest:
		log.Printf("[PFCP-DEBUG] Session Report Request: SEID=0x%x (ignored)", seid)
	case MsgTypeSessionReportResponse:
		log.Printf("[PFCP-DEBUG] Session Report Response: SEID=0x%x (ignored)", seid)
	default:
		// Log unknown message types for debugging
		if hasSessionID {
			log.Printf("[PFCP-DEBUG] Unknown msg type 0x%x with SEID=0x%x", msgType, seid)
		}
	}
}

// handleSessionEstablishmentRequest handles Session Establishment Request
// This is the only place where new sessions are created (Request has all the data)
// upfIP is the destination IP of the PFCP message (the UPF receiving this request)
func (s *Sniffer) handleSessionEstablishmentRequest(ieData []byte, upfIP net.IP) {
	// First, extract UE IP - this is our primary key for session identification
	ueIP := s.extractUEIP(ieData)
	if ueIP == nil {
		log.Printf("[PFCP] Session Establishment: No UE IP found in IEs, skipping")
		return
	}

	ueIPStr := ueIP.String()
	log.Printf("[PFCP] Session Establishment Request: UE_IP=%s, UPF=%s", ueIPStr, upfIP)

	// Extract TEIDs first - we need these to properly identify the session
	teids := s.extractUniqueTEIDs(ieData, nil)
	if len(teids) == 0 {
		log.Printf("   └─ Warning: No TEIDs found for UE IP %s", ueIPStr)
	}

	// Create new session - always create a new entry for each unique UE IP
	// The AddSession function will handle deduplication properly
	now := time.Now()
	session := &Session{
		SEID:                0, // Will be assigned by AddSession
		CPSEID:              extractTopLevelFSEID(ieData),
		Source:              "pfcp",
		UEIP:                ueIP,
		UPFIP:               upfIP, // Set UPF IP from PFCP message destination
		CreatedAt:           now,
		LastActive:          now,
		TEIDs:               teids,
		Status:              "Pending", // Initial status is Pending until modification confirms establishment
		EstablishmentStatus: EstablishmentPending,
		EstablishmentTime:   now,
	}

	// Parse IEs to extract all available info
	s.extractSessionInfo(ieData, session)

	// Extract F-TEID details (gNB/peer UPF IPs from Outer Header Creation)
	s.extractFTEIDDetails(ieData, session)
	s.extractFlowRules(ieData, session)

	// Add session (will handle deduplication and SEID assignment)
	s.correlation.AddSession(session)

	log.Printf("   └─ Session created (Pending): TEIDs: %v, UE_IP: %v, UPF_IP: %v, DNN: %s, QFI: %d, MBR: UL=%d/DL=%d kbps",
		session.TEIDs, ueIP, upfIP, session.DNN, session.QFI, session.MBRUplink, session.MBRDownlink)
}

func (s *Sniffer) handleSessionModification(seid uint64, ieData []byte, upfIP net.IP) {
	log.Printf("[PFCP] Session Modification: SEID=0x%x, UPF=%s", seid, upfIP)

	// The request header is the UPF-selected F-SEID and is the authoritative
	// lookup key for CP-to-UPF session messages.
	ueIP := s.extractUEIP(ieData)
	var session *Session
	var ok bool

	if seid != 0 {
		session, ok = s.correlation.GetSessionByUPSEID(upfIP, seid)
	}

	// If the establishment response was missed, the UE+UPF evidence in this
	// modification can recover the mapping without guessing another session.
	if !ok && ueIP != nil {
		session, ok = s.correlation.GetSessionByUEIPAndUPF(ueIP.String(), upfIP)
		if ok {
			if session.UPSEID != 0 && session.UPSEID != seid {
				log.Printf("[PFCP-WARN] UE %s on UPF %s is already bound to UP F-SEID 0x%x; refusing header 0x%x",
					ueIP, upfIP, session.UPSEID, seid)
				session = nil
				ok = false
			} else if seid != 0 {
				ok = s.correlation.RegisterUPSEID(upfIP, seid, session.SEID)
			}
		}
		if ok {
			log.Printf("   └─ Recovered session by UE IP %s and UPF %s (observation=0x%x)",
				ueIP.String(), upfIP, session.SEID)
		}
	}

	if !ok {
		// Session not found - only create if we have UE IP
		if ueIP == nil {
			log.Printf("   └─ Session not found and no UE IP, skipping modification")
			return
		}

		log.Printf("   └─ Session not found, creating from modification data with UE IP %s", ueIP.String())

		// Create new session - SEID will be assigned by AddSession
		// A session created from modification is already established
		now := time.Now()
		session = &Session{
			SEID:                0, // Will be assigned by AddSession
			UPSEID:              seid,
			Source:              "pfcp",
			UEIP:                ueIP,
			UPFIP:               upfIP, // Set UPF IP from PFCP message destination
			CreatedAt:           now,
			LastActive:          now,
			TEIDs:               make([]uint32, 0),
			Status:              "Active",
			EstablishmentStatus: EstablishmentEstablished,
			EstablishmentTime:   now,
		}
	} else {
		// Existing session received modification - mark as Established
		if session.EstablishmentStatus == EstablishmentPending {
			log.Printf("   └─ Session establishment confirmed (Pending -> Established)")
			session.EstablishmentStatus = EstablishmentEstablished
			session.Status = "Active"
		}
	}

	// Update UPF IP if not already set
	if session.UPFIP == nil && upfIP != nil {
		session.UPFIP = upfIP
	}
	if cpSEID := extractTopLevelFSEID(ieData); cpSEID != 0 {
		if session.CPSEID == 0 || session.CPSEID == cpSEID {
			session.CPSEID = cpSEID
		} else {
			log.Printf("[PFCP-WARN] Observation 0x%x received conflicting CP F-SEID: have=0x%x new=0x%x",
				session.SEID, session.CPSEID, cpSEID)
		}
	}

	// Extract session info from modification IEs
	s.extractSessionInfo(ieData, session)

	// Extract TEIDs and merge with existing (removes duplicates)
	session.TEIDs = s.extractUniqueTEIDs(ieData, session.TEIDs)

	// Extract UE IP if present and not already set
	if session.UEIP == nil && ueIP != nil {
		session.UEIP = ueIP
	}

	// Refresh interface semantics from updated FARs. Access-side peers remain
	// unclassified until correlated with the set of observed UPFs.
	s.extractFTEIDDetails(ieData, session)
	s.extractFlowRules(ieData, session)

	session.ModifiedAt = time.Now()
	session.LastActive = time.Now()
	s.correlation.AddSession(session)

	log.Printf("   └─ Updated: TEIDs: %v, UE_IP: %v, UPF_IP: %v, MBR: UL=%d/DL=%d kbps, Status: %s",
		session.TEIDs, session.UEIP, session.UPFIP, session.MBRUplink, session.MBRDownlink, session.EstablishmentStatus)
}

func (s *Sniffer) handleSessionDeletion(upSEID uint64, upfIP net.IP) {
	log.Printf("PFCP Session Deletion Request: UP_F-SEID=0x%x UPF=%s", upSEID, upfIP)

	if s.correlation.RemoveSessionByUPSEID(upfIP, upSEID) {
		log.Printf("   └─ Removed session by UP F-SEID 0x%x", upSEID)
		return
	}
	log.Printf("   └─ UP F-SEID 0x%x on UPF %s was not correlated; no session removed", upSEID, upfIP)
}

// handleSessionEstablishmentResponse processes Session Establishment Response to capture UPF's F-SEID
// The header SEID in Response is the SMF's SEID.
// The UPF's assigned SEID is in the F-SEID IE. We need to map UPF-SEID -> Internal-Session.
func (s *Sniffer) handleSessionEstablishmentResponse(smfSEID uint64, ieData []byte, upfIP net.IP) {
	// In Establishment Response (UPF->SMF):
	// - Header SEID = CP F-SEID selected by the SMF.
	// - F-SEID IE = UP F-SEID selected by this UPF.

	var upfSEID uint64
	var cause uint8
	var causeSeen bool

	log.Printf("[PFCP-DEBUG] Parsing Establishment Response IEs (len=%d)", len(ieData))
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		log.Printf("[PFCP-DEBUG] IE Type: %d (len=%d)", ieType, len(ieValue))
		switch ieType {
		case IETypeCause:
			if len(ieValue) > 0 {
				cause = ieValue[0]
				causeSeen = true
			}
		case IETypeFSEID:
			// Parse F-SEID (UPF's SEID)
			// Flags (1) + SEID (8) + ...
			log.Printf("[PFCP-DEBUG] Found F-SEID IE: %x", ieValue)
			if len(ieValue) >= 9 {
				upfSEID = binary.BigEndian.Uint64(ieValue[1:9])
				log.Printf("   └─ Found UPF F-SEID: 0x%x", upfSEID)
			}
		}
	})

	// Cause=1 is "Request accepted". Do not turn a rejected response into an
	// active session. Cause is mandatory in a standards-compliant response.
	if !causeSeen || cause != 1 {
		log.Printf("[PFCP] Session Establishment Response rejected or missing Cause: SMF_SEID=0x%x UPF=%s Cause=%d",
			smfSEID, upfIP, cause)
		return
	}

	if candidate, ok := s.correlation.ConfirmSessionEstablishment(upfIP, smfSEID, upfSEID); ok {
		s.applyCreatedPDRs(ieData, candidate)
		log.Printf("   └─ Establishment accepted: CP F-SEID 0x%x, UP F-SEID 0x%x -> observation 0x%x (UE %s)",
			smfSEID,
			upfSEID, candidate.SEID, candidate.UEIP)
	} else {
		log.Printf("[PFCP] Accepted Establishment Response has no exact CP F-SEID match: CP_F-SEID=0x%x UPF=%s",
			smfSEID, upfIP)
	}
}

func extractTopLevelFSEID(ieData []byte) uint64 {
	var seid uint64
	parseImmediateIEs(ieData, func(ieType uint16, ieValue []byte) {
		if seid == 0 && ieType == IETypeFSEID && len(ieValue) >= 9 {
			seid = binary.BigEndian.Uint64(ieValue[1:9])
		}
	})
	return seid
}

func (s *Sniffer) applyCreatedPDRs(ieData []byte, session *Session) {
	if session == nil {
		return
	}
	endpoints := make([]CreatedPDRFTEID, 0)
	parseImmediateIEs(ieData, func(ieType uint16, ieValue []byte) {
		if ieType != IETypeCreatedPDR {
			return
		}
		endpoint := CreatedPDRFTEID{}
		parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
			switch childType {
			case IETypePDRID:
				if len(childValue) >= 2 {
					endpoint.PDRID = binary.BigEndian.Uint16(childValue[:2])
				}
			case IETypeFTEID:
				endpoint.TEID, endpoint.IP = extractFTEID(childValue)
			}
		})
		if endpoint.PDRID != 0 && (endpoint.TEID != 0 || endpoint.IP != nil) {
			endpoints = append(endpoints, endpoint)
		}
	})
	s.correlation.ApplyCreatedPDRFTEIDs(session.SEID, endpoints)
}

// extractSessionInfo extracts DNN, QFI, and other session info from PFCP IEs
func (s *Sniffer) extractSessionInfo(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		switch ieType {
		case IETypeNetworkInstance: // Network Instance (DNN)
			if dnn := decodeNetworkInstance(ieValue); dnn != "" {
				session.DNN = dnn
				log.Printf("   └─ Found DNN: %s", dnn)
			}
		case IETypeQFI: // QFI
			if len(ieValue) >= 1 {
				session.QFI = ieValue[0] & 0x3F // QFI is 6 bits
				log.Printf("   └─ Found QFI: %d", session.QFI)
			}
		case IETypeMBR: // Maximum Bit Rate (Type 26)
			// According to 3GPP TS 29.244, MBR IE format:
			// - UL MBR: 5 bytes (40 bits) in kbps
			// - DL MBR: 5 bytes (40 bits) in kbps
			// Total: 10 bytes
			if len(ieValue) >= 10 {
				session.MBRUplink = decodeUint40(ieValue[0:5])
				session.MBRDownlink = decodeUint40(ieValue[5:10])
				log.Printf("   └─ Found MBR: UL=%d kbps, DL=%d kbps",
					session.MBRUplink, session.MBRDownlink)
			}
		case IETypeGBR: // Guaranteed Bit Rate
			if len(ieValue) >= 10 {
				session.GBRUplink = decodeUint40(ieValue[0:5])
				session.GBRDownlink = decodeUint40(ieValue[5:10])
				log.Printf("   └─ Found GBR: UL=%d kbps, DL=%d kbps",
					session.GBRUplink, session.GBRDownlink)
			}
		case IETypePrecedence: // Precedence (can indicate QoS priority)
			if len(ieValue) >= 4 {
				precedence := binary.BigEndian.Uint32(ieValue[0:4])
				log.Printf("   └─ Found Precedence: %d", precedence)
			}
		case IETypePDNType:
			if len(ieValue) >= 1 {
				pduType := ieValue[0] & 0x07 // Lower 3 bits
				switch pduType {
				case 1:
					session.SessionType = "IPv4"
				case 2:
					session.SessionType = "IPv6"
				case 3:
					session.SessionType = "IPv4v6"
				case 4:
					session.SessionType = "Non-IP"
				case 5:
					session.SessionType = "Ethernet"
				default:
					session.SessionType = fmt.Sprintf("Type-%d", pduType)
				}
				log.Printf("   └─ Found PDN Type: %s", session.SessionType)
			}
		case IETypeSNSSAI: // S-NSSAI
			if len(ieValue) >= 1 {
				sst := ieValue[0]
				sd := ""
				if len(ieValue) >= 4 {
					// SD is 3 bytes (24 bits)
					sdVal := uint32(ieValue[1])<<16 | uint32(ieValue[2])<<8 | uint32(ieValue[3])
					if sdVal != 0xFFFFFF { // 0xFFFFFF means SD is not present
						sd = fmt.Sprintf("%06X", sdVal)
					}
				}
				session.SNssai = fmt.Sprintf("SST:%d", sst)
				if sd != "" {
					session.SNssai += fmt.Sprintf(",SD:%s", sd)
				}
				log.Printf("   └─ Found S-NSSAI: %s", session.SNssai)
			}
		}
	})
}

const (
	pfcpInterfaceAccess = 0
	pfcpInterfaceCore   = 1
	pfcpInterfaceN6     = 2

	tgppInterfaceN3Min = 11
	tgppInterfaceN3Max = 14
	tgppInterfaceN9    = 15
	tgppInterfaceN6    = 17
)

// extractFTEIDDetails extracts topology facts from each FAR's forwarding
// parameters. It deliberately avoids classifying peers by address ranges.
//
// Destination=Core with a GTP-U outer header is N9 towards the data network.
// Destination=Access may be either N3 or N9, so it remains an access peer
// unless the optional 3GPP Interface Type IE identifies it explicitly.
func (s *Sniffer) extractFTEIDDetails(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		if ieType != IETypeForwardingParameters && ieType != 11 {
			return
		}

		destinationInterface := -1
		interfaceType := -1
		outerPeers := make([]net.IP, 0, 1)

		parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
			switch childType {
			case IETypeDestinationInterface:
				if len(childValue) > 0 {
					destinationInterface = int(childValue[0] & 0x0f)
				}
			case IEType3GPPInterfaceType:
				if len(childValue) > 0 {
					interfaceType = int(childValue[0] & 0x3f)
				}
			case IETypeOuterHeaderCreation:
				if ip := extractOuterHeaderCreationIP(childValue); ip != nil {
					outerPeers = append(outerPeers, ip)
				}
			}
		})

		if destinationInterface == pfcpInterfaceN6 || interfaceType == tgppInterfaceN6 {
			session.HasN6 = true
		}

		for _, ip := range outerPeers {
			if session.UPFIP != nil && ip.Equal(session.UPFIP) {
				continue
			}

			switch {
			case interfaceType == tgppInterfaceN9:
				direction := ""
				if destinationInterface == pfcpInterfaceCore {
					direction = "towards-core"
				} else if destinationInterface == pfcpInterfaceAccess {
					direction = "towards-access"
				}
				setN9Peer(session, ip, direction, "pfcp:3gpp-interface-type-n9")
			case interfaceType >= tgppInterfaceN3Min && interfaceType <= tgppInterfaceN3Max:
				session.GNBIP = cloneIP(ip)
				log.Printf("   └─ PFCP 3GPP Interface Type identifies N3 peer: %s", ip)
			case destinationInterface == pfcpInterfaceCore:
				setN9Peer(session, ip, "towards-core", "pfcp:destination-interface-core")
			case destinationInterface == pfcpInterfaceAccess:
				session.AccessPeerIP = cloneIP(ip)
				log.Printf("   └─ PFCP access-side peer awaiting graph correlation: %s", ip)
			}
		}
	})
}

func setN9Peer(session *Session, ip net.IP, direction, evidence string) {
	if session.N9PeerIP != nil && !session.N9PeerIP.Equal(ip) {
		log.Printf("   └─ Additional N9 peer ignored by single-path session model: %s", ip)
		return
	}
	session.N9PeerIP = cloneIP(ip)
	session.N9Direction = direction
	session.N9Evidence = evidence
	log.Printf("   └─ PFCP identifies N9 peer: %s (%s, %s)", ip, direction, evidence)
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	cloned := make(net.IP, len(ip))
	copy(cloned, ip)
	return cloned
}

// extractOuterHeaderCreationIP parses the first IP destination from an Outer
// Header Creation IE without assuming IPv4 or a fixed field offset.
func extractOuterHeaderCreationIP(value []byte) net.IP {
	if len(value) < 2 {
		return nil
	}

	description := value[0]
	offset := 2
	hasTEID := description&0x03 != 0
	hasIPv4 := description&(0x01|0x04|0x10) != 0
	hasIPv6 := description&(0x02|0x08|0x20) != 0

	if hasTEID {
		if len(value) < offset+4 {
			return nil
		}
		offset += 4
	}
	if hasIPv4 {
		if len(value) < offset+4 {
			return nil
		}
		return cloneIP(net.IP(value[offset : offset+4]))
	}
	if hasIPv6 {
		if len(value) < offset+16 {
			return nil
		}
		return cloneIP(net.IP(value[offset : offset+16]))
	}
	return nil
}

func extractOuterHeaderCreation(value []byte) (uint32, net.IP) {
	if len(value) < 2 {
		return 0, nil
	}
	description := value[0]
	offset := 2
	var teid uint32
	if description&0x03 != 0 {
		if len(value) < offset+4 {
			return 0, nil
		}
		teid = binary.BigEndian.Uint32(value[offset : offset+4])
		offset += 4
	}
	if description&(0x01|0x04|0x10) != 0 {
		if len(value) < offset+4 {
			return teid, nil
		}
		return teid, cloneIP(net.IP(value[offset : offset+4]))
	}
	if description&(0x02|0x08|0x20) != 0 {
		if len(value) < offset+16 {
			return teid, nil
		}
		return teid, cloneIP(net.IP(value[offset : offset+16]))
	}
	return teid, nil
}

// extractFTEID returns only fields that are physically present in the IE. A
// zero TEID with the CH flag means the UPF must allocate the endpoint and is
// therefore not reported as an observed TEID until a Created PDR is captured.
func extractFTEID(value []byte) (uint32, net.IP) {
	if len(value) < 5 {
		return 0, nil
	}
	flags := value[0]
	teid := binary.BigEndian.Uint32(value[1:5])
	offset := 5
	if flags&0x01 != 0 {
		if len(value) < offset+4 {
			return teid, nil
		}
		return teid, cloneIP(net.IP(value[offset : offset+4]))
	}
	if flags&0x02 != 0 {
		if len(value) < offset+16 {
			return teid, nil
		}
		return teid, cloneIP(net.IP(value[offset : offset+16]))
	}
	return teid, nil
}

func decodeNetworkInstance(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	labels := make([]string, 0, 3)
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 || offset+length > len(value) {
			labels = nil
			break
		}
		labels = append(labels, string(value[offset:offset+length]))
		offset += length
	}
	if len(labels) > 0 {
		return strings.Join(labels, ".")
	}
	return strings.TrimSpace(strings.Trim(string(value), "\x00"))
}

func decodeUint40(value []byte) uint64 {
	if len(value) < 5 {
		return 0
	}
	var decoded uint64
	for _, octet := range value[:5] {
		decoded = decoded<<8 | uint64(octet)
	}
	return decoded
}

func decodeSDFFlowDescription(value []byte) string {
	// SDF Filter: flags/spare (2), then FD length and flow description when
	// the FD flag is present. Other optional fields follow the description.
	if len(value) < 4 || value[0]&0x01 == 0 {
		return ""
	}
	length := int(binary.BigEndian.Uint16(value[2:4]))
	if length == 0 || 4+length > len(value) {
		return ""
	}
	return strings.TrimSpace(string(value[4 : 4+length]))
}

func sdfDestinationSelector(description, ueIP string) string {
	fields := strings.Fields(description)
	fromIndex, toIndex := -1, -1
	for index, field := range fields {
		switch strings.ToLower(field) {
		case "from":
			fromIndex = index
		case "to":
			toIndex = index
		}
	}
	if fromIndex < 0 || toIndex < 0 || fromIndex+1 >= len(fields) || toIndex+1 >= len(fields) {
		return ""
	}
	from := strings.Trim(fields[fromIndex+1], "[]")
	to := strings.Trim(fields[toIndex+1], "[]")
	isUE := func(endpoint string) bool {
		host := strings.Split(endpoint, "/")[0]
		return ueIP != "" && host == ueIP
	}
	isDefault := func(endpoint string) bool {
		switch strings.ToLower(endpoint) {
		case "any", "assigned", "0.0.0.0/0", "::/0":
			return true
		default:
			return false
		}
	}
	if !isUE(to) && !isDefault(to) {
		return to
	}
	if !isUE(from) && !isDefault(from) {
		return from
	}
	return ""
}

func flowPathType(rule FlowRule) string {
	if rule.OuterDst != nil {
		switch {
		case rule.InterfaceType == tgppInterfaceN9 || rule.DestinationInterface == pfcpInterfaceCore:
			return "n9"
		case rule.InterfaceType >= tgppInterfaceN3Min && rule.InterfaceType <= tgppInterfaceN3Max:
			return "n3"
		case rule.DestinationInterface == pfcpInterfaceAccess:
			return "access-tunnel"
		default:
			return "tunnel"
		}
	}
	if rule.DestinationInterface == pfcpInterfaceN6 ||
		rule.InterfaceType == tgppInterfaceN6 ||
		rule.DestinationInterface == pfcpInterfaceCore {
		return "n6"
	}
	if rule.DestinationInterface >= 0 || rule.InterfaceType >= 0 {
		return "local"
	}
	return ""
}

func parseForwardingRule(value []byte, previous ForwardingRule) ForwardingRule {
	rule := previous
	if rule.DestinationInterface == 0 && previous.FARID == 0 {
		rule.DestinationInterface = -1
		rule.InterfaceType = -1
	}
	parseImmediateIEs(value, func(ieType uint16, ieValue []byte) {
		switch ieType {
		case IETypeFARID:
			if len(ieValue) >= 4 {
				rule.FARID = binary.BigEndian.Uint32(ieValue[:4])
			}
		case IETypeApplyAction:
			if len(ieValue) > 0 {
				rule.ApplyAction = ieValue[0]
			}
		case IETypeForwardingParameters, IETypeUpdateForwarding:
			parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
				switch childType {
				case IETypeDestinationInterface:
					if len(childValue) > 0 {
						rule.DestinationInterface = int(childValue[0] & 0x0f)
					}
				case IEType3GPPInterfaceType:
					if len(childValue) > 0 {
						rule.InterfaceType = int(childValue[0] & 0x3f)
					}
				case IETypeNetworkInstance:
					rule.NetworkInstance = decodeNetworkInstance(childValue)
				case IETypeOuterHeaderCreation:
					rule.OuterTEID, rule.OuterDst = extractOuterHeaderCreation(childValue)
				}
			})
		}
	})
	return rule
}

func parsePDRFlowRule(value []byte, previous FlowRule, ueIP string) FlowRule {
	rule := previous
	if rule.SourceInterface == 0 && previous.PDRID == 0 {
		rule.SourceInterface = -1
		rule.SourceInterfaceType = -1
		rule.DestinationInterface = -1
		rule.InterfaceType = -1
	}
	parseImmediateIEs(value, func(ieType uint16, ieValue []byte) {
		switch ieType {
		case IETypePDRID:
			if len(ieValue) >= 2 {
				rule.PDRID = binary.BigEndian.Uint16(ieValue[:2])
			}
		case IETypePrecedence:
			if len(ieValue) >= 4 {
				rule.Precedence = binary.BigEndian.Uint32(ieValue[:4])
			}
		case IETypeFARID:
			if len(ieValue) >= 4 {
				rule.FARID = binary.BigEndian.Uint32(ieValue[:4])
			}
		case IETypePDI:
			parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
				switch childType {
				case IETypeSourceInterface:
					if len(childValue) > 0 {
						rule.SourceInterface = int(childValue[0] & 0x0f)
					}
				case IEType3GPPInterfaceType:
					if len(childValue) > 0 {
						rule.SourceInterfaceType = int(childValue[0] & 0x3f)
					}
				case IETypeFTEID:
					rule.LocalFTEID, rule.LocalFTEIDIP = extractFTEID(childValue)
				case IETypeNetworkInstance:
					rule.PDINetworkInstance = decodeNetworkInstance(childValue)
					rule.NetworkInstance = rule.PDINetworkInstance
				case IETypeSDFFilter:
					rule.SDFObserved = true
					rule.SDF = decodeSDFFlowDescription(childValue)
					rule.DestinationSelector = sdfDestinationSelector(rule.SDF, ueIP)
				}
			})
		}
	})
	return rule
}

// extractFlowRules maintains the PDR -> FAR graph carried by PFCP. The result
// can represent multiple simultaneous ULCL paths and therefore replaces the
// old single N9PeerIP/HasN6 summary for topology construction.
func (s *Sniffer) extractFlowRules(ieData []byte, session *Session) {
	fars := make(map[uint32]ForwardingRule, len(session.ForwardingRules))
	for _, far := range session.ForwardingRules {
		fars[far.FARID] = far
	}
	pdrs := make(map[uint16]FlowRule, len(session.FlowRules))
	for _, pdr := range session.FlowRules {
		pdrs[pdr.PDRID] = pdr
	}

	parseImmediateIEs(ieData, func(ieType uint16, ieValue []byte) {
		switch ieType {
		case IETypeCreateFAR, IETypeUpdateFAR:
			// Read the ID first so an Update FAR can merge omitted fields.
			var id uint32
			parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
				if childType == IETypeFARID && len(childValue) >= 4 {
					id = binary.BigEndian.Uint32(childValue[:4])
				}
			})
			fars[id] = parseForwardingRule(ieValue, fars[id])
		case IETypeRemoveFAR:
			parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
				if childType == IETypeFARID && len(childValue) >= 4 {
					delete(fars, binary.BigEndian.Uint32(childValue[:4]))
				}
			})
		case IETypeCreatePDR, IETypeUpdatePDR:
			var id uint16
			parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
				if childType == IETypePDRID && len(childValue) >= 2 {
					id = binary.BigEndian.Uint16(childValue[:2])
				}
			})
			ueIP := ""
			if session.UEIP != nil {
				ueIP = session.UEIP.String()
			}
			pdrs[id] = parsePDRFlowRule(ieValue, pdrs[id], ueIP)
		case IETypeRemovePDR:
			parseImmediateIEs(ieValue, func(childType uint16, childValue []byte) {
				if childType == IETypePDRID && len(childValue) >= 2 {
					delete(pdrs, binary.BigEndian.Uint16(childValue[:2]))
				}
			})
		}
	})

	session.ForwardingRules = session.ForwardingRules[:0]
	for _, far := range fars {
		session.ForwardingRules = append(session.ForwardingRules, far)
	}
	session.FlowRules = session.FlowRules[:0]
	session.HasN6 = false
	session.N9PeerIP = nil
	session.N9Direction = ""
	session.N9Evidence = ""
	for _, pdr := range pdrs {
		// These fields came from the previously joined FAR. Clear them before
		// rebuilding so a removed FAR cannot leave a stale forwarding path.
		pdr.DestinationInterface = -1
		pdr.InterfaceType = -1
		pdr.OuterDst = nil
		pdr.OuterTEID = 0
		pdr.PathType = ""
		pdr.NetworkInstance = pdr.PDINetworkInstance
		if far, ok := fars[pdr.FARID]; ok {
			pdr.DestinationInterface = far.DestinationInterface
			pdr.InterfaceType = far.InterfaceType
			if pdr.NetworkInstance == "" {
				pdr.NetworkInstance = far.NetworkInstance
			}
			pdr.OuterDst = cloneIP(far.OuterDst)
			pdr.OuterTEID = far.OuterTEID
		}
		pdr.PathType = flowPathType(pdr)
		if pdr.PathType == "n6" {
			session.HasN6 = true
		}
		if pdr.PathType == "n9" && pdr.OuterDst != nil && session.N9PeerIP == nil {
			session.N9PeerIP = cloneIP(pdr.OuterDst)
			session.N9Evidence = "pfcp:pdr-far"
			switch pdr.DestinationInterface {
			case pfcpInterfaceCore:
				session.N9Direction = "towards-core"
			case pfcpInterfaceAccess:
				session.N9Direction = "towards-access"
			}
		}
		session.FlowRules = append(session.FlowRules, pdr)
	}
}

func parseImmediateIEs(data []byte, callback func(ieType uint16, ieValue []byte)) {
	for offset := 0; offset+4 <= len(data); {
		ieType := binary.BigEndian.Uint16(data[offset : offset+2])
		ieLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		end := offset + 4 + ieLen
		if ieLen == 0 || end > len(data) {
			return
		}
		callback(ieType, data[offset+4:end])
		offset = end
	}
}

// extractTEIDs extracts F-TEIDs (UPF's own TEIDs) from PFCP IEs (including nested IEs)
// NOTE: We do NOT extract Outer Header Creation TEIDs here because those are the
// destination TEIDs (gNB or peer UPF), not the UPF's own TEIDs. The Outer Header
// Creation TEID belongs to the remote endpoint (gNB) and may be shared across
// multiple PDU sessions, which would cause incorrect TEID association.
func (s *Sniffer) extractTEIDs(ieData []byte) []uint32 {
	teids := make([]uint32, 0)
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// F-TEID IE (Type 21) - This is the UPF's own TEID for receiving packets
		if ieType == IETypeFTEID && len(ieValue) >= 5 {
			// First byte is flags, next 4 bytes is TEID
			teid := binary.BigEndian.Uint32(ieValue[1:5])
			if teid > 0 {
				teids = append(teids, teid)
				log.Printf("   └─ Found F-TEID (UPF): 0x%x", teid)
			}
		}
		// NOTE: Outer Header Creation IE (Type 84) contains the DESTINATION TEID
		// (where UPF should send packets to, e.g., gNB's TEID). This TEID belongs
		// to the gNB, not to this session, so we don't extract it here.
		// It's only logged for debugging purposes.
		if ieType == 84 && len(ieValue) >= 6 {
			teid := binary.BigEndian.Uint32(ieValue[2:6])
			if teid > 0 {
				log.Printf("   └─ Outer Header Creation TEID (gNB dest): 0x%x (not added to session)", teid)
			}
		}
	})
	return teids
}

// extractUniqueTEIDs extracts TEIDs and merges with existing ones, removing duplicates
func (s *Sniffer) extractUniqueTEIDs(ieData []byte, existingTEIDs []uint32) []uint32 {
	// Use a map to track unique TEIDs
	teidSet := make(map[uint32]bool)

	// Add existing TEIDs to the set
	for _, t := range existingTEIDs {
		if t != 0 {
			teidSet[t] = true
		}
	}

	// Extract new TEIDs from IE data
	newTEIDs := s.extractTEIDs(ieData)
	for _, t := range newTEIDs {
		if t != 0 {
			teidSet[t] = true
		}
	}

	// Convert set back to slice
	result := make([]uint32, 0, len(teidSet))
	for t := range teidSet {
		result = append(result, t)
	}

	return result
}

// extractUEIP extracts UE IP Address from PFCP IEs (including nested IEs)
// According to 3GPP TS 29.244, UE IP Address IE (Type 93) format:
// - Flags (1 byte): bit 0=S/D, bit 1=V4, bit 2=V6, bit 3=IPv6D, bit 4=CHV4, bit 5=CHV6
// - IPv4 address (4 bytes) if V4 bit is set and CHV4 is not set
// - IPv6 address (16 bytes) if V6 bit is set and CHV6 is not set
func (s *Sniffer) extractUEIP(ieData []byte) net.IP {
	var ueIP net.IP
	var foundCount int

	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// UE IP Address IE (Type 93)
		if ieType == IETypeUEIPAddr && len(ieValue) >= 1 {
			flags := ieValue[0]
			offset := 1

			// Check V4 bit (bit 1) and ensure CHV4 (bit 4) is not set
			// CHV4 means "Choose IPv4 Address" - the IP hasn't been assigned yet
			hasV4 := (flags & 0x02) != 0
			isChooseV4 := (flags & 0x10) != 0

			if hasV4 && !isChooseV4 && len(ieValue) >= offset+4 {
				extractedIP := net.IP(make([]byte, 4))
				copy(extractedIP, ieValue[offset:offset+4])

				// Validate that it's a proper UE IP (not 0.0.0.0)
				if !extractedIP.Equal(net.IPv4zero) {
					// Only use the first valid UE IP found (avoid overwriting)
					if ueIP == nil {
						ueIP = extractedIP
						foundCount++
						log.Printf("   └─ Found UE IP: %s (flags=0x%02x)", ueIP, flags)
					} else if !ueIP.Equal(extractedIP) {
						// Log if we find a different UE IP (shouldn't happen in same session)
						log.Printf("   └─ Additional UE IP found (ignored): %s", extractedIP)
					}
				}
			} else if isChooseV4 {
				log.Printf("   └─ UE IP Address IE with CHV4 flag (IP not yet assigned)")
			}
		}
	})

	if ueIP == nil {
		log.Printf("   └─ No valid UE IP found in PFCP message")
	}

	return ueIP
}

// parseIEsRecursive recursively parses PFCP IEs and calls callback for each IE
func (s *Sniffer) parseIEsRecursive(ieData []byte, callback func(ieType uint16, ieValue []byte)) {
	offset := 0

	for offset < len(ieData)-4 {
		if offset+4 > len(ieData) {
			break
		}

		ieType := binary.BigEndian.Uint16(ieData[offset : offset+2])
		ieLen := binary.BigEndian.Uint16(ieData[offset+2 : offset+4])

		if ieLen == 0 || offset+4+int(ieLen) > len(ieData) {
			break
		}

		ieValue := ieData[offset+4 : offset+4+int(ieLen)]

		// Call callback for this IE
		callback(ieType, ieValue)

		// Recursively parse grouped IEs
		// These IE types contain nested IEs:
		// - Create PDR (1), Create FAR (3), Create URR (6), Create QER (7)
		// - PDI (2), Forwarding Parameters (4), Duplicating Parameters (5)
		// - Update PDR (9), Update FAR (10), etc.
		switch ieType {
		case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16:
			// These are grouped IEs, parse recursively
			s.parseIEsRecursive(ieValue, callback)
		}

		offset += 4 + int(ieLen)
	}
}

// GetCorrelation returns the correlation store
func (s *Sniffer) GetCorrelation() *Correlation {
	return s.correlation
}

// UpdateUplinkPeer updates the uplink peer IP for a session
func (c *Correlation) UpdateUplinkPeer(teid uint32, peerIP net.IP) {
	c.UpdateGTPUplink(teid, peerIP, nil)
}

// UpdateGTPUplink records both endpoints observed on an uplink GTP-U packet.
// peerIP is the gNB/access peer and upfN3IP is the local UPF N3 endpoint.
func (c *Correlation) UpdateGTPUplink(teid uint32, peerIP, upfN3IP net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if seid, ok := c.teidMap[teid]; ok {
		if session, ok := c.sessions[seid]; ok {
			if peerIP != nil && !peerIP.IsUnspecified() &&
				(session.UplinkPeerIP == nil || !session.UplinkPeerIP.Equal(peerIP)) {
				session.UplinkPeerIP = peerIP
				log.Printf("[PFCP] Updated Uplink Peer IP for SEID 0x%x: %s", session.SEID, peerIP)
			}
			if upfN3IP != nil && !upfN3IP.IsUnspecified() &&
				(session.UPFN3IP == nil || !session.UPFN3IP.Equal(upfN3IP)) {
				session.UPFN3IP = upfN3IP
				log.Printf("[PFCP] Updated UPF N3 IP for SEID 0x%x: %s", session.SEID, upfN3IP)
			}
		}
	}
}

// RecordGTPFlow correlates a GTP-U ingress packet using TEID, the local outer
// destination, and the inner UE endpoint. TEID alone is not unique in an ULCL
// graph. Also, tunnel ingress may carry uplink or downlink PDU traffic; the
// inner UE endpoint determines its actual direction.
func (c *Correlation) RecordGTPFlow(
	teid uint32,
	outerSrc, outerDst, innerSrc, innerDst net.IP,
	pduBytes uint32,
) (*Session, bool) {
	if teid == 0 || innerSrc == nil || innerDst == nil ||
		innerSrc.IsUnspecified() || innerDst.IsUnspecified() {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var candidate *Session
	bestScore := -1
	for _, session := range c.sessions {
		hasTEID := false
		for _, candidateTEID := range session.TEIDs {
			if candidateTEID == teid {
				hasTEID = true
				break
			}
		}
		if !hasTEID {
			continue
		}

		score := 0
		if outerDst != nil {
			if session.UPFN3IP != nil && session.UPFN3IP.Equal(outerDst) {
				score = 4
			} else if session.UPFIP != nil && session.UPFIP.Equal(outerDst) {
				score = 3
			}
		}
		if session.UEIP != nil &&
			(session.UEIP.Equal(innerSrc) || session.UEIP.Equal(innerDst)) {
			score += 2
		}
		if score > bestScore {
			bestScore = score
			candidate = session
		}
	}
	if candidate == nil {
		return nil, false
	}

	direction := ""
	var remoteEndpoint net.IP
	switch {
	case candidate.UEIP != nil && candidate.UEIP.Equal(innerSrc):
		direction = "uplink"
		remoteEndpoint = innerDst
	case candidate.UEIP != nil && candidate.UEIP.Equal(innerDst):
		direction = "downlink"
		remoteEndpoint = innerSrc
	default:
		return nil, false
	}

	now := time.Now()
	if outerSrc != nil && !outerSrc.IsUnspecified() &&
		(candidate.N9PeerIP == nil || !candidate.N9PeerIP.Equal(outerSrc)) {
		candidate.UplinkPeerIP = cloneIP(outerSrc)
	}
	if outerDst != nil && !outerDst.IsUnspecified() &&
		(candidate.UPFIP == nil || candidate.UPFIP.Equal(outerDst)) {
		candidate.UPFN3IP = cloneIP(outerDst)
	}
	for index := range candidate.FlowTraffic {
		flow := &candidate.FlowTraffic[index]
		if flow.Direction == direction && flow.DestIP.Equal(remoteEndpoint) {
			flow.Packets++
			flow.Bytes += uint64(pduBytes)
			flow.LastActive = now
			flow.OuterSrc = cloneIP(outerSrc)
			flow.OuterDst = cloneIP(outerDst)
			candidate.LastPacketTime = now
			candidate.LastActive = now
			candidate.DataPlaneStatus = DataPlaneActive
			return candidate, true
		}
	}

	candidate.FlowTraffic = append(candidate.FlowTraffic, FlowTraffic{
		DestIP:     cloneIP(remoteEndpoint),
		Packets:    1,
		Bytes:      uint64(pduBytes),
		LastActive: now,
		OuterSrc:   cloneIP(outerSrc),
		OuterDst:   cloneIP(outerDst),
		Direction:  direction,
	})
	candidate.LastPacketTime = now
	candidate.LastActive = now
	candidate.DataPlaneStatus = DataPlaneActive
	return candidate, true
}

// RefreshSessionTrafficFromFlows derives session counters from observations
// already correlated to one local UPF. The legacy TEID-only counter map cannot
// do this safely because ULCL may reuse a TEID on N3 and N9.
func (c *Correlation) RefreshSessionTrafficFromFlows() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, session := range c.sessions {
		var packetsUL, packetsDL, bytesUL, bytesDL uint64
		for _, flow := range session.FlowTraffic {
			switch flow.Direction {
			case "uplink":
				packetsUL += flow.Packets
				bytesUL += flow.Bytes
			case "downlink":
				packetsDL += flow.Packets
				bytesDL += flow.Bytes
			}
		}
		session.PacketsUL = packetsUL
		session.PacketsDL = packetsDL
		session.BytesUL = bytesUL
		session.BytesDL = bytesDL
	}
}
