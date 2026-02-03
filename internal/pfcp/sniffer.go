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
	IETypeCreateURR            = 6   // Create URR
	IETypeCreateQER            = 7   // Create QER
	IETypeCause                = 19  // Cause
	IETypeSourceInterface      = 20  // Source Interface
	IETypeFTEID                = 21  // F-TEID
	IETypeNetworkInstance      = 22  // Network Instance (DNN)
	IETypeSDFFilter            = 23  // SDF Filter
	IETypeApplicationID        = 24  // Application ID
	IETypeFSEID                = 57  // F-SEID (Fully Qualified SEID)

	IETypeGateStatus           = 25  // Gate Status
	IETypeMBR                  = 26  // MBR (Maximum Bit Rate)
	IETypeGBR                  = 27  // GBR (Guaranteed Bit Rate)
	IETypeQERCorrelationID     = 28  // QER Correlation ID
	IETypePrecedence           = 29  // Precedence
	IETypePDUSessionType       = 85  // PDU Session Type
	IETypeOuterHeaderRemoval   = 95  // Outer Header Removal
	IETypeOuterHeaderCreation  = 84  // Outer Header Creation
	IETypeUEIPAddr             = 93  // UE IP Address
	IETypeQFI                  = 124 // QFI (QoS Flow Identifier)
	IEType5QI                  = 45  // 5QI (5G QoS Identifier)
	IETypeARP                  = 46  // ARP (Allocation and Retention Priority)
	IETypeSNSSAI               = 148 // S-NSSAI (Network Slice Selection Assistance Information)
	IEType3GPPInterfaceType    = 160 // 3GPP Interface Type
)

// Establishment status constants
const (
	EstablishmentPending     = "Pending"     // Session Establishment Request received, waiting for completion
	EstablishmentEstablished = "Established" // Session Modification received, session is fully established
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

// Session represents a PFCP session with its associated TEIDs
type Session struct {
	SEID         uint64
	LocalSEID    uint64
	RemoteSEID   uint64
	UEIP         net.IP
	UPFIP        net.IP
	GNBIP        net.IP   // Downlink Peer IP (gNB for N3)
	UplinkPeerIP net.IP   // Uplink Peer IP (gNB or prev UPF)
	N9PeerIP     net.IP   // N9 Peer UPF IP (for ULCL: i-upf <-> psa-upf)
	TEIDs        []uint32 // Associated GTP TEIDs
	CreatedAt    time.Time
	ModifiedAt   time.Time
	PDRCount     int
	FARCount     int

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
	QoS5QI      uint8  // 5G QoS Identifier
	ARPPL       uint8  // ARP Priority Level
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
	mu           sync.RWMutex
	sessions     map[uint64]*Session // SEID -> Session
	teidMap      map[uint32]uint64   // TEID -> SEID
	ueIPMap      map[string]uint64   // UE IP string -> primary SEID (for deduplication)
	remoteSEIDMap map[uint64]uint64  // Remote SEID (from PFCP header) -> our internal SEID
	seidCounter  uint64              // Counter for generating unique SEIDs
	// Track session creation timestamps to handle race conditions
	sessionCreationTime map[string]time.Time // UE IP -> creation time
	// Timeout checker
	stopChan chan struct{}
}

// EstablishmentTimeout is the time to wait before marking a pending session as failed
const EstablishmentTimeout = 10 * time.Second

// NewCorrelation creates a new correlation store
func NewCorrelation() *Correlation {
	c := &Correlation{
		sessions:            make(map[uint64]*Session),
		teidMap:             make(map[uint32]uint64),
		ueIPMap:             make(map[string]uint64),
		remoteSEIDMap:       make(map[uint64]uint64),
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
				log.Printf("[PFCP] Session SEID=0x%x (UE IP=%s) marked as Failed - no modification received within %v",
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

	if seid, ok := c.ueIPMap[ueIP]; ok {
		if session, ok := c.sessions[seid]; ok {
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

// getNextSEID generates a sequential SEID for new sessions
// Uses atomic-like pattern with mutex already held by caller
func (c *Correlation) getNextSEID() uint64 {
	c.seidCounter++
	return c.seidCounter
}

// AddSession adds or updates a session
// Each unique UE IP should have exactly one session entry
// This function is thread-safe and handles concurrent session creation
func (c *Correlation) AddSession(session *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If session has no UE IP, we cannot properly deduplicate - skip it
	if session.UEIP == nil {
		log.Printf("[WARN] AddSession: session without UE IP, skipping (SEID=0x%x)", session.SEID)
		return
	}

	ueIPStr := session.UEIP.String()

	// Check if we already have a session for this UE IP
	if existingSEID, exists := c.ueIPMap[ueIPStr]; exists {
		if existingSession, ok := c.sessions[existingSEID]; ok {
			// Only merge if this is clearly an update (same session being modified)
			// Don't merge if the existing session was just created (within 100ms)
			// This prevents race conditions during rapid session establishment
			creationTime, hasTime := c.sessionCreationTime[ueIPStr]
			timeSinceCreation := time.Since(creationTime)

			if hasTime && timeSinceCreation < 100*time.Millisecond {
				// Recent session - likely a race condition, skip this update
				log.Printf("[DEBUG] AddSession: Skipping duplicate for UE IP %s (created %v ago)",
					ueIPStr, timeSinceCreation)
				return
			}

			// Merge with existing session
			log.Printf("[DEBUG] AddSession: Merging session for UE IP %s (existing SEID=0x%x)",
				ueIPStr, existingSEID)

			// Merge TEIDs (avoid duplicates)
			teidSet := make(map[uint32]bool)
			for _, t := range existingSession.TEIDs {
				teidSet[t] = true
			}
			for _, t := range session.TEIDs {
				if !teidSet[t] && t != 0 {
					existingSession.TEIDs = append(existingSession.TEIDs, t)
					c.teidMap[t] = existingSEID
				}
			}
			// Update other fields if they have better data
			if session.DNN != "" && existingSession.DNN == "" {
				existingSession.DNN = session.DNN
			}
			if session.QFI != 0 && existingSession.QFI == 0 {
				existingSession.QFI = session.QFI
			}
			if session.UPFIP != nil && existingSession.UPFIP == nil {
				existingSession.UPFIP = session.UPFIP
			}
			if session.GNBIP != nil && existingSession.GNBIP == nil {
				existingSession.GNBIP = session.GNBIP
			}
			if session.MBRUplink > 0 {
				existingSession.MBRUplink = session.MBRUplink
			}
			if session.MBRDownlink > 0 {
				existingSession.MBRDownlink = session.MBRDownlink
			}
			existingSession.LastActive = time.Now()
			return
		}
	}

	// New session with this UE IP
	// Assign a new sequential SEID if not already set
	if session.SEID == 0 {
		session.SEID = c.getNextSEID()
	}

	// Register this UE IP -> SEID mapping
	c.ueIPMap[ueIPStr] = session.SEID
	c.sessionCreationTime[ueIPStr] = time.Now()

	// Store session
	c.sessions[session.SEID] = session
	for _, teid := range session.TEIDs {
		if teid != 0 {
			c.teidMap[teid] = session.SEID
		}
	}

	log.Printf("[DEBUG] AddSession: New session SEID=0x%x for UE IP %s (total sessions: %d)",
		session.SEID, ueIPStr, len(c.sessions))
}

// RemoveSession removes a session
func (c *Correlation) RemoveSession(seid uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if session, ok := c.sessions[seid]; ok {
		for _, teid := range session.TEIDs {
			delete(c.teidMap, teid)
		}
		// Remove from UE IP map and creation time tracking
		if session.UEIP != nil {
			ueIPStr := session.UEIP.String()
			delete(c.ueIPMap, ueIPStr)
			delete(c.sessionCreationTime, ueIPStr)
		}
		// Remove from remote SEID map
		if session.RemoteSEID != 0 {
			delete(c.remoteSEIDMap, session.RemoteSEID)
		}
		delete(c.sessions, seid)
		log.Printf("[DEBUG] RemoveSession: Removed SEID=0x%x (total sessions: %d)", seid, len(c.sessions))
	}
}

// RegisterRemoteSEID registers a remote SEID (from PFCP header) to our internal SEID
// This enables proper session lookup during Session Deletion per 3GPP TS 29.244
func (c *Correlation) RegisterRemoteSEID(remoteSEID uint64, internalSEID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if remoteSEID != 0 && internalSEID != 0 {
		c.remoteSEIDMap[remoteSEID] = internalSEID
		// Also update the session's RemoteSEID field
		if session, ok := c.sessions[internalSEID]; ok {
			session.RemoteSEID = remoteSEID
			log.Printf("[DEBUG] RegisterRemoteSEID: Mapped remote SEID 0x%x -> internal SEID 0x%x", remoteSEID, internalSEID)
		}
	}
}

// GetSessionByRemoteSEID looks up session by remote SEID (from PFCP header)
func (c *Correlation) GetSessionByRemoteSEID(remoteSEID uint64) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if internalSEID, ok := c.remoteSEIDMap[remoteSEID]; ok {
		if session, ok := c.sessions[internalSEID]; ok {
			return session, true
		}
	}
	return nil, false
}

// RemoveSessionByRemoteSEID removes a session by remote SEID
func (c *Correlation) RemoveSessionByRemoteSEID(remoteSEID uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if internalSEID, ok := c.remoteSEIDMap[remoteSEID]; ok {
		if session, ok := c.sessions[internalSEID]; ok {
			// Clean up all mappings
			for _, teid := range session.TEIDs {
				delete(c.teidMap, teid)
			}
			if session.UEIP != nil {
				ueIPStr := session.UEIP.String()
				delete(c.ueIPMap, ueIPStr)
				delete(c.sessionCreationTime, ueIPStr)
			}
			delete(c.remoteSEIDMap, remoteSEID)
			delete(c.sessions, internalSEID)
			log.Printf("[DEBUG] RemoveSessionByRemoteSEID: Removed remote SEID 0x%x (internal 0x%x, total: %d)", 
				remoteSEID, internalSEID, len(c.sessions))
			return true
		}
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

// AutoDetectInterface automatically detects the best interface for PFCP capture
// It checks for common patterns used by free5gc and other 5G deployments
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
			log.Printf("[AUTO-DETECT] Found free5gc bridge interface: %s", name)
			return name, "free5gc Docker bridge"
		}
	}

	// Priority 2: Look for Docker bridge interfaces (br-*) with IP in common 5G network ranges
	// free5gc typically uses 10.100.200.0/24, but other setups may vary
	commonRanges := []string{"10.100.", "10.200.", "10.60.", "10.61.", "192.168.100.", "172."}
	for _, dev := range devices {
		if !strings.HasPrefix(dev.Name, "br-") {
			continue
		}
		for _, addr := range dev.Addresses {
			ip := addr.IP.String()
			for _, prefix := range commonRanges {
				if strings.HasPrefix(ip, prefix) {
					log.Printf("[AUTO-DETECT] Found Docker bridge with 5G network IP: %s (%s)", dev.Name, ip)
					return dev.Name, fmt.Sprintf("Docker bridge with IP %s", ip)
				}
			}
		}
	}

	// Priority 3: Look for any Docker bridge interface (br-*)
	for _, dev := range devices {
		if strings.HasPrefix(dev.Name, "br-") && dev.Name != "br-lan" {
			log.Printf("[AUTO-DETECT] Found Docker bridge interface: %s", dev.Name)
			return dev.Name, "Docker bridge (generic)"
		}
	}

	// Priority 4: Look for interfaces with IP in 5G network ranges (non-bridge)
	// This handles cases where free5gc runs on host networking
	for _, dev := range devices {
		// Skip loopback and common non-relevant interfaces
		if dev.Name == "lo" || strings.HasPrefix(dev.Name, "veth") ||
			strings.HasPrefix(dev.Name, "docker") || dev.Name == "virbr0" {
			continue
		}
		for _, addr := range dev.Addresses {
			ip := addr.IP.String()
			for _, prefix := range commonRanges {
				if strings.HasPrefix(ip, prefix) {
					log.Printf("[AUTO-DETECT] Found interface with 5G network IP: %s (%s)", dev.Name, ip)
					return dev.Name, fmt.Sprintf("interface with IP %s", ip)
				}
			}
		}
	}

	// Priority 5: Use "any" to capture from all interfaces
	// This is the safest fallback but may capture irrelevant traffic
	log.Printf("[AUTO-DETECT] No specific interface found, using 'any' to capture from all interfaces")
	return "any", "all interfaces (no specific match found)"
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

	// Ensure we have IE data to process
	if ieOffset >= ieDataEnd {
		log.Printf("[PFCP-WARN] No IE data in message (offset=%d, end=%d)", ieOffset, ieDataEnd)
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
		s.handleSessionEstablishmentResponse(seid, ieData)
	case MsgTypeSessionModificationRequest:
		log.Printf("[PFCP-DEBUG] Session Modification Request: SEID=0x%x, UPF=%s", seid, dstIP)
		s.handleSessionModification(seid, ieData, dstIP)
	case MsgTypeSessionModificationResponse:
		log.Printf("[PFCP-DEBUG] Session Modification Response: SEID=0x%x (ignored)", seid)
	case MsgTypeSessionDeletionRequest:
		log.Printf("[PFCP-DEBUG] Session Deletion Request: SEID=0x%x", seid)
		s.handleSessionDeletion(seid)
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

	// Add session (will handle deduplication and SEID assignment)
	s.correlation.AddSession(session)

	log.Printf("   └─ Session created (Pending): TEIDs: %v, UE_IP: %v, UPF_IP: %v, DNN: %s, QFI: %d, MBR: UL=%d/DL=%d kbps",
		session.TEIDs, ueIP, upfIP, session.DNN, session.QFI, session.MBRUplink, session.MBRDownlink)
}

func (s *Sniffer) handleSessionModification(seid uint64, ieData []byte, upfIP net.IP) {
	log.Printf("[PFCP] Session Modification: SEID=0x%x, UPF=%s", seid, upfIP)

	// First try to find session by UE IP (our primary key)
	ueIP := s.extractUEIP(ieData)
	var session *Session
	var ok bool

	if ueIP != nil {
		session, ok = s.correlation.GetSessionByUEIP(ueIP.String())
		if ok {
			log.Printf("   └─ Found session by UE IP %s (SEID=0x%x)", ueIP.String(), session.SEID)
		}
	}

	// If not found by UE IP, try by SEID (fallback)
	if !ok {
		session, ok = s.correlation.GetSessionBySEID(seid)
		if ok {
			log.Printf("   └─ Found session by SEID 0x%x", seid)
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

	// Extract session info from modification IEs
	s.extractSessionInfo(ieData, session)

	// Extract TEIDs and merge with existing (removes duplicates)
	session.TEIDs = s.extractUniqueTEIDs(ieData, session.TEIDs)

	// Extract UE IP if present and not already set
	if session.UEIP == nil && ueIP != nil {
		session.UEIP = ueIP
	}

	// Extract gNB IP from Modification (this is where gNB endpoint info appears)
	s.extractGNBIPFromModification(ieData, session)

	session.ModifiedAt = time.Now()
	session.LastActive = time.Now()
	s.correlation.AddSession(session)

	// Register the PFCP header SEID as a remote SEID for this session
	// This enables proper session lookup during Session Deletion per 3GPP TS 29.244
	if seid != 0 && session.SEID != 0 {
		s.correlation.RegisterRemoteSEID(seid, session.SEID)
	}

	log.Printf("   └─ Updated: TEIDs: %v, UE_IP: %v, UPF_IP: %v, MBR: UL=%d/DL=%d kbps, Status: %s",
		session.TEIDs, session.UEIP, session.UPFIP, session.MBRUplink, session.MBRDownlink, session.EstablishmentStatus)
}

func (s *Sniffer) handleSessionDeletion(seid uint64) {
	log.Printf("PFCP Session Deletion Request: SEID=0x%x", seid)
	
	// Per 3GPP TS 29.244, the SEID in Session Deletion Request is the remote (CP) SEID
	// We need to look up by remote SEID first, then fall back to internal SEID
	
	// Try 1: Look up by remote SEID (most likely match per 3GPP spec)
	if s.correlation.RemoveSessionByRemoteSEID(seid) {
		log.Printf("   └─ Removed session by remote SEID 0x%x (3GPP compliant)", seid)
		return
	}
	
	// Try 2: Look up by internal SEID (fallback for edge cases)
	if session, ok := s.correlation.GetSessionBySEID(seid); ok {
		s.correlation.RemoveSession(seid)
		log.Printf("   └─ Removed session by internal SEID 0x%x (UE: %s)", seid, session.UEIP)
		return
	}
	
	// Session not found - this may happen if we missed the establishment or it was already deleted
	log.Printf("   └─ Session SEID 0x%x not found (may be stale or already deleted)", seid)
}

// handleSessionEstablishmentResponse processes Session Establishment Response to capture UPF's F-SEID
// The header SEID in Response is the SMF's SEID.
// The UPF's assigned SEID is in the F-SEID IE. We need to map UPF-SEID -> Internal-Session.
func (s *Sniffer) handleSessionEstablishmentResponse(smfSEID uint64, ieData []byte) {
	// In Establishment Response (UPF->SMF):
	// - Header SEID = SMF's SEID (current implementation ignores this mapping)
	// - F-SEID IE = UPF's SEID (this is what SMF will use for Deletion Request)

	var upfSEID uint64
	
	log.Printf("[PFCP-DEBUG] Parsing Establishment Response IEs (len=%d)", len(ieData))
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		log.Printf("[PFCP-DEBUG] IE Type: %d (len=%d)", ieType, len(ieValue))
		if ieType == IETypeFSEID {
			// Parse F-SEID (UPF's SEID)
			// Flags (1) + SEID (8) + ...
			log.Printf("[PFCP-DEBUG] Found F-SEID IE: %x", ieValue)
			if len(ieValue) >= 9 {
				upfSEID = binary.BigEndian.Uint64(ieValue[1:9])
				log.Printf("   └─ Found UPF F-SEID: 0x%x", upfSEID)
			}
		}
	})
	
	if upfSEID != 0 {
		// Heuristic: Match with the most recently created PENDING session (within last 5s)
		// This is necessary because we don't track proper PFCP Transaction IDs yet.
		sessions := s.correlation.GetAllSessions()
		var candidate *Session
		var newestTime time.Time
		
		for _, sess := range sessions {
			if sess.EstablishmentStatus == EstablishmentPending && sess.CreatedAt.After(newestTime) {
				newestTime = sess.CreatedAt
				candidate = sess
			}
		}
		
		if candidate != nil {
			// Check if created recently (e.g. < 5 seconds)
			if time.Since(candidate.CreatedAt) < 5*time.Second {
				log.Printf("   └─ Mapping UPF SEID 0x%x -> Internal SEID 0x%x (for UE %s)", upfSEID, candidate.SEID, candidate.UEIP)
				s.correlation.RegisterRemoteSEID(upfSEID, candidate.SEID)
			}
		}
	}
}

// extractSessionInfo extracts DNN, QFI, and other session info from PFCP IEs
func (s *Sniffer) extractSessionInfo(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		switch ieType {
		case IETypeNetworkInstance: // Network Instance (DNN)
			if len(ieValue) > 0 {
				// DNN is encoded as a string (may have length prefix)
				dnn := string(ieValue)
				// Clean up the DNN string
				if len(dnn) > 0 && dnn[0] < 32 {
					// Has length prefix, skip it
					if len(ieValue) > 1 {
						dnn = string(ieValue[1:])
					}
				}
				if len(dnn) > 0 {
					session.DNN = dnn
					log.Printf("   └─ Found DNN: %s", dnn)
				}
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
			log.Printf("   └─ MBR IE length: %d bytes, content: %x", len(ieValue), ieValue)
			if len(ieValue) >= 10 {
				// 5 bytes each: use 40-bit encoding
				ulMBR := uint64(0)
				dlMBR := uint64(0)
				for i := 0; i < 5; i++ {
					ulMBR = (ulMBR << 8) | uint64(ieValue[i])
					dlMBR = (dlMBR << 8) | uint64(ieValue[5+i])
				}
				session.MBRUplink = ulMBR
				session.MBRDownlink = dlMBR
				log.Printf("   └─ Found MBR (10-byte): UL=%d kbps, DL=%d kbps", session.MBRUplink, session.MBRDownlink)
			} else if len(ieValue) >= 8 {
				// Fallback: 4 bytes each (32-bit)
				session.MBRUplink = uint64(binary.BigEndian.Uint32(ieValue[0:4]))
				session.MBRDownlink = uint64(binary.BigEndian.Uint32(ieValue[4:8]))
				log.Printf("   └─ Found MBR (8-byte): UL=%d kbps, DL=%d kbps", session.MBRUplink, session.MBRDownlink)
			} else if len(ieValue) >= 4 {
				// Single direction (uplink only or downlink only)
				// This seems to be the case in current SMF implementation
				session.MBRUplink = uint64(binary.BigEndian.Uint32(ieValue[0:4]))
				log.Printf("   └─ Found MBR (4-byte, UL only): UL=%d kbps", session.MBRUplink)
			}
		case IETypeGBR: // Guaranteed Bit Rate
			if len(ieValue) >= 8 {
				session.GBRUplink = uint64(binary.BigEndian.Uint32(ieValue[0:4]))
				session.GBRDownlink = uint64(binary.BigEndian.Uint32(ieValue[4:8]))
				log.Printf("   └─ Found GBR: UL=%d kbps, DL=%d kbps", session.GBRUplink, session.GBRDownlink)
			}
		case IETypePrecedence: // Precedence (can indicate QoS priority)
			if len(ieValue) >= 4 {
				precedence := binary.BigEndian.Uint32(ieValue[0:4])
				log.Printf("   └─ Found Precedence: %d", precedence)
			}
		case IETypePDUSessionType: // PDU Session Type
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
					session.SessionType = "Unstructured"
				case 5:
					session.SessionType = "Ethernet"
				default:
					session.SessionType = fmt.Sprintf("Type-%d", pduType)
				}
				log.Printf("   └─ Found PDU Session Type: %s", session.SessionType)
			}
		case IEType5QI: // 5QI (5G QoS Identifier)
			if len(ieValue) >= 1 {
				session.QoS5QI = ieValue[0]
				log.Printf("   └─ Found 5QI: %d", session.QoS5QI)
			}
		case IETypeARP: // ARP (Allocation and Retention Priority)
			if len(ieValue) >= 1 {
				// ARP IE format: Priority Level (4 bits) + PCI (1 bit) + PVI (1 bit) + spare (2 bits)
				session.ARPPL = (ieValue[0] >> 4) & 0x0F // Upper 4 bits are priority level
				log.Printf("   └─ Found ARP Priority Level: %d", session.ARPPL)
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

// extractFTEIDDetails extracts F-TEID and Outer Header Creation details
// For ULCL: Outer Header Creation in i-upf's FAR points to psa-upf (N9 interface)
// For single UPF: Outer Header Creation points to gNB (N3)
func (s *Sniffer) extractFTEIDDetails(ieData []byte, session *Session) {
	// Known UPF IPs in ULCL configuration (could be made configurable)
	// For now, we detect UPF IPs by checking common UPF IP patterns
	isUPFIP := func(ip net.IP) bool {
		// Check if IP is in 10.100.200.x range (free5gc-compose network)
		// UPFs are typically at .2, .3, .4 etc, while gNB is at higher addresses like .15
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 10 && ip4[1] == 100 && ip4[2] == 200 {
				// UPFs are typically in lower addresses (2-10), gNB is typically higher
				return ip4[3] >= 2 && ip4[3] <= 10
			}
		}
		return false
	}

	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// Outer Header Creation contains the destination for forwarded packets
		if ieType == IETypeOuterHeaderCreation && len(ieValue) >= 10 {
			// Flags (2) + TEID (4) + IPv4 (4)
			ip := net.IP(make([]byte, 4))
			copy(ip, ieValue[6:10])

			// Skip if it's the same as this UPF's IP
			if session.UPFIP != nil && ip.Equal(session.UPFIP) {
				return
			}

			// Determine if this is N9 (peer UPF) or N3 (gNB) based on IP
			if isUPFIP(ip) {
				// This is likely another UPF (N9 peer)
				if session.N9PeerIP == nil {
					session.N9PeerIP = ip
					log.Printf("   └─ Outer Header Creation N9 peer UPF: %s", ip)
				}
			} else {
				// This is likely gNB (N3)
				if session.GNBIP == nil {
					session.GNBIP = ip
					log.Printf("   └─ Outer Header Creation gNB (N3): %s", ip)
				}
			}
		}
	})
}

// extractGNBIPFromModification extracts gNB IP from Session Modification
// This is where gNB's F-TEID info is provided after gNB responds to AMF
func (s *Sniffer) extractGNBIPFromModification(ieData []byte, session *Session) {
	s.parseIEsRecursive(ieData, func(ieType uint16, ieValue []byte) {
		// Outer Header Creation in Session Modification contains gNB endpoint
		// This is in FAR (Forwarding Action Rules) for downlink
		if ieType == IETypeOuterHeaderCreation && len(ieValue) >= 10 {
			// Flags (2) + TEID (4) + IPv4 (4)
			ip := net.IP(ieValue[6:10])
			// Only update gNB IP if it's different from UPF IP
			if session.UPFIP == nil || !ip.Equal(session.UPFIP) {
				session.GNBIP = ip
				log.Printf("   └─ Outer Header gNB IP: %s", ip)
			}
		}
		// Also check F-TEID in Update FAR which may contain gNB info
		if ieType == IETypeFTEID && len(ieValue) >= 5 {
			flags := ieValue[0]
			offset := 5 // Skip flags (1) + TEID (4)

			// Check for IPv4 address (bit 0)
			if flags&0x01 != 0 && len(ieValue) >= offset+4 {
				ip := net.IP(ieValue[offset : offset+4])
				// If this IP is different from UPF IP, it's likely gNB IP
				if session.UPFIP != nil && !ip.Equal(session.UPFIP) {
					session.GNBIP = ip
					log.Printf("   └─ F-TEID gNB IP from Modification: %s", ip)
				}
			}
		}
	})
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
	c.mu.Lock()
	defer c.mu.Unlock()

	if seid, ok := c.teidMap[teid]; ok {
		if session, ok := c.sessions[seid]; ok {
			if session.UplinkPeerIP == nil || !session.UplinkPeerIP.Equal(peerIP) {
				session.UplinkPeerIP = peerIP
				log.Printf("[PFCP] Updated Uplink Peer IP for SEID 0x%x: %s", session.SEID, peerIP)
			}
		}
	}
}
