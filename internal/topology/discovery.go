package topology

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/solar224/5G-DPOP/internal/gtp5g"
	"github.com/solar224/5G-DPOP/internal/pfcp"
)

// NodeType represents the type of network node
type NodeType string

const (
	NodeTypeUE  NodeType = "ue"
	NodeTypeGNB NodeType = "gnb"
	NodeTypeUPF NodeType = "upf"
	NodeTypeDN  NodeType = "dn"
)

// LinkType represents the type of network link
type LinkType string

const (
	LinkTypeRadio LinkType = "radio" // UE-gNB
	LinkTypeN3    LinkType = "n3"    // gNB-UPF
	LinkTypeN9    LinkType = "n9"    // UPF-UPF (ULCL)
	LinkTypeN6    LinkType = "n6"    // UPF-DN
)

// VerifyMethod indicates how a node/link was verified
type VerifyMethod string

const (
	VerifyMethodGtp5g  VerifyMethod = "gtp5g"
	VerifyMethodPFCP   VerifyMethod = "pfcp"
	VerifyMethodDocker VerifyMethod = "docker"
	VerifyMethodConfig VerifyMethod = "config"
)

// Node represents a network topology node
type Node struct {
	ID           string
	Type         NodeType
	Label        string
	IP           net.IP
	Verified     bool
	VerifyMethod VerifyMethod
	LastSeen     time.Time

	// UPF-specific
	PDRCount    int
	FARCount    int
	ActiveTEIDs []uint32

	// gNB-specific
	ConnectedUEs int

	// UE-specific
	SessionID string
	UEIP      string
}

// Link represents a network topology link
type Link struct {
	Source    string
	Target    string
	Type      LinkType
	TEIDs     []uint32
	HasTraffic bool
	LastActive time.Time
	BytesUL    uint64
	BytesDL    uint64
	Verified   bool
}

// ValidationResult holds the result of topology validation
type ValidationResult struct {
	Timestamp       time.Time
	NodesValidated  int
	LinksValidated  int
	Discrepancies   []string
	UnverifiedNodes []string
	UnverifiedLinks []string
}

// SessionProvider interface for getting session data
type SessionProvider interface {
	GetAllSessions() []*pfcp.Session
	GetDataPlaneActiveSessions() []*pfcp.Session
}

// Discoverer discovers and validates network topology
type Discoverer struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	links map[string]*Link

	// Data sources
	sessions  SessionProvider
	gtp5gReader *gtp5g.Reader

	// Known network configuration
	knownUPFIPs map[string]string // IP -> UPF name (e.g., "i-upf", "psa-upf")
}

// NewDiscoverer creates a new topology discoverer
func NewDiscoverer(sessions SessionProvider) *Discoverer {
	return &Discoverer{
		nodes:       make(map[string]*Node),
		links:       make(map[string]*Link),
		sessions:    sessions,
		gtp5gReader: gtp5g.NewReader(),
		knownUPFIPs: make(map[string]string),
	}
}

// SetKnownUPFIPs sets the known UPF IP addresses for network classification
func (d *Discoverer) SetKnownUPFIPs(upfIPs map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownUPFIPs = upfIPs
}

// DiscoverFromSessions builds topology from active sessions
func (d *Discoverer) DiscoverFromSessions() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sessions == nil {
		return fmt.Errorf("session provider not set")
	}

	sessions := d.sessions.GetAllSessions()

	for _, session := range sessions {
		// Skip non-established sessions
		if session.EstablishmentStatus != pfcp.EstablishmentEstablished {
			continue
		}

		// Add UE node
		if session.UEIP != nil {
			ueID := fmt.Sprintf("ue-%s", session.UEIP.String())
			d.nodes[ueID] = &Node{
				ID:           ueID,
				Type:         NodeTypeUE,
				Label:        session.UEIP.String(),
				IP:           session.UEIP,
				SessionID:    fmt.Sprintf("0x%x", session.SEID),
				UEIP:         session.UEIP.String(),
				Verified:     true,
				VerifyMethod: VerifyMethodPFCP,
				LastSeen:     time.Now(),
			}
		}

		// Add gNB node
		if session.GNBIP != nil {
			gnbID := fmt.Sprintf("gnb-%s", session.GNBIP.String())
			if existing, ok := d.nodes[gnbID]; ok {
				existing.ConnectedUEs++
				existing.LastSeen = time.Now()
			} else {
				d.nodes[gnbID] = &Node{
					ID:           gnbID,
					Type:         NodeTypeGNB,
					Label:        fmt.Sprintf("gNB (%s)", session.GNBIP.String()),
					IP:           session.GNBIP,
					ConnectedUEs: 1,
					Verified:     true,
					VerifyMethod: VerifyMethodPFCP,
					LastSeen:     time.Now(),
				}
			}
		}

		// Add UPF node
		if session.UPFIP != nil {
			upfID := fmt.Sprintf("upf-%s", session.UPFIP.String())
			upfLabel := "UPF"
			if name, ok := d.knownUPFIPs[session.UPFIP.String()]; ok {
				upfLabel = name
			}
			if existing, ok := d.nodes[upfID]; ok {
				existing.ActiveTEIDs = append(existing.ActiveTEIDs, session.TEIDs...)
				existing.LastSeen = time.Now()
			} else {
				d.nodes[upfID] = &Node{
					ID:           upfID,
					Type:         NodeTypeUPF,
					Label:        upfLabel,
					IP:           session.UPFIP,
					ActiveTEIDs:  session.TEIDs,
					Verified:     true,
					VerifyMethod: VerifyMethodPFCP,
					LastSeen:     time.Now(),
				}
			}
		}

		// Add N9 peer UPF (for ULCL)
		if session.N9PeerIP != nil {
			n9upfID := fmt.Sprintf("upf-%s", session.N9PeerIP.String())
			n9Label := "UPF (N9)"
			if name, ok := d.knownUPFIPs[session.N9PeerIP.String()]; ok {
				n9Label = name
			}
			if _, ok := d.nodes[n9upfID]; !ok {
				d.nodes[n9upfID] = &Node{
					ID:           n9upfID,
					Type:         NodeTypeUPF,
					Label:        n9Label,
					IP:           session.N9PeerIP,
					Verified:     true,
					VerifyMethod: VerifyMethodPFCP,
					LastSeen:     time.Now(),
				}
			}
		}
	}

	return nil
}

// DiscoverFromGtp5g enriches topology with gtp5g FAR data
func (d *Discoverer) DiscoverFromGtp5g() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.gtp5gReader.IsAvailable() {
		return fmt.Errorf("gtp5g proc files not available")
	}

	fars, err := d.gtp5gReader.ReadAllFARs()
	if err != nil {
		return fmt.Errorf("failed to read FARs: %w", err)
	}

	for _, far := range fars {
		if far.OuterHeader.PeerIP == "" || far.OuterHeader.TEID == 0 {
			continue
		}

		peerIP := far.OuterHeader.PeerIP

		// Check if this is a known UPF (N9 link) or gNB (N3 link)
		if _, isKnownUPF := d.knownUPFIPs[peerIP]; isKnownUPF {
			// This is an N9 peer UPF
			upfID := fmt.Sprintf("upf-%s", peerIP)
			if node, ok := d.nodes[upfID]; ok {
				node.Verified = true
				node.VerifyMethod = VerifyMethodGtp5g
				node.ActiveTEIDs = append(node.ActiveTEIDs, far.OuterHeader.TEID)
			} else {
				d.nodes[upfID] = &Node{
					ID:           upfID,
					Type:         NodeTypeUPF,
					Label:        d.knownUPFIPs[peerIP],
					IP:           net.ParseIP(peerIP),
					ActiveTEIDs:  []uint32{far.OuterHeader.TEID},
					Verified:     true,
					VerifyMethod: VerifyMethodGtp5g,
					LastSeen:     time.Now(),
				}
			}
		} else {
			// Assume it's a gNB 
			gnbID := fmt.Sprintf("gnb-%s", peerIP)
			if node, ok := d.nodes[gnbID]; ok {
				node.Verified = true
				node.VerifyMethod = VerifyMethodGtp5g
				node.LastSeen = time.Now()
			} else {
				d.nodes[gnbID] = &Node{
					ID:           gnbID,
					Type:         NodeTypeGNB,
					Label:        fmt.Sprintf("gNB (%s)", peerIP),
					IP:           net.ParseIP(peerIP),
					Verified:     true,
					VerifyMethod: VerifyMethodGtp5g,
					LastSeen:     time.Now(),
				}
			}
		}
	}

	return nil
}

// ValidateTopology validates current topology against gtp5g
func (d *Discoverer) ValidateTopology() *ValidationResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := &ValidationResult{
		Timestamp:       time.Now(),
		Discrepancies:   make([]string, 0),
		UnverifiedNodes: make([]string, 0),
		UnverifiedLinks: make([]string, 0),
	}

	// Get active TEIDs from gtp5g
	activeTEIDs, err := d.gtp5gReader.GetActiveSessionTEIDs()
	if err != nil {
		log.Printf("[TOPOLOGY] Warning: cannot validate against gtp5g: %v", err)
		result.Discrepancies = append(result.Discrepancies, fmt.Sprintf("gtp5g not available: %v", err))
		return result
	}

	// Validate each UPF node's TEIDs
	for _, node := range d.nodes {
		result.NodesValidated++

		if !node.Verified {
			result.UnverifiedNodes = append(result.UnverifiedNodes, node.ID)
		}

		if node.Type == NodeTypeUPF && len(node.ActiveTEIDs) > 0 {
			// Check if TEIDs are present in gtp5g
			missingTEIDs := 0
			for _, teid := range node.ActiveTEIDs {
				if !activeTEIDs[teid] {
					missingTEIDs++
				}
			}
			if missingTEIDs > 0 {
				result.Discrepancies = append(result.Discrepancies,
					fmt.Sprintf("UPF %s: %d/%d TEIDs not in gtp5g", node.ID, missingTEIDs, len(node.ActiveTEIDs)))
			}
		}
	}

	// Validate links
	for _, link := range d.links {
		result.LinksValidated++
		if !link.Verified {
			result.UnverifiedLinks = append(result.UnverifiedLinks, fmt.Sprintf("%s->%s", link.Source, link.Target))
		}
	}

	return result
}

// GetNodes returns all discovered nodes
func (d *Discoverer) GetNodes() []*Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	nodes := make([]*Node, 0, len(d.nodes))
	for _, n := range d.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// GetLinks returns all discovered links
func (d *Discoverer) GetLinks() []*Link {
	d.mu.RLock()
	defer d.mu.RUnlock()

	links := make([]*Link, 0, len(d.links))
	for _, l := range d.links {
		links = append(links, l)
	}
	return links
}

// GetSummary returns a summary of the topology
type TopologySummary struct {
	TotalNodes      int
	TotalLinks      int
	VerifiedNodes   int
	UnverifiedNodes int
	UECount         int
	GNBCount        int
	UPFCount        int
}

func (d *Discoverer) GetSummary() *TopologySummary {
	d.mu.RLock()
	defer d.mu.RUnlock()

	summary := &TopologySummary{
		TotalNodes: len(d.nodes),
		TotalLinks: len(d.links),
	}

	for _, node := range d.nodes {
		if node.Verified {
			summary.VerifiedNodes++
		} else {
			summary.UnverifiedNodes++
		}

		switch node.Type {
		case NodeTypeUE:
			summary.UECount++
		case NodeTypeGNB:
			summary.GNBCount++
		case NodeTypeUPF:
			summary.UPFCount++
		}
	}

	return summary
}

// Reset clears all discovered topology data
func (d *Discoverer) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.nodes = make(map[string]*Node)
	d.links = make(map[string]*Link)
}
