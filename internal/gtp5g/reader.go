package gtp5g

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PDRInfo represents a gtp5g PDR entry
type PDRInfo struct {
	ID          uint16
	SEID        uint64
	TEID        uint32
	UEIPv4      string
	OuterHdrRem bool
	FARID       uint32
	Precedence  uint32
	Interface   string // "Access" or "Core"
}

// FARInfo represents a gtp5g FAR entry
type FARInfo struct {
	ID          uint32
	SEID        uint64
	ApplyAction uint8
	OuterHeader struct {
		TEID   uint32
		PeerIP string
	}
	ForwardingPolicy string
}

// QERInfo represents a gtp5g QER entry
type QERInfo struct {
	ID         uint32
	SEID       uint64
	GateStatus struct {
		UL bool // true = open, false = closed
		DL bool
	}
	MBR struct {
		UL uint64 // bits per second
		DL uint64
	}
	GBR struct {
		UL uint64
		DL uint64
	}
}

// SessionValidation represents validation result for a session
type SessionValidation struct {
	SEID            uint64
	TEIDsFound      []uint32
	TEIDsMissing    []uint32
	PDRCount        int
	FARCount        int
	QERCount        int
	IsValid         bool
	ValidationTime  time.Time
	DiscrepancyNote string
}

// Reader reads gtp5g proc files
type Reader struct {
	pdrPath string
	farPath string
	qerPath string

	mu           sync.RWMutex
	lastPDRs     []PDRInfo
	lastFARs     []FARInfo
	lastQERs     []QERInfo
	lastReadTime time.Time
	cacheTTL     time.Duration
}

// NewReader creates a new gtp5g reader
func NewReader() *Reader {
	return &Reader{
		pdrPath:  "/proc/gtp5g/pdr",
		farPath:  "/proc/gtp5g/far",
		qerPath:  "/proc/gtp5g/qer",
		cacheTTL: 5 * time.Second, // Cache for 5 seconds to avoid excessive reads
	}
}

// NewReaderWithPaths creates a reader with custom proc paths (for testing)
func NewReaderWithPaths(pdrPath, farPath, qerPath string) *Reader {
	return &Reader{
		pdrPath:  pdrPath,
		farPath:  farPath,
		qerPath:  qerPath,
		cacheTTL: 5 * time.Second,
	}
}

// IsAvailable checks if gtp5g proc files are accessible
func (r *Reader) IsAvailable() bool {
	if _, err := os.Stat(r.pdrPath); err != nil {
		return false
	}
	return true
}

// ReadAllPDRs reads all PDR entries from /proc/gtp5g/pdr
func (r *Reader) ReadAllPDRs() ([]PDRInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return cached data if still valid
	if time.Since(r.lastReadTime) < r.cacheTTL && len(r.lastPDRs) > 0 {
		return r.lastPDRs, nil
	}

	data, err := os.ReadFile(r.pdrPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read gtp5g pdr: %w", err)
	}

	pdrs, err := r.parsePDRData(string(data))
	if err != nil {
		return nil, err
	}

	r.lastPDRs = pdrs
	r.lastReadTime = time.Now()
	return pdrs, nil
}

// parsePDRData parses PDR data from proc content
// Expected format (may vary by gtp5g version):
// pdr_id=1 seid=0x1 teid=0x1 ue_ip=10.60.0.1 far_id=1 precedence=255
func (r *Reader) parsePDRData(content string) ([]PDRInfo, error) {
	var pdrs []PDRInfo

	// Common patterns in gtp5g proc output
	pdrIDRe := regexp.MustCompile(`pdr_id[=:](\d+)`)
	seidRe := regexp.MustCompile(`seid[=:]0x([0-9a-fA-F]+)`)
	teidRe := regexp.MustCompile(`teid[=:]0x([0-9a-fA-F]+)`)
	ueIPRe := regexp.MustCompile(`ue_ip[=:](\d+\.\d+\.\d+\.\d+)`)
	farIDRe := regexp.MustCompile(`far_id[=:](\d+)`)
	precedenceRe := regexp.MustCompile(`precedence[=:](\d+)`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		pdr := PDRInfo{}

		// Parse PDR ID
		if match := pdrIDRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 16); err == nil {
				pdr.ID = uint16(val)
			}
		}

		// Parse SEID
		if match := seidRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 16, 64); err == nil {
				pdr.SEID = val
			}
		}

		// Parse TEID
		if match := teidRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 16, 32); err == nil {
				pdr.TEID = uint32(val)
			}
		}

		// Parse UE IP
		if match := ueIPRe.FindStringSubmatch(line); len(match) > 1 {
			pdr.UEIPv4 = match[1]
		}

		// Parse FAR ID
		if match := farIDRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 32); err == nil {
				pdr.FARID = uint32(val)
			}
		}

		// Parse Precedence
		if match := precedenceRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 32); err == nil {
				pdr.Precedence = uint32(val)
			}
		}

		// Determine interface type based on content
		if strings.Contains(strings.ToLower(line), "access") || pdr.TEID > 0 {
			pdr.Interface = "Access" // Uplink PDR typically has TEID
		} else {
			pdr.Interface = "Core" // Downlink PDR typically matches by UE IP
		}

		// Only add if we have at least SEID or TEID
		if pdr.SEID > 0 || pdr.TEID > 0 {
			pdrs = append(pdrs, pdr)
		}
	}

	return pdrs, scanner.Err()
}

// ReadAllFARs reads all FAR entries from /proc/gtp5g/far
func (r *Reader) ReadAllFARs() ([]FARInfo, error) {
	data, err := os.ReadFile(r.farPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read gtp5g far: %w", err)
	}

	return r.parseFARData(string(data))
}

// parseFARData parses FAR data from proc content
func (r *Reader) parseFARData(content string) ([]FARInfo, error) {
	var fars []FARInfo

	farIDRe := regexp.MustCompile(`far_id[=:](\d+)`)
	seidRe := regexp.MustCompile(`seid[=:]0x([0-9a-fA-F]+)`)
	applyActionRe := regexp.MustCompile(`apply_action[=:](\d+)`)
	ohcTEIDRe := regexp.MustCompile(`ohc_teid[=:]0x([0-9a-fA-F]+)`)
	ohcIPRe := regexp.MustCompile(`ohc_ip[=:](\d+\.\d+\.\d+\.\d+)`)
	// Also try peer_addr pattern
	peerAddrRe := regexp.MustCompile(`peer_addr[=:](\d+\.\d+\.\d+\.\d+)`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		far := FARInfo{}

		// Parse FAR ID
		if match := farIDRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 32); err == nil {
				far.ID = uint32(val)
			}
		}

		// Parse SEID
		if match := seidRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 16, 64); err == nil {
				far.SEID = val
			}
		}

		// Parse Apply Action
		if match := applyActionRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 8); err == nil {
				far.ApplyAction = uint8(val)
			}
		}

		// Parse Outer Header Creation TEID
		if match := ohcTEIDRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 16, 32); err == nil {
				far.OuterHeader.TEID = uint32(val)
			}
		}

		// Parse Outer Header Creation IP (try both patterns)
		if match := ohcIPRe.FindStringSubmatch(line); len(match) > 1 {
			far.OuterHeader.PeerIP = match[1]
		} else if match := peerAddrRe.FindStringSubmatch(line); len(match) > 1 {
			far.OuterHeader.PeerIP = match[1]
		}

		// Only add if we have FAR ID
		if far.ID > 0 {
			fars = append(fars, far)
		}
	}

	return fars, scanner.Err()
}

// ReadAllQERs reads all QER entries from /proc/gtp5g/qer
func (r *Reader) ReadAllQERs() ([]QERInfo, error) {
	data, err := os.ReadFile(r.qerPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read gtp5g qer: %w", err)
	}

	return r.parseQERData(string(data))
}

// parseQERData parses QER data from proc content
func (r *Reader) parseQERData(content string) ([]QERInfo, error) {
	var qers []QERInfo

	qerIDRe := regexp.MustCompile(`qer_id[=:](\d+)`)
	seidRe := regexp.MustCompile(`seid[=:]0x([0-9a-fA-F]+)`)
	ulGateRe := regexp.MustCompile(`ul_gate[=:](\d+)`)
	dlGateRe := regexp.MustCompile(`dl_gate[=:](\d+)`)
	ulMBRRe := regexp.MustCompile(`ul_mbr[=:](\d+)`)
	dlMBRRe := regexp.MustCompile(`dl_mbr[=:](\d+)`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		qer := QERInfo{}

		// Parse QER ID
		if match := qerIDRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 32); err == nil {
				qer.ID = uint32(val)
			}
		}

		// Parse SEID
		if match := seidRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 16, 64); err == nil {
				qer.SEID = val
			}
		}

		// Parse gate status (0 = open, 1 = closed typically)
		if match := ulGateRe.FindStringSubmatch(line); len(match) > 1 {
			qer.GateStatus.UL = match[1] == "0"
		}
		if match := dlGateRe.FindStringSubmatch(line); len(match) > 1 {
			qer.GateStatus.DL = match[1] == "0"
		}

		// Parse MBR
		if match := ulMBRRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 64); err == nil {
				qer.MBR.UL = val
			}
		}
		if match := dlMBRRe.FindStringSubmatch(line); len(match) > 1 {
			if val, err := strconv.ParseUint(match[1], 10, 64); err == nil {
				qer.MBR.DL = val
			}
		}

		if qer.ID > 0 {
			qers = append(qers, qer)
		}
	}

	return qers, scanner.Err()
}

// GetActiveSessionTEIDs returns a map of all active TEIDs in gtp5g
func (r *Reader) GetActiveSessionTEIDs() (map[uint32]bool, error) {
	pdrs, err := r.ReadAllPDRs()
	if err != nil {
		return nil, err
	}

	teids := make(map[uint32]bool)
	for _, pdr := range pdrs {
		if pdr.TEID > 0 {
			teids[pdr.TEID] = true
		}
	}
	return teids, nil
}

// GetSEIDToTEIDMapping returns a map from SEID to TEIDs
func (r *Reader) GetSEIDToTEIDMapping() (map[uint64][]uint32, error) {
	pdrs, err := r.ReadAllPDRs()
	if err != nil {
		return nil, err
	}

	mapping := make(map[uint64][]uint32)
	for _, pdr := range pdrs {
		if pdr.SEID > 0 && pdr.TEID > 0 {
			mapping[pdr.SEID] = append(mapping[pdr.SEID], pdr.TEID)
		}
	}
	return mapping, nil
}

// GetPeerIPs returns a map of all peer IPs from FAR outer header creation
// This helps identify gNB and peer UPF addresses
func (r *Reader) GetPeerIPs() (map[string][]uint32, error) {
	fars, err := r.ReadAllFARs()
	if err != nil {
		return nil, err
	}

	// Map from peer IP to list of TEIDs
	peers := make(map[string][]uint32)
	for _, far := range fars {
		if far.OuterHeader.PeerIP != "" && far.OuterHeader.TEID > 0 {
			peers[far.OuterHeader.PeerIP] = append(peers[far.OuterHeader.PeerIP], far.OuterHeader.TEID)
		}
	}
	return peers, nil
}

// ValidateSession checks if a session with given TEIDs exists in gtp5g
func (r *Reader) ValidateSession(seid uint64, teids []uint32) (*SessionValidation, error) {
	validation := &SessionValidation{
		SEID:           seid,
		ValidationTime: time.Now(),
		IsValid:        true,
	}

	activeTEIDs, err := r.GetActiveSessionTEIDs()
	if err != nil {
		return nil, err
	}

	pdrs, _ := r.ReadAllPDRs()
	fars, _ := r.ReadAllFARs()
	qers, _ := r.ReadAllQERs()

	// Count PDRs/FARs/QERs for this SEID
	for _, pdr := range pdrs {
		if pdr.SEID == seid {
			validation.PDRCount++
		}
	}
	for _, far := range fars {
		if far.SEID == seid {
			validation.FARCount++
		}
	}
	for _, qer := range qers {
		if qer.SEID == seid {
			validation.QERCount++
		}
	}

	// Check each TEID
	for _, teid := range teids {
		if activeTEIDs[teid] {
			validation.TEIDsFound = append(validation.TEIDsFound, teid)
		} else {
			validation.TEIDsMissing = append(validation.TEIDsMissing, teid)
			validation.IsValid = false
		}
	}

	if len(validation.TEIDsMissing) > 0 {
		validation.DiscrepancyNote = fmt.Sprintf("%d TEIDs not found in gtp5g", len(validation.TEIDsMissing))
	}

	return validation, nil
}

// Summary returns a summary of the current gtp5g state
type Gtp5gSummary struct {
	PDRCount   int
	FARCount   int
	QERCount   int
	UniqueSEID int
	UniqueTEID int
	PeerIPs    []string
	ReadTime   time.Time
}

// GetSummary returns a summary of the gtp5g state
func (r *Reader) GetSummary() (*Gtp5gSummary, error) {
	pdrs, err := r.ReadAllPDRs()
	if err != nil {
		return nil, err
	}

	fars, _ := r.ReadAllFARs()
	qers, _ := r.ReadAllQERs()
	peers, _ := r.GetPeerIPs()

	seidSet := make(map[uint64]bool)
	teidSet := make(map[uint32]bool)

	for _, pdr := range pdrs {
		if pdr.SEID > 0 {
			seidSet[pdr.SEID] = true
		}
		if pdr.TEID > 0 {
			teidSet[pdr.TEID] = true
		}
	}

	peerList := make([]string, 0, len(peers))
	for ip := range peers {
		peerList = append(peerList, ip)
	}

	return &Gtp5gSummary{
		PDRCount:   len(pdrs),
		FARCount:   len(fars),
		QERCount:   len(qers),
		UniqueSEID: len(seidSet),
		UniqueTEID: len(teidSet),
		PeerIPs:    peerList,
		ReadTime:   time.Now(),
	}, nil
}
