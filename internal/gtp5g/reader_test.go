package gtp5g

import (
	"os"
	"path/filepath"
	"testing"
)

// Test data mimicking /proc/gtp5g/pdr format
const testPDRData = `pdr_id=1 seid=0x1 precedence=255 outer_hdr_removal=0 teid=0x1 ue_ip=10.60.0.1 far_id=1
pdr_id=2 seid=0x1 precedence=255 outer_hdr_removal=0 teid=0x2 ue_ip=10.60.0.1 far_id=2
pdr_id=3 seid=0x2 precedence=255 outer_hdr_removal=0 teid=0x5 ue_ip=10.60.0.2 far_id=3
`

// Test data mimicking /proc/gtp5g/far format
// Use peer_addr or ohc_ip which matches reader.go regex patterns
const testFARData = `far_id=1 seid=0x1 apply_action=2 outer_hdr_creation=256 peer_addr=10.100.200.7 ohc_teid=0x1
far_id=2 seid=0x1 apply_action=2 outer_hdr_creation=256 peer_addr=10.100.200.3 ohc_teid=0x3
far_id=3 seid=0x2 apply_action=2 outer_hdr_creation=256 peer_addr=10.100.200.2 ohc_teid=0x6
`

// Test data mimicking /proc/gtp5g/qer format
const testQERData = `qer_id=1 seid=0x1 gate_status=0 mbr_ul=208000000 mbr_dl=208000000 qfi=2
qer_id=2 seid=0x1 gate_status=0 mbr_ul=208000000 mbr_dl=208000000 qfi=2
qer_id=3 seid=0x2 gate_status=0 mbr_ul=104000000 mbr_dl=104000000 qfi=5
`

// createTestFiles creates temporary test proc files
func createTestFiles(t *testing.T) (string, func()) {
	tmpDir, err := os.MkdirTemp("", "gtp5g-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	pdrPath := filepath.Join(tmpDir, "pdr")
	farPath := filepath.Join(tmpDir, "far")
	qerPath := filepath.Join(tmpDir, "qer")

	if err := os.WriteFile(pdrPath, []byte(testPDRData), 0644); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to write PDR file: %v", err)
	}
	if err := os.WriteFile(farPath, []byte(testFARData), 0644); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to write FAR file: %v", err)
	}
	if err := os.WriteFile(qerPath, []byte(testQERData), 0644); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to write QER file: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

func TestReaderReadAllPDRs(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	pdrs, err := reader.ReadAllPDRs()
	if err != nil {
		t.Fatalf("ReadAllPDRs failed: %v", err)
	}

	if len(pdrs) != 3 {
		t.Errorf("Expected 3 PDRs, got %d", len(pdrs))
	}

	// Verify first PDR
	if len(pdrs) >= 1 {
		pdr := pdrs[0]
		if pdr.ID != 1 {
			t.Errorf("Expected PDR ID 1, got %d", pdr.ID)
		}
		if pdr.SEID != 1 {
			t.Errorf("Expected SEID 1, got %d", pdr.SEID)
		}
	}
}

func TestReaderReadAllFARs(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	fars, err := reader.ReadAllFARs()
	if err != nil {
		t.Fatalf("ReadAllFARs failed: %v", err)
	}

	if len(fars) != 3 {
		t.Errorf("Expected 3 FARs, got %d", len(fars))
	}

	// Verify FAR with peer IP
	if len(fars) >= 1 {
		far := fars[0]
		if far.ID != 1 {
			t.Errorf("Expected FAR ID 1, got %d", far.ID)
		}
		if far.OuterHeader.PeerIP != "10.100.200.7" {
			t.Errorf("Expected Peer IP 10.100.200.7, got %s", far.OuterHeader.PeerIP)
		}
	}
}

func TestReaderReadAllQERs(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	qers, err := reader.ReadAllQERs()
	if err != nil {
		t.Fatalf("ReadAllQERs failed: %v", err)
	}

	if len(qers) != 3 {
		t.Errorf("Expected 3 QERs, got %d", len(qers))
	}

	// Verify QoS parameters (3GPP TS 23.501 compliant)
	// MBR values should be non-negative
	for _, qer := range qers {
		if qer.MBR.UL < 0 {
			t.Errorf("MBR UL should be non-negative, got %d", qer.MBR.UL)
		}
		if qer.MBR.DL < 0 {
			t.Errorf("MBR DL should be non-negative, got %d", qer.MBR.DL)
		}
	}
}

func TestReaderGetActiveSessionTEIDs(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	teids, err := reader.GetActiveSessionTEIDs()
	if err != nil {
		t.Fatalf("GetActiveSessionTEIDs failed: %v", err)
	}

	// Should have TEIDs from PDRs
	if len(teids) == 0 {
		t.Errorf("Expected some TEIDs, got none")
	}
}

func TestReaderGetSEIDToTEIDMapping(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	mapping, err := reader.GetSEIDToTEIDMapping()
	if err != nil {
		t.Fatalf("GetSEIDToTEIDMapping failed: %v", err)
	}

	// Should have 2 unique SEIDs (0x1 and 0x2)
	if len(mapping) != 2 {
		t.Errorf("Expected 2 unique SEIDs, got %d", len(mapping))
	}
}

func TestReaderGetPeerIPs(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	peerIPs, err := reader.GetPeerIPs()
	if err != nil {
		t.Fatalf("GetPeerIPs failed: %v", err)
	}

	// Should have 3 unique peer IPs from FAR data
	expectedPeers := []string{"10.100.200.7", "10.100.200.3", "10.100.200.2"}
	for _, peer := range expectedPeers {
		if _, exists := peerIPs[peer]; !exists {
			t.Errorf("Expected peer IP %s to be present", peer)
		}
	}
}

func TestReaderValidateSession(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	// Test with valid SEID (0x1)
	validation, err := reader.ValidateSession(1, []uint32{1, 2})
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}

	if validation == nil {
		t.Fatal("Expected validation result, got nil")
	}

	if validation.SEID != 1 {
		t.Errorf("Expected SEID 1, got %d", validation.SEID)
	}
}

func TestReaderGetSummary(t *testing.T) {
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader := NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)

	summary, err := reader.GetSummary()
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if summary.PDRCount != 3 {
		t.Errorf("Expected PDR count 3, got %d", summary.PDRCount)
	}
	if summary.FARCount != 3 {
		t.Errorf("Expected FAR count 3, got %d", summary.FARCount)
	}
	if summary.QERCount != 3 {
		t.Errorf("Expected QER count 3, got %d", summary.QERCount)
	}
	if summary.UniqueSEID != 2 {
		t.Errorf("Expected 2 unique SEIDs, got %d", summary.UniqueSEID)
	}
}

func TestReaderIsAvailable(t *testing.T) {
	// Test with non-existent paths
	reader := NewReaderWithPaths("/nonexistent/pdr", "/nonexistent/far", "/nonexistent/qer")
	if reader.IsAvailable() {
		t.Error("Expected IsAvailable to return false for non-existent paths")
	}

	// Test with existing paths
	tmpDir, cleanup := createTestFiles(t)
	defer cleanup()

	reader = NewReaderWithPaths(
		filepath.Join(tmpDir, "pdr"),
		filepath.Join(tmpDir, "far"),
		filepath.Join(tmpDir, "qer"),
	)
	if !reader.IsAvailable() {
		t.Error("Expected IsAvailable to return true for existing paths")
	}
}
