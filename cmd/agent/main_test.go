package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/solar224/5G-DPOP/internal/ebpf"
	"github.com/solar224/5G-DPOP/internal/pfcp"
)

func TestConvertSessionExposesOnlySemanticallyNamedIdentifiers(t *testing.T) {
	session := &pfcp.Session{
		SEID:      3,
		CPSEID:    0x101,
		UPSEID:    0x201,
		Source:    "pfcp",
		UEIP:      net.ParseIP("10.60.0.2"),
		TEIDs:     []uint32{0x0a},
		CreatedAt: time.Now(),
		FlowRules: []pfcp.FlowRule{{
			PDRID:                9,
			FARID:                10,
			SourceInterface:      0,
			SourceInterfaceType:  11,
			DestinationInterface: 0,
			InterfaceType:        11,
			LocalFTEID:           0x0a,
			LocalFTEIDIP:         net.ParseIP("10.100.200.10"),
			OuterTEID:            0x03,
			OuterDst:             net.ParseIP("10.100.200.17"),
			PathType:             "n3",
		}},
	}

	converted := convertSessionToJSON(session)
	if converted.ObservationID != "obs-3" ||
		converted.CPSEID != "0x101" ||
		converted.UPSEID != "0x201" ||
		len(converted.LocalFTEIDs) != 1 ||
		converted.LocalFTEIDs[0] != "0xa" {
		t.Fatalf("identifier conversion is wrong: %+v", converted)
	}
	if converted.FlowRules[0].LocalFTEID != "0xa" ||
		converted.FlowRules[0].OuterTEID != "0x3" {
		t.Fatalf("tunnel endpoint conversion is wrong: %+v", converted.FlowRules[0])
	}

	encoded, err := json.Marshal(converted)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"seid", "teids", "teid_ul", "teid_dl"} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("ambiguous legacy field %q is still exposed: %s", forbidden, encoded)
		}
	}
	for _, unobserved := range []string{"status", "establishment_status", "data_plane_status"} {
		if _, exists := fields[unobserved]; exists {
			t.Fatalf("unobserved state %q was fabricated: %s", unobserved, encoded)
		}
	}
}

func TestBuildDropEventClassifiesIPv6RouterSolicitationAsInfrastructure(t *testing.T) {
	pfcpCorrelation = pfcp.NewCorrelation()
	defer pfcpCorrelation.Stop()

	event := ebpf.DropEvent{
		Timestamp:  123,
		PktLen:     48,
		Reason:     ebpf.DropReasonGeneral,
		Direction:  ebpf.DirectionUnknown,
		Family:     6,
		L4Protocol: 58,
		Origin:     ebpf.OriginDevXmit,
		ICMPType:   133,
	}

	drop := buildDropEventJSON(event, ebpf.FormatDropReason(event.Reason),
		ebpf.FormatDirection(event.Direction))

	if drop.Scope != "infrastructure" ||
		drop.Classification != "ipv6_router_solicitation" ||
		drop.Direction != "unknown" {
		t.Fatalf("unexpected IPv6 RS classification: %+v", drop)
	}
	if drop.TEID != "" || drop.SrcIP != "" || drop.DstIP != "" ||
		drop.SrcPort != 0 || drop.DstPort != 0 {
		t.Fatalf("invalid packet fields were exposed as facts: %+v", drop)
	}
}

func TestBuildDropEventPreservesOnlyValidatedIPv4Fields(t *testing.T) {
	pfcpCorrelation = pfcp.NewCorrelation()
	defer pfcpCorrelation.Stop()

	event := ebpf.DropEvent{
		Timestamp:   456,
		TEID:        0x10203040,
		SrcIP:       0x0100000a,
		DstIP:       0x08080808,
		PktLen:      128,
		SrcPort:     49152,
		DstPort:     2152,
		ValidFields: ebpf.FieldTEID | ebpf.FieldSrcIP | ebpf.FieldDstIP,
		Reason:      ebpf.DropReasonNoPDR,
		Direction:   ebpf.DirectionUplink,
		Family:      4,
		L4Protocol:  17,
		Origin:      ebpf.OriginEncapRecv,
	}

	drop := buildDropEventJSON(event, ebpf.FormatDropReason(event.Reason),
		ebpf.FormatDirection(event.Direction))

	if drop.Scope != "user-plane" || drop.TEID != "0x10203040" ||
		drop.SrcIP != "10.0.0.1" || drop.DstIP != "8.8.8.8" {
		t.Fatalf("validated fields were not preserved: %+v", drop)
	}
	if drop.SrcPort != 0 || drop.DstPort != 0 {
		t.Fatalf("unvalidated ports were exposed: %+v", drop)
	}
}

func TestMonotonicCounterDeltaHandlesReset(t *testing.T) {
	if got := monotonicCounterDelta(1_500, 500); got != 1_000 {
		t.Fatalf("normal delta = %d, want 1000", got)
	}
	if got := monotonicCounterDelta(100, 500); got != 0 {
		t.Fatalf("counter reset delta = %d, want 0", got)
	}
}

func TestUserPlaneDropRateUsesSuccessfulPlusDroppedAttempts(t *testing.T) {
	if got := userPlaneDropRate(99, 1); got != 1 {
		t.Fatalf("drop rate = %v%%, want 1%%", got)
	}
	if got := userPlaneDropRate(0, 0); got != 0 {
		t.Fatalf("empty drop rate = %v%%, want 0%%", got)
	}
}
