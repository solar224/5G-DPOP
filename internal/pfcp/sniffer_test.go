package pfcp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestSessionDeletionWithoutIEsRemovesSessionByUPFSEID(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()

	const upSEID = uint64(0x11223344)
	session := &Session{
		SEID:                1,
		UPSEID:              upSEID,
		UEIP:                net.ParseIP("10.60.0.1"),
		UPFIP:               net.ParseIP("127.0.0.8"),
		TEIDs:               []uint32{2},
		CreatedAt:           time.Now(),
		EstablishmentStatus: EstablishmentEstablished,
	}
	correlation.AddSession(session)

	sniffer := NewSniffer("lo", 8805, correlation)
	sniffer.processPacket(makePFCPDeletionPacket(t, upSEID))

	if correlation.SessionCount() != 0 {
		t.Fatalf("empty-IE deletion did not remove session: %+v", correlation.GetAllSessions())
	}
}

func TestSuccessfulEstablishmentResponseConfirmsSession(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	upfIP := net.ParseIP("10.100.200.4")
	session := &Session{
		SEID:                1,
		CPSEID:              0x99,
		UEIP:                net.ParseIP("10.60.0.2"),
		UPFIP:               upfIP,
		TEIDs:               []uint32{6},
		CreatedAt:           time.Now(),
		EstablishmentTime:   time.Now(),
		EstablishmentStatus: EstablishmentPending,
		Status:              "Pending",
	}
	correlation.AddSession(session)

	const upSEID = uint64(0x1020304050607080)
	fseid := make([]byte, 9)
	fseid[0] = 0x02 // IPv4 address is present after the SEID.
	binary.BigEndian.PutUint64(fseid[1:9], upSEID)
	ies := append(encodePFCPTestIE(IETypeCause, []byte{1}),
		encodePFCPTestIE(IETypeFSEID, fseid)...)

	NewSniffer("lo", 8805, correlation).
		handleSessionEstablishmentResponse(0x99, ies, upfIP)

	confirmed, ok := correlation.GetSessionBySEID(session.SEID)
	if !ok || confirmed.EstablishmentStatus != EstablishmentEstablished ||
		confirmed.Status != "Active" || confirmed.CPSEID != 0x99 ||
		confirmed.UPSEID != upSEID {
		t.Fatalf("accepted response did not confirm session: %+v", confirmed)
	}
	if mapped, ok := correlation.GetSessionByUPSEID(upfIP, upSEID); !ok || mapped.SEID != session.SEID {
		t.Fatalf("UP F-SEID was not registered: %+v, ok=%v", mapped, ok)
	}
}

func TestExtractTopLevelFSEIDReadsCPIdentityWithoutNestedGuess(t *testing.T) {
	topLevel := make([]byte, 13)
	topLevel[0] = 0x02
	binary.BigEndian.PutUint64(topLevel[1:9], 0x1122334455667788)
	copy(topLevel[9:13], net.ParseIP("127.0.0.1").To4())

	nested := make([]byte, 9)
	binary.BigEndian.PutUint64(nested[1:9], 0x9999)
	data := append(
		encodePFCPTestIE(IETypeFSEID, topLevel),
		encodePFCPTestIE(
			IETypeCreatePDR,
			encodePFCPTestIE(IETypeFSEID, nested),
		)...,
	)

	if got := extractTopLevelFSEID(data); got != 0x1122334455667788 {
		t.Fatalf("CP F-SEID = 0x%x, want 0x1122334455667788", got)
	}
}

func TestRejectedEstablishmentResponseDoesNotConfirmSession(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	upfIP := net.ParseIP("10.100.200.4")
	session := &Session{
		SEID:                1,
		CPSEID:              0x99,
		UEIP:                net.ParseIP("10.60.0.2"),
		UPFIP:               upfIP,
		CreatedAt:           time.Now(),
		EstablishmentTime:   time.Now(),
		EstablishmentStatus: EstablishmentPending,
		Status:              "Pending",
	}
	correlation.AddSession(session)

	NewSniffer("lo", 8805, correlation).
		handleSessionEstablishmentResponse(0x99, encodePFCPTestIE(IETypeCause, []byte{64}), upfIP)

	got, _ := correlation.GetSessionBySEID(session.SEID)
	if got.EstablishmentStatus != EstablishmentPending {
		t.Fatalf("rejected response changed session state: %+v", got)
	}
}

func TestEstablishmentResponseUsesExactCPSEIDWithConcurrentPendingSessions(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	upfIP := net.ParseIP("10.100.200.4")

	first := &Session{
		CPSEID:              0x101,
		UEIP:                net.ParseIP("10.60.0.1"),
		UPFIP:               upfIP,
		CreatedAt:           time.Now(),
		EstablishmentTime:   time.Now(),
		EstablishmentStatus: EstablishmentPending,
	}
	second := &Session{
		CPSEID:              0x202,
		UEIP:                net.ParseIP("10.60.0.2"),
		UPFIP:               upfIP,
		CreatedAt:           time.Now().Add(time.Millisecond),
		EstablishmentTime:   time.Now(),
		EstablishmentStatus: EstablishmentPending,
	}
	correlation.AddSession(first)
	correlation.AddSession(second)

	const upSEID = uint64(0x9002)
	fseid := make([]byte, 9)
	binary.BigEndian.PutUint64(fseid[1:9], upSEID)
	ies := append(
		encodePFCPTestIE(IETypeCause, []byte{1}),
		encodePFCPTestIE(IETypeFSEID, fseid)...,
	)
	NewSniffer("lo", 8805, correlation).
		handleSessionEstablishmentResponse(second.CPSEID, ies, upfIP)

	if first.EstablishmentStatus != EstablishmentPending || first.UPSEID != 0 {
		t.Fatalf("response was cross-wired to the first pending session: %+v", first)
	}
	if second.EstablishmentStatus != EstablishmentEstablished || second.UPSEID != upSEID {
		t.Fatalf("exact CP F-SEID session was not confirmed: %+v", second)
	}
}

func TestEstablishmentResponseWithoutExactCPSEIDDoesNotGuess(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	upfIP := net.ParseIP("10.100.200.4")
	session := &Session{
		CPSEID:              0x101,
		UEIP:                net.ParseIP("10.60.0.1"),
		UPFIP:               upfIP,
		CreatedAt:           time.Now(),
		EstablishmentTime:   time.Now(),
		EstablishmentStatus: EstablishmentPending,
	}
	correlation.AddSession(session)

	fseid := make([]byte, 9)
	binary.BigEndian.PutUint64(fseid[1:9], 0x9001)
	ies := append(
		encodePFCPTestIE(IETypeCause, []byte{1}),
		encodePFCPTestIE(IETypeFSEID, fseid)...,
	)
	NewSniffer("lo", 8805, correlation).
		handleSessionEstablishmentResponse(0x999, ies, upfIP)

	if session.EstablishmentStatus != EstablishmentPending || session.UPSEID != 0 {
		t.Fatalf("unmatched response changed a session by guesswork: %+v", session)
	}
}

func TestUpdateGTPUplinkRecordsBothN3Endpoints(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()

	session := &Session{
		SEID:                1,
		UEIP:                net.ParseIP("10.60.0.1"),
		TEIDs:               []uint32{2},
		CreatedAt:           time.Now(),
		EstablishmentStatus: EstablishmentEstablished,
	}
	correlation.AddSession(session)

	gnbIP := net.ParseIP("192.168.56.101")
	upfN3IP := net.ParseIP("192.168.56.103")
	correlation.UpdateGTPUplink(2, gnbIP, upfN3IP)

	updated, ok := correlation.GetSessionByTEID(2)
	if !ok {
		t.Fatal("session is missing from TEID map")
	}
	if !updated.UplinkPeerIP.Equal(gnbIP) || !updated.UPFN3IP.Equal(upfN3IP) {
		t.Fatalf("N3 endpoints were not recorded: peer=%v upf=%v",
			updated.UplinkPeerIP, updated.UPFN3IP)
	}
}

func TestRecordGTPFlowDisambiguatesSameTEIDByOuterDestination(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	for index, upf := range []string{"10.100.200.3", "10.100.200.4"} {
		correlation.AddSession(&Session{
			SEID:                uint64(index + 1),
			UEIP:                net.ParseIP("10.60.0.2"),
			UPFIP:               net.ParseIP(upf),
			TEIDs:               []uint32{6},
			CreatedAt:           time.Now().Add(time.Duration(index) * time.Second),
			EstablishmentStatus: EstablishmentEstablished,
		})
	}

	session, ok := correlation.RecordGTPFlow(
		6,
		net.ParseIP("10.100.200.3"),
		net.ParseIP("10.100.200.4"),
		net.ParseIP("10.60.0.2"),
		net.ParseIP("8.8.8.8"),
		84,
	)
	if !ok || session.UPFIP.String() != "10.100.200.4" {
		t.Fatalf("same TEID was correlated to the wrong UPF: %+v, ok=%v", session, ok)
	}
	if len(session.FlowTraffic) != 1 ||
		session.FlowTraffic[0].DestIP.String() != "8.8.8.8" ||
		session.FlowTraffic[0].Bytes != 84 {
		t.Fatalf("flow observation is wrong: %+v", session.FlowTraffic)
	}
}

func TestRecordGTPFlowUsesInnerUEEndpointForDirection(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	session := &Session{
		SEID:                1,
		UEIP:                net.ParseIP("10.60.0.3"),
		UPFIP:               net.ParseIP("10.100.200.3"),
		TEIDs:               []uint32{10},
		CreatedAt:           time.Now(),
		EstablishmentStatus: EstablishmentEstablished,
	}
	correlation.AddSession(session)

	_, ok := correlation.RecordGTPFlow(
		10,
		net.ParseIP("10.100.200.4"),
		net.ParseIP("10.100.200.3"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("10.60.0.3"),
		84,
	)
	if !ok {
		t.Fatal("downlink GTP ingress was not correlated")
	}
	correlation.RefreshSessionTrafficFromFlows()

	if len(session.FlowTraffic) != 1 ||
		session.FlowTraffic[0].Direction != "downlink" ||
		session.FlowTraffic[0].DestIP.String() != "1.1.1.1" ||
		session.PacketsUL != 0 || session.PacketsDL != 1 ||
		session.BytesDL != 84 {
		t.Fatalf("inner endpoint direction/counters are wrong: %+v", session)
	}
}

func TestPFCPTopologyUsesInterfaceSemanticsNotIPRanges(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	sniffer := NewSniffer("lo", 8805, correlation)

	session := &Session{UPFIP: net.ParseIP("198.18.0.20")}
	peer := net.ParseIP("203.0.113.220")
	data := makeForwardingParametersIE(t, pfcpInterfaceCore, nil, peer)

	sniffer.extractFTEIDDetails(data, session)

	if session.N9PeerIP == nil || !session.N9PeerIP.Equal(peer) {
		t.Fatalf("core-side peer was not classified as N9: %+v", session)
	}
	if session.N9Direction != "towards-core" {
		t.Fatalf("unexpected N9 direction %q", session.N9Direction)
	}
	if session.GNBIP != nil || session.AccessPeerIP != nil {
		t.Fatalf("N9 peer was also classified as an access peer: %+v", session)
	}
}

func TestPFCPAccessPeerRemainsUnclassifiedWithoutGraphEvidence(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	sniffer := NewSniffer("lo", 8805, correlation)

	session := &Session{UPFIP: net.ParseIP("192.168.56.103")}
	peer := net.ParseIP("192.168.56.5")
	data := makeForwardingParametersIE(t, pfcpInterfaceAccess, nil, peer)

	sniffer.extractFTEIDDetails(data, session)

	if session.AccessPeerIP == nil || !session.AccessPeerIP.Equal(peer) {
		t.Fatalf("access peer was not retained for graph correlation: %+v", session)
	}
	if session.GNBIP != nil || session.N9PeerIP != nil {
		t.Fatalf("access peer role was guessed without evidence: %+v", session)
	}
}

func TestPFCP3GPPInterfaceTypeCanIdentifyAccessSideN9(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	sniffer := NewSniffer("lo", 8805, correlation)

	session := &Session{UPFIP: net.ParseIP("198.18.0.20")}
	peer := net.ParseIP("198.18.0.199")
	interfaceType := byte(tgppInterfaceN9)
	data := makeForwardingParametersIE(t, pfcpInterfaceAccess, &interfaceType, peer)

	sniffer.extractFTEIDDetails(data, session)

	if session.N9PeerIP == nil || !session.N9PeerIP.Equal(peer) {
		t.Fatalf("3GPP N9 peer was not extracted: %+v", session)
	}
	if session.N9Direction != "towards-access" ||
		session.N9Evidence != "pfcp:3gpp-interface-type-n9" {
		t.Fatalf("N9 evidence was not retained: %+v", session)
	}
}

func TestPFCPDestinationN6MarksAnchorCapability(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	sniffer := NewSniffer("lo", 8805, correlation)

	session := &Session{UPFIP: net.ParseIP("198.18.0.20")}
	data := makeForwardingParametersIE(t, pfcpInterfaceN6, nil, nil)
	sniffer.extractFTEIDDetails(data, session)

	if !session.HasN6 {
		t.Fatal("PFCP Destination Interface N6 was not recorded")
	}
}

func TestPFCPFlowRulesDistinguishULCLPaths(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	sniffer := NewSniffer("lo", 8805, correlation)
	session := &Session{
		UEIP: net.ParseIP("10.60.0.2"),
		DNN:  "internet",
	}

	localFAR := makeTestFAR(11, pfcpInterfaceCore, nil)
	n9FAR := makeTestFAR(9, pfcpInterfaceCore, net.ParseIP("10.100.200.4"))
	specificPDR := makeTestPDR(
		11, 11, 30,
		"permit out ip from 10.60.0.2 to 1.0.0.1",
	)
	defaultPDR := makeTestPDR(9, 9, 255, "")
	data := append(append(append(localFAR, n9FAR...), specificPDR...), defaultPDR...)

	sniffer.extractFlowRules(data, session)

	if len(session.FlowRules) != 2 {
		t.Fatalf("got %d flow rules, want 2: %+v", len(session.FlowRules), session.FlowRules)
	}
	var local, n9 *FlowRule
	for index := range session.FlowRules {
		rule := &session.FlowRules[index]
		switch rule.PDRID {
		case 11:
			local = rule
		case 9:
			n9 = rule
		}
	}
	if local == nil || local.PathType != "n6" ||
		local.DestinationSelector != "1.0.0.1" || local.OuterDst != nil {
		t.Fatalf("specific local-breakout rule is wrong: %+v", local)
	}
	if n9 == nil || n9.PathType != "n9" ||
		n9.DestinationSelector != "" ||
		n9.OuterDst == nil || n9.OuterDst.String() != "10.100.200.4" {
		t.Fatalf("default N9 rule is wrong: %+v", n9)
	}
	if !session.HasN6 {
		t.Fatal("local-breakout FAR did not set N6 capability")
	}
}

func TestPFCPRemovePDRAndFARWithdrawsTopologyEvidence(t *testing.T) {
	sniffer := NewSniffer("lo", 8805, nil)
	session := &Session{UEIP: net.ParseIP("10.60.0.2")}

	far := makeTestFAR(9, pfcpInterfaceCore, net.ParseIP("10.100.200.4"))
	pdr := makeTestPDR(9, 9, 255, "")
	sniffer.extractFlowRules(append(far, pdr...), session)
	if len(session.FlowRules) != 1 || session.N9PeerIP == nil {
		t.Fatalf("initial N9 rule was not established: %+v", session)
	}

	pdrID := make([]byte, 2)
	binary.BigEndian.PutUint16(pdrID, 9)
	farID := make([]byte, 4)
	binary.BigEndian.PutUint32(farID, 9)
	removePDR := encodePFCPTestIE(
		IETypeRemovePDR,
		encodePFCPTestIE(IETypePDRID, pdrID),
	)
	removeFAR := encodePFCPTestIE(
		IETypeRemoveFAR,
		encodePFCPTestIE(IETypeFARID, farID),
	)

	sniffer.extractFlowRules(append(removePDR, removeFAR...), session)

	if len(session.FlowRules) != 0 || len(session.ForwardingRules) != 0 ||
		session.N9PeerIP != nil || session.N9Direction != "" || session.HasN6 {
		t.Fatalf("removed PDR/FAR left stale topology evidence: %+v", session)
	}
}

func TestPFCPFlowRulePreservesObservedLocalAndRemoteTunnelEndpoints(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	sniffer := NewSniffer("lo", 8805, correlation)
	session := &Session{UEIP: net.ParseIP("10.60.0.2")}

	far := makeTestFAR(10, pfcpInterfaceAccess, net.ParseIP("10.100.200.17"))
	pdr := makeTestPDRWithFTEID(
		10,
		10,
		255,
		tgppInterfaceN3Min,
		0x0a,
		net.ParseIP("10.100.200.10"),
	)
	sniffer.extractFlowRules(append(far, pdr...), session)

	if len(session.FlowRules) != 1 {
		t.Fatalf("got %d flow rules, want 1: %+v", len(session.FlowRules), session.FlowRules)
	}
	rule := session.FlowRules[0]
	if rule.SourceInterface != pfcpInterfaceAccess ||
		rule.SourceInterfaceType != tgppInterfaceN3Min ||
		rule.LocalFTEID != 0x0a ||
		rule.LocalFTEIDIP == nil ||
		rule.LocalFTEIDIP.String() != "10.100.200.10" {
		t.Fatalf("local F-TEID evidence is wrong: %+v", rule)
	}
	if rule.OuterTEID != 10 ||
		rule.OuterDst == nil ||
		rule.OuterDst.String() != "10.100.200.17" {
		t.Fatalf("remote OHC endpoint evidence is wrong: %+v", rule)
	}
}

func TestCreatedPDRAddsOnlyActuallyReturnedFTEID(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()
	session := &Session{
		CPSEID:              0x11,
		UEIP:                net.ParseIP("10.60.0.2"),
		UPFIP:               net.ParseIP("10.100.200.10"),
		CreatedAt:           time.Now(),
		EstablishmentStatus: EstablishmentPending,
		FlowRules: []FlowRule{{
			PDRID:               9,
			SourceInterface:     pfcpInterfaceAccess,
			SourceInterfaceType: tgppInterfaceN3Min,
		}},
	}
	correlation.AddSession(session)

	pdrID := make([]byte, 2)
	binary.BigEndian.PutUint16(pdrID, 9)
	fteid := make([]byte, 9)
	fteid[0] = 0x01
	binary.BigEndian.PutUint32(fteid[1:5], 0x44)
	copy(fteid[5:9], net.ParseIP("10.100.200.10").To4())
	createdPDR := encodePFCPTestIE(
		IETypeCreatedPDR,
		append(
			encodePFCPTestIE(IETypePDRID, pdrID),
			encodePFCPTestIE(IETypeFTEID, fteid)...,
		),
	)

	NewSniffer("lo", 8805, correlation).applyCreatedPDRs(createdPDR, session)

	if session.FlowRules[0].LocalFTEID != 0x44 ||
		session.FlowRules[0].LocalFTEIDIP.String() != "10.100.200.10" {
		t.Fatalf("Created PDR endpoint was not applied: %+v", session.FlowRules[0])
	}
	if mapped, ok := correlation.GetSessionByTEID(0x44); !ok || mapped.SEID != session.SEID {
		t.Fatalf("Created PDR TEID was not indexed: %+v, ok=%v", mapped, ok)
	}
}

func TestSDFFlowDescriptionSelectsNonUEEndpoint(t *testing.T) {
	for _, test := range []struct {
		description string
		want        string
	}{
		{"permit out ip from 10.60.0.2 to 1.0.0.1/32", "1.0.0.1/32"},
		{"permit out ip from 1.0.0.1/32 to 10.60.0.2", "1.0.0.1/32"},
		{"permit out ip from 10.60.0.2 to any", ""},
	} {
		if got := sdfDestinationSelector(test.description, "10.60.0.2"); got != test.want {
			t.Errorf("selector(%q)=%q, want %q", test.description, got, test.want)
		}
	}
}

func TestExtractSessionInfoUsesStandardPFCPTypesAnd40BitRates(t *testing.T) {
	encode40 := func(value uint64) []byte {
		return []byte{
			byte(value >> 32),
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
	mbr := append(encode40(100_000), encode40(200_000)...)
	gbr := append(encode40(50_000), encode40(75_000)...)
	dnn := append([]byte{8}, []byte("internet")...)
	dnn = append(dnn, 3, 'm', 'n', 'c')

	ies := encodePFCPTestIE(IETypeNetworkInstance, dnn)
	ies = append(ies, encodePFCPTestIE(IETypeMBR, mbr)...)
	ies = append(ies, encodePFCPTestIE(IETypeGBR, gbr)...)
	ies = append(ies, encodePFCPTestIE(IETypePDNType, []byte{1})...)
	ies = append(ies, encodePFCPTestIE(IETypeSNSSAI, []byte{1, 0x01, 0x02, 0x03})...)

	session := &Session{}
	NewSniffer("lo", 8805, nil).extractSessionInfo(ies, session)

	if session.DNN != "internet.mnc" ||
		session.MBRUplink != 100_000 || session.MBRDownlink != 200_000 ||
		session.GBRUplink != 50_000 || session.GBRDownlink != 75_000 ||
		session.SessionType != "IPv4" ||
		session.SNssai != "SST:1,SD:010203" {
		t.Fatalf("standard PFCP session attributes were decoded incorrectly: %+v", session)
	}
}

func TestExtractSessionInfoRejectsLegacyMisidentifiedIEsAndShortBitRates(t *testing.T) {
	ies := encodePFCPTestIE(45, []byte{9})
	ies = append(ies, encodePFCPTestIE(46, []byte{0xf0})...)
	ies = append(ies, encodePFCPTestIE(85, []byte{1})...)
	ies = append(ies, encodePFCPTestIE(148, []byte{1, 2, 3, 4})...)
	ies = append(ies, encodePFCPTestIE(IETypeMBR, make([]byte, 8))...)
	ies = append(ies, encodePFCPTestIE(IETypeGBR, make([]byte, 8))...)

	session := &Session{}
	NewSniffer("lo", 8805, nil).extractSessionInfo(ies, session)

	if session.SessionType != "" || session.SNssai != "" ||
		session.MBRUplink != 0 || session.MBRDownlink != 0 ||
		session.GBRUplink != 0 || session.GBRDownlink != 0 {
		t.Fatalf("misidentified or malformed PFCP IEs were exposed as facts: %+v", session)
	}
}

func TestCorrelationKeepsSameUEOnDifferentUPFs(t *testing.T) {
	correlation := NewCorrelation()
	defer correlation.Stop()

	for index, upf := range []string{"198.18.0.20", "203.0.113.220"} {
		correlation.AddSession(&Session{
			SEID:      uint64(index + 1),
			UEIP:      net.ParseIP("10.60.0.1"),
			UPFIP:     net.ParseIP(upf),
			TEIDs:     []uint32{uint32(index + 10)},
			CreatedAt: time.Now(),
		})
	}

	if got := correlation.SessionCount(); got != 2 {
		t.Fatalf("multi-UPF sessions were merged by UE IP: got %d, want 2", got)
	}
}

func makeForwardingParametersIE(
	t *testing.T,
	destination byte,
	interfaceType *byte,
	peer net.IP,
) []byte {
	t.Helper()

	children := make([]byte, 0)
	children = append(children, encodePFCPTestIE(IETypeDestinationInterface, []byte{destination})...)
	if interfaceType != nil {
		children = append(children, encodePFCPTestIE(IEType3GPPInterfaceType, []byte{*interfaceType})...)
	}
	if peer != nil {
		ipv4 := peer.To4()
		if ipv4 == nil {
			t.Fatalf("test peer must be IPv4: %s", peer)
		}
		outerHeader := make([]byte, 10)
		outerHeader[0] = 0x01 // GTP-U/UDP/IPv4: TEID and IPv4 are present.
		binary.BigEndian.PutUint32(outerHeader[2:6], 0x11223344)
		copy(outerHeader[6:10], ipv4)
		children = append(children, encodePFCPTestIE(IETypeOuterHeaderCreation, outerHeader)...)
	}
	return encodePFCPTestIE(IETypeForwardingParameters, children)
}

func makeTestFAR(id uint32, destination byte, peer net.IP) []byte {
	idValue := make([]byte, 4)
	binary.BigEndian.PutUint32(idValue, id)
	children := encodePFCPTestIE(IETypeFARID, idValue)
	children = append(children, encodePFCPTestIE(IETypeApplyAction, []byte{0x02})...)

	forwarding := encodePFCPTestIE(IETypeDestinationInterface, []byte{destination})
	if peer != nil {
		outerHeader := make([]byte, 10)
		outerHeader[0] = 0x01
		binary.BigEndian.PutUint32(outerHeader[2:6], id)
		copy(outerHeader[6:10], peer.To4())
		forwarding = append(forwarding,
			encodePFCPTestIE(IETypeOuterHeaderCreation, outerHeader)...)
	}
	children = append(children,
		encodePFCPTestIE(IETypeForwardingParameters, forwarding)...)
	return encodePFCPTestIE(IETypeCreateFAR, children)
}

func makeTestPDR(id uint16, farID, precedence uint32, sdf string) []byte {
	pdrIDValue := make([]byte, 2)
	binary.BigEndian.PutUint16(pdrIDValue, id)
	farIDValue := make([]byte, 4)
	binary.BigEndian.PutUint32(farIDValue, farID)
	precedenceValue := make([]byte, 4)
	binary.BigEndian.PutUint32(precedenceValue, precedence)

	pdi := encodePFCPTestIE(IETypeSourceInterface, []byte{pfcpInterfaceAccess})
	if sdf != "" {
		sdfValue := make([]byte, 4+len(sdf))
		sdfValue[0] = 0x01
		binary.BigEndian.PutUint16(sdfValue[2:4], uint16(len(sdf)))
		copy(sdfValue[4:], sdf)
		pdi = append(pdi, encodePFCPTestIE(IETypeSDFFilter, sdfValue)...)
	}

	children := encodePFCPTestIE(IETypePDRID, pdrIDValue)
	children = append(children, encodePFCPTestIE(IETypePrecedence, precedenceValue)...)
	children = append(children, encodePFCPTestIE(IETypePDI, pdi)...)
	children = append(children, encodePFCPTestIE(IETypeFARID, farIDValue)...)
	return encodePFCPTestIE(IETypeCreatePDR, children)
}

func makeTestPDRWithFTEID(
	id uint16,
	farID, precedence uint32,
	interfaceType int,
	teid uint32,
	localIP net.IP,
) []byte {
	pdrIDValue := make([]byte, 2)
	binary.BigEndian.PutUint16(pdrIDValue, id)
	farIDValue := make([]byte, 4)
	binary.BigEndian.PutUint32(farIDValue, farID)
	precedenceValue := make([]byte, 4)
	binary.BigEndian.PutUint32(precedenceValue, precedence)

	pdi := encodePFCPTestIE(IETypeSourceInterface, []byte{pfcpInterfaceAccess})
	pdi = append(pdi, encodePFCPTestIE(IEType3GPPInterfaceType, []byte{byte(interfaceType)})...)
	fteid := make([]byte, 9)
	fteid[0] = 0x01
	binary.BigEndian.PutUint32(fteid[1:5], teid)
	copy(fteid[5:9], localIP.To4())
	pdi = append(pdi, encodePFCPTestIE(IETypeFTEID, fteid)...)

	children := encodePFCPTestIE(IETypePDRID, pdrIDValue)
	children = append(children, encodePFCPTestIE(IETypePrecedence, precedenceValue)...)
	children = append(children, encodePFCPTestIE(IETypePDI, pdi)...)
	children = append(children, encodePFCPTestIE(IETypeFARID, farIDValue)...)
	return encodePFCPTestIE(IETypeCreatePDR, children)
}

func encodePFCPTestIE(ieType uint16, value []byte) []byte {
	encoded := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(encoded[0:2], ieType)
	binary.BigEndian.PutUint16(encoded[2:4], uint16(len(value)))
	copy(encoded[4:], value)
	return encoded
}

func makePFCPDeletionPacket(t *testing.T, seid uint64) gopacket.Packet {
	t.Helper()

	payload := make([]byte, 16)
	payload[0] = 0x21 // PFCP version 1, S flag set
	payload[1] = MsgTypeSessionDeletionRequest
	binary.BigEndian.PutUint16(payload[2:4], 12)
	binary.BigEndian.PutUint64(payload[4:12], seid)
	payload[14] = 1 // Sequence number

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("127.0.0.1").To4(),
		DstIP:    net.ParseIP("127.0.0.8").To4(),
	}
	udp := &layers.UDP{SrcPort: 8805, DstPort: 8805}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum network layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(
		buffer,
		options,
		ip,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize PFCP deletion packet: %v", err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
