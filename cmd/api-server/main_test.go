package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func topologyForSessions(t *testing.T, sessions []SessionInfo) Topology {
	t.Helper()

	gin.SetMode(gin.TestMode)
	server := &Server{sessions: sessions}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest("GET", "/api/v1/topology", nil)

	server.handleTopology(context)

	if recorder.Code != 200 {
		t.Fatalf("handleTopology returned HTTP %d: %s", recorder.Code, recorder.Body.String())
	}

	var topology Topology
	if err := json.Unmarshal(recorder.Body.Bytes(), &topology); err != nil {
		t.Fatalf("decode topology response: %v", err)
	}
	return topology
}

func findTopologyLink(topology Topology, source, target, linkType string) (TopologyLink, bool) {
	for _, link := range topology.Links {
		if link.Source == source && link.Target == target && link.Type == linkType {
			return link, true
		}
	}
	return TopologyLink{}, false
}

func findTopologyNode(topology Topology, id string) (TopologyNode, bool) {
	for _, node := range topology.Nodes {
		if node.ID == id {
			return node, true
		}
	}
	return TopologyNode{}, false
}

func TestSessionsResponsePreservesPFCPAndTunnelEvidence(t *testing.T) {
	payload := []byte(`{
		"total": 1,
		"sessions": [{
			"observation_id": "obs-3",
			"cp_seid": "0x101",
			"up_seid": "0x201",
			"source": "pfcp",
			"ue_ip": "10.60.0.2",
			"local_f_teids": ["0xa"],
			"created_at": "2026-07-23T00:00:00Z",
			"flow_rules": [{
				"pdr_id": 9,
				"far_id": 10,
				"source_interface": 0,
				"source_interface_type": 11,
				"destination_interface": 0,
				"interface_type": 11,
				"local_f_teid": "0xa",
				"local_f_teid_ip": "10.100.200.10",
				"sdf_observed": false,
				"outer_teid": "0x3",
				"outer_dst": "10.100.200.17",
				"path_type": "n3"
			}]
		}]
	}`)

	var response SessionsResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Sessions) != 1 {
		t.Fatalf("sessions were not decoded: %+v", response)
	}
	session := response.Sessions[0]
	if session.ObservationID != "obs-3" ||
		session.CPSEID != "0x101" ||
		session.UPSEID != "0x201" ||
		len(session.LocalFTEIDs) != 1 ||
		len(session.FlowRules) != 1 ||
		session.FlowRules[0].LocalFTEID != "0xa" ||
		session.FlowRules[0].OuterTEID != "0x3" {
		t.Fatalf("API proxy dropped session evidence: %+v", session)
	}
}

func activeTestSession() SessionInfo {
	now := time.Now().UTC()
	return SessionInfo{
		UEIP:        "10.60.0.1",
		GNBIP:       "192.168.56.101",
		UPFIP:       "127.0.0.8",
		UPFN3IP:     "192.168.56.103",
		CreatedAt:   now.Add(-time.Minute).Format(time.RFC3339),
		LastActive:  now.Format(time.RFC3339),
		PacketsUL:   5,
		BytesUL:     420,
		DNN:         "internet",
		Status:      "Active",
		SessionType: "IPv4",
	}
}

func TestHandleTopologySingleUPFIncludesN3Link(t *testing.T) {
	session := activeTestSession()
	session.FlowRules = []FlowRule{{
		PDRID:           1,
		FARID:           1,
		NetworkInstance: session.DNN,
		PathType:        "n6",
	}}
	topology := topologyForSessions(t, []SessionInfo{session})

	link, found := findTopologyLink(topology, session.GNBIP, session.UPFIP, "n3")
	if !found {
		t.Fatalf("missing single-UPF N3 link %s -> %s; links: %+v",
			session.GNBIP, session.UPFIP, topology.Links)
	}
	if !link.HasActiveTraffic {
		t.Fatal("single-UPF N3 link should carry the session activity")
	}

	node, found := findTopologyNode(topology, session.UPFIP)
	if !found {
		t.Fatalf("missing UPF node %s", session.UPFIP)
	}
	if node.Label != "UPF" {
		t.Fatalf("single free5GC UPF must keep the generic label, got %+v", node)
	}
	if node.IP != session.UPFN3IP || node.N3IP != session.UPFN3IP || node.N4IP != session.UPFIP {
		t.Fatalf("UPF node does not distinguish N3/N4 addresses: %+v", node)
	}
	if _, found := findTopologyNode(topology, "DN:internet"); !found {
		t.Fatalf("topology does not use the observed DNN: %+v", topology.Nodes)
	}
	if _, found := findTopologyLink(topology, session.UPFIP, "DN:internet", "n6"); !found {
		t.Fatalf("missing single-UPF N6 link: %+v", topology.Links)
	}
}

func TestHandleTopologyULCLUsesObservedUPFsAtArbitraryAddresses(t *testing.T) {
	accessSession := activeTestSession()
	accessSession.UPFIP = "172.31.44.77"
	accessSession.UPFN3IP = "198.51.100.77"
	accessSession.GNBIP = ""
	accessSession.AccessPeerIP = "192.0.2.5"
	accessSession.N9PeerIP = "198.51.100.220"
	accessSession.N9Direction = "towards-core"
	accessSession.N9Evidence = "pfcp:destination-interface-core"
	accessSession.DNN = "corp.mec"

	anchorSession := activeTestSession()
	anchorSession.UPFIP = "203.0.113.220"
	anchorSession.UPFN3IP = accessSession.N9PeerIP
	anchorSession.GNBIP = ""
	anchorSession.AccessPeerIP = accessSession.UPFIP
	anchorSession.N9PeerIP = ""
	anchorSession.HasN6 = true
	anchorSession.DNN = accessSession.DNN

	topology := topologyForSessions(t, []SessionInfo{accessSession, anchorSession})

	if _, found := findTopologyLink(topology, accessSession.AccessPeerIP, accessSession.UPFIP, "n3"); !found {
		t.Fatalf("missing ULCL N3 link %s -> %s; links: %+v",
			accessSession.AccessPeerIP, accessSession.UPFIP, topology.Links)
	}
	if _, found := findTopologyLink(topology, accessSession.UPFIP, anchorSession.UPFIP, "n9"); !found {
		t.Fatalf("missing ULCL N9 link %s -> %s; links: %+v",
			accessSession.UPFIP, anchorSession.UPFIP, topology.Links)
	}
	if _, found := findTopologyLink(topology, anchorSession.UPFIP, "DN:corp.mec", "n6"); !found {
		t.Fatalf("missing anchor N6 link derived from DNN; links: %+v", topology.Links)
	}
	if _, found := findTopologyLink(topology, accessSession.UPFIP, "DN:corp.mec", "n6"); found {
		t.Fatalf("invented an N6 link on an intermediate UPF: %+v", topology.Links)
	}

	accessNode, found := findTopologyNode(topology, accessSession.UPFIP)
	if !found || accessNode.Label != "I-UPF" {
		t.Fatalf("graph-derived intermediate role is wrong: %+v, found=%v", accessNode, found)
	}
	anchorNode, found := findTopologyNode(topology, anchorSession.UPFIP)
	if !found || anchorNode.Label != "PSA-UPF" {
		t.Fatalf("graph-derived anchor role is wrong: %+v, found=%v", anchorNode, found)
	}
}

func TestHandleTopologyDoesNotInventN9WithoutDirectionEvidence(t *testing.T) {
	session := activeTestSession()
	session.N9PeerIP = "203.0.113.8"

	topology := topologyForSessions(t, []SessionInfo{session})
	for _, link := range topology.Links {
		if link.Type == "n9" {
			t.Fatalf("invented N9 link without direction evidence: %+v", link)
		}
	}
}

func TestHandleTopologyBuildsDistinctULCLDestinationPathsFromPFCPRules(t *testing.T) {
	intermediate := activeTestSession()
	intermediate.UPFIP = "10.100.200.3"
	intermediate.GNBIP = "10.100.200.16"
	intermediate.N9PeerIP = "10.100.200.4"
	intermediate.N9Direction = "towards-core"
	intermediate.DNN = "internet"
	intermediate.FlowRules = []FlowRule{
		{
			PDRID:               11,
			FARID:               11,
			DestinationSelector: "1.0.0.1/32",
			PathType:            "n6",
		},
		{
			PDRID:     9,
			FARID:     9,
			OuterDst:  "10.100.200.4",
			PathType:  "n9",
			OuterTEID: "0x6",
		},
	}
	intermediate.FlowTraffic = []FlowTraffic{{
		DestIP:     "1.0.0.1",
		Packets:    5,
		Bytes:      420,
		LastActive: time.Now().UTC().Format(time.RFC3339),
		Direction:  "uplink",
	}}
	anchor := activeTestSession()
	anchor.UPFIP = "10.100.200.4"
	anchor.GNBIP = ""
	anchor.DNN = "internet"
	anchor.FlowRules = []FlowRule{
		{
			PDRID:               7,
			FARID:               7,
			DestinationSelector: "1.1.1.1/32",
			NetworkInstance:     "internet",
			PathType:            "n6",
		},
		{
			PDRID:           5,
			FARID:           5,
			NetworkInstance: "internet",
			PathType:        "n6",
		},
	}

	topology := topologyForSessions(t, []SessionInfo{intermediate, anchor})

	specific, found := findTopologyLink(topology, intermediate.UPFIP, "DN:1.0.0.1/32", "n6")
	if !found || !specific.Configured ||
		len(specific.FlowSelectors) != 1 || specific.FlowSelectors[0] != "1.0.0.1/32" ||
		!specific.HasActiveTraffic {
		t.Fatalf("missing PFCP-specific local-breakout path: %+v, found=%v", specific, found)
	}
	defaultDN, found := findTopologyLink(topology, anchor.UPFIP, "DN:internet", "n6")
	if !found || !defaultDN.Configured ||
		len(defaultDN.FlowSelectors) != 2 {
		t.Fatalf("missing PSA default DN path: %+v, found=%v", defaultDN, found)
	}
	if _, found := findTopologyNode(topology, "DN:1.1.1.1/32"); found {
		t.Fatalf("PSA selectors became separate physical DNs: %+v", topology.Nodes)
	}
	n9, found := findTopologyLink(topology, intermediate.UPFIP, anchor.UPFIP, "n9")
	if !found || !n9.Configured ||
		len(n9.FlowSelectors) != 1 || n9.FlowSelectors[0] != "all traffic (no SDF filter)" ||
		n9.HasActiveTraffic {
		t.Fatalf("missing default N9 path selector: %+v, found=%v", n9, found)
	}
}

func TestHandleTopologyDoesNotFabricateMissingUPFOrDN(t *testing.T) {
	topology := topologyForSessions(t, []SessionInfo{{
		ObservationID: "obs-partial",
		UEIP:          "10.60.0.9",
		DNN:           "",
	}})

	if _, found := findTopologyNode(topology, "UPF-Local"); found {
		t.Fatalf("fabricated placeholder UPF: %+v", topology.Nodes)
	}
	for _, node := range topology.Nodes {
		if node.Type == "dn" {
			t.Fatalf("fabricated DN without N6 and DN identity evidence: %+v", node)
		}
	}
}

func TestHandleTopologyDoesNotInferN6FromSingleUPF(t *testing.T) {
	session := activeTestSession()
	session.FlowRules = nil
	session.HasN6 = false

	topology := topologyForSessions(t, []SessionInfo{session})
	for _, link := range topology.Links {
		if link.Type == "n6" {
			t.Fatalf("fabricated single-UPF N6 link without PFCP evidence: %+v", link)
		}
	}
}

func TestSessionActivityUsesFlowTimestampWhenAvailable(t *testing.T) {
	session := activeTestSession()
	session.LastActive = time.Now().UTC().Format(time.RFC3339)
	session.FlowTraffic = []FlowTraffic{{
		DestIP:     "1.1.1.1",
		Packets:    5,
		Bytes:      420,
		LastActive: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		Direction:  "uplink",
	}}
	if isSessionActive(session) {
		t.Fatal("stale flow was kept active by a newer session-level timestamp")
	}
	session.FlowTraffic[0].LastActive = time.Now().UTC().Format(time.RFC3339)
	if !isSessionActive(session) {
		t.Fatal("recent flow observation was not considered active")
	}
}

func TestUndecodableObservedSDFFilterIsNotTreatedAsDefaultRule(t *testing.T) {
	session := activeTestSession()
	session.FlowTraffic = []FlowTraffic{{
		DestIP:     "8.8.8.8",
		Packets:    1,
		Bytes:      84,
		LastActive: time.Now().UTC().Format(time.RFC3339),
		Direction:  "uplink",
	}}
	rule := FlowRule{PDRID: 1, SDFObserved: true}
	session.FlowRules = []FlowRule{rule}

	if hasActiveFlowForRule(session, rule) {
		t.Fatal("an observed but undecodable SDF filter was treated as a default match")
	}
}

func TestCounterRateRejectsResetAndUsesElapsedTime(t *testing.T) {
	if got := counterRate(1_500, 500, 2); got != 500 {
		t.Fatalf("counterRate() = %v, want 500 units/s", got)
	}
	if got := counterRate(100, 500, 1); got != 0 {
		t.Fatalf("counter reset produced %v, want 0", got)
	}
	if got := counterRate(500, 100, 0); got != 0 {
		t.Fatalf("zero elapsed time produced %v, want 0", got)
	}
}

func TestSessionTrafficRateIsDeltaNotLifetimeAverage(t *testing.T) {
	server := &Server{
		sessionSamples: make(map[string]sessionCounterSample),
		sessionRates:   make(map[string]float64),
	}
	session := activeTestSession()
	session.ObservationID = "obs-100"
	session.BytesUL = 1_000
	response := &SessionsResponse{Sessions: []SessionInfo{session}}
	start := time.Unix(100, 0)

	server.updateSessionRatesLocked(response, start)
	if got := server.currentSessionTrafficRate(session); got != 0 {
		t.Fatalf("first sample rate = %v, want 0", got)
	}

	session.BytesUL = 2_000
	response.Sessions[0] = session
	server.updateSessionRatesLocked(response, start.Add(2*time.Second))
	if got := server.currentSessionTrafficRate(session); got != 500 {
		t.Fatalf("session rate = %v B/s, want 500 B/s", got)
	}

	session.BytesUL = 100
	response.Sessions[0] = session
	server.updateSessionRatesLocked(response, start.Add(3*time.Second))
	if got := server.currentSessionTrafficRate(session); got != 0 {
		t.Fatalf("session counter reset produced %v B/s, want 0", got)
	}
}

func TestFlowTrafficRateUsesPDUByteDeltaPerDestination(t *testing.T) {
	server := &Server{}
	session := activeTestSession()
	session.ObservationID = "obs-200"
	session.FlowRules = []FlowRule{{PDRID: 1, PathType: "n9"}}
	session.FlowTraffic = []FlowTraffic{{
		DestIP:     "8.8.8.8",
		Bytes:      100,
		Packets:    1,
		LastActive: time.Now().UTC().Format(time.RFC3339),
		Direction:  "uplink",
	}}
	response := &SessionsResponse{Sessions: []SessionInfo{session}}
	start := time.Unix(100, 0)

	server.updateSessionRatesLocked(response, start)
	session.FlowTraffic[0].Bytes = 1100
	response.Sessions[0] = session
	server.updateSessionRatesLocked(response, start.Add(2*time.Second))

	if got := server.currentRuleTrafficRate(session, session.FlowRules[0]); got != 500 {
		t.Fatalf("flow rate = %v B/s, want 500 B/s", got)
	}
}

func TestTopologyDiagnosticsReportsPFCPInterfaceMismatch(t *testing.T) {
	diagnostics := topologyDiagnostics(0, TrafficStats{
		Uplink: DirectionStats{Packets: 15},
	}, AgentInterfaceStatus{
		RequestedConfig: "lo",
		ActiveCapture:   "lo",
		AutoDetected:    "br-free5gc",
		DetectionReason: "free5gc Docker bridge",
	})

	if len(diagnostics) != 1 ||
		diagnostics[0].Code != "pfcp_capture_interface_mismatch" {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestTopologyDiagnosticsTreatsAnyAsContainingDetectedBridge(t *testing.T) {
	diagnostics := topologyDiagnostics(0, TrafficStats{
		Uplink: DirectionStats{Packets: 15},
	}, AgentInterfaceStatus{
		RequestedConfig: "any",
		ActiveCapture:   "any",
		AutoDetected:    "br-free5gc",
		DetectionReason: "free5gc Docker bridge",
	})

	if len(diagnostics) != 1 ||
		diagnostics[0].Code != "gtpu_without_pfcp_session" {
		t.Fatalf(`"any" capture was incorrectly treated as an interface mismatch: %+v`,
			diagnostics)
	}
}

func TestTopologyDiagnosticsReportsUncorrelatedGTPU(t *testing.T) {
	diagnostics := topologyDiagnostics(0, TrafficStats{
		Downlink: DirectionStats{Packets: 5},
	}, AgentInterfaceStatus{
		RequestedConfig: "auto",
		ActiveCapture:   "any",
		AutoDetected:    "any",
	})

	if len(diagnostics) != 1 ||
		diagnostics[0].Code != "gtpu_without_pfcp_session" {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if got := topologyDiagnostics(1, TrafficStats{}, AgentInterfaceStatus{}); got != nil {
		t.Fatalf("established topology should not report empty-session diagnostics: %+v", got)
	}
}
