package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	agentBaseURL       = strings.TrimRight(envOrDefault("DPOP_AGENT_URL", "http://localhost:9100"), "/")
	agentMetricsURL    = agentBaseURL + "/metrics"
	agentDropsURL      = agentBaseURL + "/api/drops"
	agentSessionsURL   = agentBaseURL + "/api/sessions"
	agentInterfacesURL = agentBaseURL + "/api/interfaces?compact=1"
)

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// TrafficStats represents traffic statistics
type TrafficStats struct {
	Uplink   DirectionStats `json:"uplink"`
	Downlink DirectionStats `json:"downlink"`
}

// DirectionStats represents stats for a single direction
type DirectionStats struct {
	Packets          uint64  `json:"packets"`            // cumulative successful PDU packets
	Bytes            uint64  `json:"bytes"`              // cumulative successful PDU bytes
	PacketsPerSecond float64 `json:"packets_per_second"` // packets/second over the last sample
	Throughput       float64 `json:"throughput_mbps"`    // decimal megabits/second
	LastUpdated      string  `json:"last_updated"`
}

// DropStats represents drop statistics
type DropStats struct {
	Total               uint64            `json:"total"`
	UserPlaneTotal      uint64            `json:"user_plane_total"`
	InfrastructureTotal uint64            `json:"infrastructure_total"`
	UncorrelatedTotal   uint64            `json:"uncorrelated_total"`
	Rate                float64           `json:"rate_percent"`
	RateBasis           string            `json:"rate_basis"`
	RecentDrops         []DropEvent       `json:"recent_drops"`
	ByReason            map[string]uint64 `json:"by_reason"`
}

// DropEvent represents a single drop event
type DropEvent struct {
	Timestamp               string   `json:"timestamp"`
	KernelTimestampNS       uint64   `json:"kernel_timestamp_ns"`
	TEID                    string   `json:"teid,omitempty"`
	SrcIP                   string   `json:"src_ip,omitempty"`
	DstIP                   string   `json:"dst_ip,omitempty"`
	SrcPort                 uint16   `json:"src_port,omitempty"`
	DstPort                 uint16   `json:"dst_port,omitempty"`
	Reason                  string   `json:"reason"`
	Direction               string   `json:"direction"`
	PktLen                  uint32   `json:"pkt_len"`
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

// FlowTraffic represents per-destination traffic for ULCL path differentiation
type FlowTraffic struct {
	DestIP     string `json:"dest_ip"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	LastActive string `json:"last_active,omitempty"`
	OuterSrc   string `json:"outer_src,omitempty"`
	OuterDst   string `json:"outer_dst,omitempty"` // Local GTP-U ingress endpoint
	Direction  string `json:"direction,omitempty"`
}

// FlowRule is a PFCP PDR joined with its FAR. It describes the configured path
// independently of whether traffic has recently been observed on that path.
type FlowRule struct {
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

// SessionInfo represents a PDU session (extended)
type SessionInfo struct {
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
	UPFIP        string     `json:"upf_ip,omitempty"`
	UPFN3IP      string     `json:"upf_n3_ip,omitempty"`
	GNBIP        string     `json:"gnb_ip,omitempty"`
	AccessPeerIP string     `json:"access_peer_ip,omitempty"`
	UplinkPeerIP string     `json:"uplink_peer_ip,omitempty"`
	N9PeerIP     string     `json:"n9_peer_ip,omitempty"` // N9 peer UPF IP (for ULCL)
	N9Direction  string     `json:"n9_direction,omitempty"`
	N9Evidence   string     `json:"n9_evidence,omitempty"`
	HasN6        bool       `json:"has_n6,omitempty"`
	FlowRules    []FlowRule `json:"flow_rules,omitempty"`
	SUPI         string     `json:"supi,omitempty"`
	DNN          string     `json:"dnn,omitempty"`
	SNssai       string     `json:"s_nssai,omitempty"`
	QFI          uint8      `json:"qfi,omitempty"`
	SessionType  string     `json:"session_type,omitempty"`
	SessionID    uint8      `json:"pdu_session_id,omitempty"`

	// Traffic statistics
	BytesUL uint64 `json:"bytes_ul"`
	BytesDL uint64 `json:"bytes_dl"`

	// Per-flow traffic (for ULCL path differentiation)
	FlowTraffic []FlowTraffic `json:"flow_traffic,omitempty"`

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

// Server represents the API server
type Server struct {
	router    *gin.Engine
	upgrader  websocket.Upgrader
	clients   map[*websocket.Conn]bool
	clientsMu sync.Mutex
	broadcast chan interface{}

	// In-memory stats (will be replaced with Prometheus queries)
	stats                TrafficStats
	drops                DropStats
	sessions             []SessionInfo // Active data plane sessions
	staleSessions        []SessionInfo // Established but no recent traffic
	failedSessions       []SessionInfo // Failed establishment sessions
	pendingSessions      []SessionInfo // Pending sessions (waiting for confirmation)
	unclassifiedSessions []SessionInfo // Session evidence without a measured monitoring state
	sessionSamples       map[string]sessionCounterSample
	sessionRates         map[string]float64 // current PDU bytes per second
	flowSamples          map[string]sessionCounterSample
	flowRates            map[string]float64 // current observed uplink PDU bytes per second
	captureStatus        AgentInterfaceStatus
	statsMu              sync.RWMutex
}

type AgentInterfaceStatus struct {
	RequestedConfig string `json:"requested_config"`
	CurrentConfig   string `json:"current_config"`
	ActiveCapture   string `json:"active_capture"`
	AutoDetected    string `json:"auto_detected"`
	DetectionReason string `json:"detection_reason"`
}

type sessionCounterSample struct {
	bytes uint64
	at    time.Time
}

func main() {
	log.Println("============================================================")
	log.Println("    5G-DPOP: Backend API Server")
	log.Println("============================================================")

	server := NewServer()

	log.Println("[INFO] Starting API server on :8080")
	if err := server.Run(":8080"); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// NewServer creates a new API server
func NewServer() *Server {
	s := &Server{
		router: gin.Default(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan interface{}),
		drops: DropStats{
			RecentDrops: make([]DropEvent, 0),
			ByReason:    make(map[string]uint64),
		},
		sessions:             make([]SessionInfo, 0),
		staleSessions:        make([]SessionInfo, 0),
		failedSessions:       make([]SessionInfo, 0),
		pendingSessions:      make([]SessionInfo, 0),
		unclassifiedSessions: make([]SessionInfo, 0),
		sessionSamples:       make(map[string]sessionCounterSample),
		sessionRates:         make(map[string]float64),
		flowSamples:          make(map[string]sessionCounterSample),
		flowRates:            make(map[string]float64),
	}

	s.setupRoutes()
	go s.handleBroadcast()
	go s.collectMetricsFromAgent() // Start collecting metrics from agent

	return s
}

func (s *Server) setupRoutes() {
	// CORS middleware
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// API routes
	api := s.router.Group("/api/v1")
	{
		api.GET("/health", s.handleHealth)
		api.GET("/metrics/traffic", s.handleTrafficMetrics)
		api.GET("/metrics/drops", s.handleDropMetrics)
		api.GET("/sessions", s.handleSessions)
		api.GET("/sessions/:observation_id", s.handleSessionDetail)
		api.GET("/topology", s.handleTopology)
		api.POST("/fault/inject", s.handleFaultInject)

		// Proxy demo APIs to agent
		api.POST("/demo/inject-drop", s.proxyToAgent)
		api.POST("/demo/inject-session", s.proxyToAgent)
	}

	// WebSocket for real-time updates
	s.router.GET("/ws/metrics", s.handleWebSocket)
	s.router.GET("/ws/events", s.handleEventsWebSocket)
}

// Health check
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

// Traffic metrics
func (s *Server) handleTrafficMetrics(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	c.JSON(http.StatusOK, s.stats)
}

// Drop metrics
func (s *Server) handleDropMetrics(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	c.JSON(http.StatusOK, s.drops)
}

// Sessions list
func (s *Server) handleSessions(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"total":                 len(s.sessions), // Only count data plane active sessions
		"sessions":              s.sessions,      // Data plane active sessions
		"stale_sessions":        s.staleSessions, // Established but no recent traffic
		"failed_sessions":       s.failedSessions,
		"pending_sessions":      s.pendingSessions,
		"unclassified_sessions": s.unclassifiedSessions,
		"total_all": len(s.sessions) + len(s.staleSessions) + len(s.failedSessions) +
			len(s.pendingSessions) + len(s.unclassifiedSessions),
		"counts": gin.H{
			"active":       len(s.sessions),
			"stale":        len(s.staleSessions),
			"failed":       len(s.failedSessions),
			"pending":      len(s.pendingSessions),
			"unclassified": len(s.unclassifiedSessions),
		},
	})
}

// Session detail
func (s *Server) handleSessionDetail(c *gin.Context) {
	observationID := c.Param("observation_id")

	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	for _, session := range s.sessions {
		if session.ObservationID == observationID {
			c.JSON(http.StatusOK, session)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error": "session not found",
	})
}

// Fault injection
func (s *Server) handleFaultInject(c *gin.Context) {
	var req struct {
		Type   string `json:"type"`   // "invalid_teid", "no_pdr"
		Target string `json:"target"` // Target TEID or IP
		Count  int    `json:"count"`  // Number of packets
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement actual fault injection
	log.Printf("[FAULT] Injection requested: type=%s, target=%s, count=%d",
		req.Type, req.Target, req.Count)

	c.JSON(http.StatusOK, gin.H{
		"status": "injection_started",
		"type":   req.Type,
		"target": req.Target,
	})
}

// proxyToAgent proxies demo API requests to the agent
func (s *Server) proxyToAgent(c *gin.Context) {
	// Build the agent URL (agent uses /api/ instead of /api/v1/)
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/v1/") {
		path = "/api/" + path[len("/api/v1/"):]
	}
	agentURL := agentBaseURL + path
	if c.Request.URL.RawQuery != "" {
		agentURL += "?" + c.Request.URL.RawQuery
	}

	// Create request to agent
	req, err := http.NewRequest(c.Request.Method, agentURL, c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", c.GetHeader("Content-Type"))

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Agent not available"})
		return
	}
	defer resp.Body.Close()

	// Copy response
	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// WebSocket handler for real-time metrics
func (s *Server) handleWebSocket(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		conn.Close()
	}()

	// Send initial data
	s.statsMu.RLock()
	conn.WriteJSON(gin.H{
		"type": "initial",
		"data": gin.H{
			"traffic":  s.stats,
			"drops":    s.drops,
			"sessions": len(s.sessions),
		},
	})
	s.statsMu.RUnlock()

	// Keep connection alive and handle client messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// WebSocket handler for events
func (s *Server) handleEventsWebSocket(c *gin.Context) {
	conn, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// Broadcast updates to all WebSocket clients
func (s *Server) handleBroadcast() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.statsMu.RLock()
		msg := gin.H{
			"type": "update",
			"data": gin.H{
				"traffic":  s.stats,
				"drops":    s.drops,
				"sessions": len(s.sessions),
			},
			"timestamp": time.Now().Format(time.RFC3339),
		}
		s.statsMu.RUnlock()

		s.clientsMu.Lock()
		for client := range s.clients {
			if err := client.WriteJSON(msg); err != nil {
				client.Close()
				delete(s.clients, client)
			}
		}
		s.clientsMu.Unlock()
	}
}

// UpdateStats updates the traffic statistics (called from agent)
func (s *Server) UpdateStats(stats TrafficStats) {
	s.statsMu.Lock()
	s.stats = stats
	s.statsMu.Unlock()
}

// AddDropEvent adds a drop event
func (s *Server) AddDropEvent(event DropEvent) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	s.drops.Total++
	s.drops.RecentDrops = append([]DropEvent{event}, s.drops.RecentDrops...)

	// Keep only last 100 events
	if len(s.drops.RecentDrops) > 100 {
		s.drops.RecentDrops = s.drops.RecentDrops[:100]
	}

	s.drops.ByReason[event.Reason]++
}

// Run starts the server
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

// collectMetricsFromAgent periodically fetches metrics from the eBPF agent
func (s *Server) collectMetricsFromAgent() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prevUplinkPackets, prevDownlinkPackets uint64
	var prevUplinkBytes, prevDownlinkBytes uint64
	var prevTime time.Time

	log.Println("[INFO] Starting metrics collection from agent at", agentMetricsURL)

	for range ticker.C {
		// Fetch Prometheus metrics for traffic
		metrics, err := s.fetchAgentMetrics()
		if err != nil {
			log.Printf("[WARN] Failed to fetch agent metrics: %v", err)
			continue
		}

		// Fetch drops from agent API
		dropsData, err := s.fetchAgentDrops()
		if err != nil {
			log.Printf("[WARN] Failed to fetch drops: %v", err)
		}

		// Fetch sessions from agent API
		sessionsData, err := s.fetchAgentSessions()
		if err != nil {
			log.Printf("[WARN] Failed to fetch sessions: %v", err)
		}

		interfacesData, err := s.fetchAgentInterfaces()
		if err != nil {
			log.Printf("[WARN] Failed to fetch agent interface status: %v", err)
		}

		now := time.Now()

		// Calculate throughput
		var uplinkPPS, downlinkPPS float64
		var uplinkThroughput, downlinkThroughput float64
		if !prevTime.IsZero() {
			elapsed := now.Sub(prevTime).Seconds()
			if elapsed > 0 {
				uplinkPPS = counterRate(metrics.uplinkPackets, prevUplinkPackets, elapsed)
				downlinkPPS = counterRate(metrics.downlinkPackets, prevDownlinkPackets, elapsed)
				uplinkThroughput = counterRate(metrics.uplinkBytes, prevUplinkBytes, elapsed) * 8 / 1_000_000
				downlinkThroughput = counterRate(metrics.downlinkBytes, prevDownlinkBytes, elapsed) * 8 / 1_000_000
			}
		}

		prevUplinkPackets = metrics.uplinkPackets
		prevDownlinkPackets = metrics.downlinkPackets
		prevUplinkBytes = metrics.uplinkBytes
		prevDownlinkBytes = metrics.downlinkBytes
		prevTime = now

		// Update stats
		s.statsMu.Lock()
		s.stats = TrafficStats{
			Uplink: DirectionStats{
				Packets:          metrics.uplinkPackets,
				Bytes:            metrics.uplinkBytes,
				PacketsPerSecond: uplinkPPS,
				Throughput:       uplinkThroughput,
				LastUpdated:      now.Format(time.RFC3339Nano),
			},
			Downlink: DirectionStats{
				Packets:          metrics.downlinkPackets,
				Bytes:            metrics.downlinkBytes,
				PacketsPerSecond: downlinkPPS,
				Throughput:       downlinkThroughput,
				LastUpdated:      now.Format(time.RFC3339Nano),
			},
		}

		// Update drop stats from agent API
		if dropsData != nil {
			s.drops = *dropsData
		}

		// Update sessions from agent API (separated by status)
		if sessionsData != nil {
			s.updateSessionRatesLocked(sessionsData, now)
			s.sessions = sessionsData.Sessions
			s.staleSessions = sessionsData.StaleSessions
			s.failedSessions = sessionsData.FailedSessions
			s.pendingSessions = sessionsData.PendingSessions
			s.unclassifiedSessions = sessionsData.UnclassifiedSessions
		}
		if interfacesData != nil {
			s.captureStatus = *interfacesData
		}
		s.statsMu.Unlock()
	}
}

// counterRate returns a per-second delta and treats a decreasing counter as a
// reset instead of allowing uint64 underflow to create a false spike.
func counterRate(current, previous uint64, elapsedSeconds float64) float64 {
	if elapsedSeconds <= 0 || current < previous {
		return 0
	}
	return float64(current-previous) / elapsedSeconds
}

// fetchAgentDrops fetches drop events from agent API
func (s *Server) fetchAgentDrops() (*DropStats, error) {
	resp, err := http.Get(agentDropsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch drops: %w", err)
	}
	defer resp.Body.Close()

	var dropsData DropStats
	if err := json.NewDecoder(resp.Body).Decode(&dropsData); err != nil {
		return nil, fmt.Errorf("failed to decode drops: %w", err)
	}
	if dropsData.RecentDrops == nil {
		dropsData.RecentDrops = make([]DropEvent, 0)
	}
	if dropsData.ByReason == nil {
		dropsData.ByReason = make(map[string]uint64)
	}

	return &dropsData, nil
}

// SessionsResponse holds the full sessions response from agent
type SessionsResponse struct {
	Total                int           `json:"total"`
	Sessions             []SessionInfo `json:"sessions"`
	StaleSessions        []SessionInfo `json:"stale_sessions"`
	FailedSessions       []SessionInfo `json:"failed_sessions"`
	PendingSessions      []SessionInfo `json:"pending_sessions"`
	UnclassifiedSessions []SessionInfo `json:"unclassified_sessions"`
}

// fetchAgentSessions fetches sessions from agent API
func (s *Server) fetchAgentSessions() (*SessionsResponse, error) {
	resp, err := http.Get(agentSessionsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sessions: %w", err)
	}
	defer resp.Body.Close()

	var result SessionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sessions: %w", err)
	}

	return &result, nil
}

func (s *Server) fetchAgentInterfaces() (*AgentInterfaceStatus, error) {
	resp, err := http.Get(agentInterfacesURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch interface status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("interface status returned HTTP %d", resp.StatusCode)
	}

	var result AgentInterfaceStatus
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode interface status: %w", err)
	}
	return &result, nil
}

// agentMetrics holds parsed metrics from the agent
type agentMetrics struct {
	uplinkPackets   uint64
	downlinkPackets uint64
	uplinkBytes     uint64
	downlinkBytes   uint64
	totalDrops      uint64
	activeSessions  uint64
}

// fetchAgentMetrics fetches and parses metrics from the eBPF agent
func (s *Server) fetchAgentMetrics() (*agentMetrics, error) {
	resp, err := http.Get(agentMetricsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return parsePrometheusMetrics(string(body))
}

// parsePrometheusMetrics parses Prometheus text format metrics
func parsePrometheusMetrics(body string) (*agentMetrics, error) {
	metrics := &agentMetrics{}

	// Regex patterns for different metric formats
	packetsPattern := regexp.MustCompile(`upf_packets_total\{direction="(\w+)"\}\s+([0-9.e+\-]+)`)
	bytesPattern := regexp.MustCompile(`upf_bytes_total\{direction="(\w+)"\}\s+([0-9.e+\-]+)`)
	dropsPattern := regexp.MustCompile(`upf_packet_drops_total\{[^}]*\}\s+([0-9.e+\-]+)`)
	sessionsPattern := regexp.MustCompile(`upf_active_sessions\s+([0-9.e+\-]+)`)

	// Parse packets
	for _, match := range packetsPattern.FindAllStringSubmatch(body, -1) {
		if len(match) == 3 {
			value := parseNumber(match[2])
			switch match[1] {
			case "uplink":
				metrics.uplinkPackets = value
			case "downlink":
				metrics.downlinkPackets = value
			}
		}
	}

	// Parse bytes
	for _, match := range bytesPattern.FindAllStringSubmatch(body, -1) {
		if len(match) == 3 {
			value := parseNumber(match[2])
			switch match[1] {
			case "uplink":
				metrics.uplinkBytes = value
			case "downlink":
				metrics.downlinkBytes = value
			}
		}
	}

	// Parse drops (sum all drop reasons)
	for _, match := range dropsPattern.FindAllStringSubmatch(body, -1) {
		if len(match) == 2 {
			value := parseNumber(match[1])
			metrics.totalDrops += value
		}
	}

	// Parse active sessions
	if match := sessionsPattern.FindStringSubmatch(body); len(match) == 2 {
		metrics.activeSessions = parseNumber(match[1])
	}

	return metrics, nil
}

// parseNumber parses both integer and scientific notation
func parseNumber(s string) uint64 {
	// Try parsing as float first (handles scientific notation)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return uint64(f)
	}
	// Fall back to uint64
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return v
	}
	return 0
}

// Ensure json and other imports are used
var _ = json.Marshal

// TopologyNode represents a node in the topology
type TopologyNode struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"` // "ue", "upf", "gnb", "dn"
	Label      string   `json:"label"`
	IP         string   `json:"ip"`
	N3IP       string   `json:"n3_ip,omitempty"` // UPF user-plane GTP-U endpoint
	N4IP       string   `json:"n4_ip,omitempty"` // UPF PFCP node address
	Roles      []string `json:"roles,omitempty"`
	RoleSource string   `json:"role_source,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
}

// TopologyLink represents a link in the topology
type TopologyLink struct {
	Source           string   `json:"source"`
	Target           string   `json:"target"`
	Label            string   `json:"label"`              // e.g. SEID
	Type             string   `json:"type"`               // "n3", "n4", "n6", "n9", "radio"
	HasActiveTraffic bool     `json:"hasActiveTraffic"`   // Whether there's active traffic
	TrafficRate      float64  `json:"trafficRate"`        // Traffic rate in bytes/sec
	LastSeen         string   `json:"lastSeen,omitempty"` // Timestamp of last traffic
	Evidence         string   `json:"evidence,omitempty"`
	Confidence       float64  `json:"confidence,omitempty"`
	FlowSelectors    []string `json:"flow_selectors,omitempty"`
	Configured       bool     `json:"configured,omitempty"`
}

// Topology represents the network topology
type Topology struct {
	Nodes       []TopologyNode       `json:"nodes"`
	Links       []TopologyLink       `json:"links"`
	Diagnostics []TopologyDiagnostic `json:"diagnostics,omitempty"`
}

type TopologyDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Action   string `json:"action"`
}

func topologyDiagnostics(sessionCount int, stats TrafficStats,
	capture AgentInterfaceStatus) []TopologyDiagnostic {
	if sessionCount > 0 {
		return nil
	}

	trafficObserved := stats.Uplink.Packets+stats.Downlink.Packets > 0
	requested := strings.ToLower(strings.TrimSpace(capture.RequestedConfig))
	active := strings.ToLower(strings.TrimSpace(capture.ActiveCapture))
	detected := strings.ToLower(strings.TrimSpace(capture.AutoDetected))
	captureIncludesDetected := active == "any" || detected == "any" || active == detected
	explicitMismatch := requested != "" &&
		requested != "auto" &&
		requested != "any" &&
		capture.ActiveCapture != "" &&
		capture.AutoDetected != "" &&
		!captureIncludesDetected

	if explicitMismatch {
		return []TopologyDiagnostic{{
			Severity: "error",
			Code:     "pfcp_capture_interface_mismatch",
			Message: fmt.Sprintf(
				"PFCP capture is fixed to %q while %q was detected (%s), so sessions on the detected interface are invisible.",
				capture.ActiveCapture, capture.AutoDetected, capture.DetectionReason),
			Action: "Restart the agent without -pfcp-iface, then re-establish the UE PDU session.",
		}}
	}

	if trafficObserved {
		return []TopologyDiagnostic{{
			Severity: "warning",
			Code:     "gtpu_without_pfcp_session",
			Message:  "GTP-U traffic is visible, but no PFCP session was captured, so the topology cannot be correlated safely.",
			Action:   "Start the agent in auto mode before UE registration and re-establish the UE PDU session.",
		}}
	}
	return nil
}

// isSessionActive checks if a session has recent traffic activity
// A session is considered active if it has traffic in the last 10 seconds
func isSessionActive(session SessionInfo) bool {
	// Once flow-level observations exist, they are the only valid activity
	// source. PFCP/session counters can be refreshed by control-plane activity
	// or collide on a reused ULCL TEID and must not keep links glowing.
	if len(session.FlowTraffic) > 0 {
		for _, flow := range session.FlowTraffic {
			if isFlowActive(flow) {
				return true
			}
		}
		return false
	}

	if session.LastActive == "" {
		// No LastActive timestamp - check if there's any traffic
		return session.PacketsUL > 0 || session.PacketsDL > 0
	}

	// Parse LastActive timestamp
	lastActive, err := time.Parse(time.RFC3339, session.LastActive)
	if err != nil {
		// If parsing fails, fall back to checking packet count
		return session.PacketsUL > 0 || session.PacketsDL > 0
	}

	// Consider active if last activity was within 10 seconds
	return time.Since(lastActive) < 10*time.Second
}

// isFlowActive checks if a specific flow (destination) has recent traffic
func isFlowActive(flow FlowTraffic) bool {
	if flow.LastActive == "" {
		return flow.Packets > 0
	}

	lastActive, err := time.Parse(time.RFC3339, flow.LastActive)
	if err != nil {
		return flow.Packets > 0
	}

	// Consider active if last activity was within 10 seconds
	return time.Since(lastActive) < 10*time.Second
}

// getActiveFlowsByOuterDst groups active flows by their outer destination (next hop)
// This allows us to determine which UPF paths have active traffic
func getActiveFlowsByOuterDst(session SessionInfo) map[string]bool {
	result := make(map[string]bool)
	for _, flow := range session.FlowTraffic {
		if isFlowActive(flow) && flow.OuterDst != "" {
			result[flow.OuterDst] = true
		}
	}
	return result
}

// hasActiveFlowToN9Peer requires flow-level evidence for N9 activity.
func hasActiveFlowToN9Peer(session SessionInfo) bool {
	if session.N9PeerIP == "" {
		return false
	}
	for _, flow := range session.FlowTraffic {
		if isFlowActive(flow) && flow.OuterDst == session.N9PeerIP {
			return true
		}
	}
	return false
}

// hasActiveFlowToLocalBreakout checks if session has active traffic NOT going through N9
func hasActiveFlowToLocalBreakout(session SessionInfo) bool {
	for _, flow := range session.FlowTraffic {
		if isFlowActive(flow) {
			// If OuterDst is empty or not N9PeerIP, it's local breakout
			if flow.OuterDst == "" || flow.OuterDst != session.N9PeerIP {
				return true
			}
		}
	}
	if len(session.FlowTraffic) == 0 && session.N9PeerIP != "" {
		return false
	}
	// For non-ULCL sessions, fall back to session-level activity
	if len(session.FlowTraffic) == 0 && session.N9PeerIP == "" {
		return isSessionActive(session)
	}
	return false
}

func hasActiveFlowForRule(session SessionInfo, rule FlowRule) bool {
	for _, flow := range session.FlowTraffic {
		if !isFlowActive(flow) {
			continue
		}
		if rule.DestinationSelector != "" &&
			destinationMatchesSelector(flow.DestIP, rule.DestinationSelector) {
			return true
		}
		if rule.DestinationSelector == "" && !rule.SDFObserved {
			matchedSpecificRule := false
			for _, specific := range session.FlowRules {
				if specific.DestinationSelector != "" &&
					destinationMatchesSelector(flow.DestIP, specific.DestinationSelector) {
					matchedSpecificRule = true
					break
				}
			}
			if !matchedSpecificRule {
				return true
			}
		}
	}
	return false
}

func destinationMatchesSelector(ip, selector string) bool {
	if ip == "" || selector == "" {
		return false
	}
	selectorHost := strings.Split(selector, "/")[0]
	if parsedIP := net.ParseIP(selectorHost); parsedIP != nil && parsedIP.String() == ip {
		return true
	}
	_, network, err := net.ParseCIDR(selector)
	return err == nil && network.Contains(net.ParseIP(ip))
}

func sessionRateKey(session SessionInfo) string {
	return session.UPFIP + "|" + session.ObservationID
}

func flowRateKey(session SessionInfo, flow FlowTraffic) string {
	return sessionRateKey(session) + "|" + flow.Direction + "|" + flow.DestIP
}

// updateSessionRatesLocked derives current per-session PDU byte rates from
// consecutive cumulative samples. The caller must hold statsMu.
func (s *Server) updateSessionRatesLocked(response *SessionsResponse, now time.Time) {
	all := make([]SessionInfo, 0,
		len(response.Sessions)+len(response.StaleSessions)+
			len(response.PendingSessions)+len(response.FailedSessions)+
			len(response.UnclassifiedSessions))
	all = append(all, response.Sessions...)
	all = append(all, response.StaleSessions...)
	all = append(all, response.PendingSessions...)
	all = append(all, response.FailedSessions...)
	all = append(all, response.UnclassifiedSessions...)

	seen := make(map[string]bool, len(all))
	seenFlows := make(map[string]bool)
	if s.sessionSamples == nil {
		s.sessionSamples = make(map[string]sessionCounterSample)
	}
	if s.sessionRates == nil {
		s.sessionRates = make(map[string]float64)
	}
	if s.flowSamples == nil {
		s.flowSamples = make(map[string]sessionCounterSample)
	}
	if s.flowRates == nil {
		s.flowRates = make(map[string]float64)
	}
	for _, session := range all {
		key := sessionRateKey(session)
		seen[key] = true
		currentBytes := session.BytesUL + session.BytesDL
		rate := 0.0
		if previous, ok := s.sessionSamples[key]; ok {
			elapsed := now.Sub(previous.at).Seconds()
			rate = counterRate(currentBytes, previous.bytes, elapsed)
		}
		s.sessionSamples[key] = sessionCounterSample{bytes: currentBytes, at: now}
		s.sessionRates[key] = rate
		for _, flow := range session.FlowTraffic {
			flowKey := flowRateKey(session, flow)
			seenFlows[flowKey] = true
			flowRate := 0.0
			if previous, ok := s.flowSamples[flowKey]; ok {
				flowRate = counterRate(flow.Bytes, previous.bytes, now.Sub(previous.at).Seconds())
			}
			s.flowSamples[flowKey] = sessionCounterSample{bytes: flow.Bytes, at: now}
			s.flowRates[flowKey] = flowRate
		}
	}

	for key := range s.sessionSamples {
		if !seen[key] {
			delete(s.sessionSamples, key)
			delete(s.sessionRates, key)
		}
	}
	for key := range s.flowSamples {
		if !seenFlows[key] {
			delete(s.flowSamples, key)
			delete(s.flowRates, key)
		}
	}
}

// currentSessionTrafficRate returns the most recent PDU bytes/second delta.
// statsMu must be held by the caller.
func (s *Server) currentSessionTrafficRate(session SessionInfo) float64 {
	if len(session.FlowTraffic) > 0 {
		rate := 0.0
		for _, flow := range session.FlowTraffic {
			rate += s.flowRates[flowRateKey(session, flow)]
		}
		return rate
	}
	return s.sessionRates[sessionRateKey(session)]
}

func (s *Server) currentRuleTrafficRate(session SessionInfo, rule FlowRule) float64 {
	rate := 0.0
	for _, flow := range session.FlowTraffic {
		if hasActiveFlowForRule(SessionInfo{
			FlowRules:   session.FlowRules,
			FlowTraffic: []FlowTraffic{flow},
		}, rule) {
			rate += s.flowRates[flowRateKey(session, flow)]
		}
	}
	return rate
}

func resolveSessionPeers(session SessionInfo, upfIPs map[string]bool) SessionInfo {
	// An access-side Outer Header Creation can point to either a gNB (N3) or
	// another observed UPF (N9). Resolve it only after all PFCP-local UPFs are
	// known; no address range or deployment-specific name is involved.
	if session.N9PeerIP == "" && session.AccessPeerIP != "" && upfIPs[session.AccessPeerIP] {
		session.N9PeerIP = session.AccessPeerIP
		session.N9Direction = "towards-access"
		session.N9Evidence = "pfcp:access-peer+observed-upf"
	}

	if session.GNBIP != "" && upfIPs[session.GNBIP] {
		session.GNBIP = ""
	}
	if session.GNBIP == "" {
		for _, candidate := range []string{session.AccessPeerIP, session.UplinkPeerIP} {
			if candidate != "" && candidate != session.N9PeerIP && !upfIPs[candidate] {
				session.GNBIP = candidate
				break
			}
		}
	}
	return session
}

func canonicalUPFID(ip string, aliases map[string]string) string {
	if canonical, found := aliases[ip]; found {
		return canonical
	}
	return ip
}

func n9Endpoints(session SessionInfo, localUPF string, aliases map[string]string) (string, string, bool) {
	if session.N9PeerIP == "" || session.N9PeerIP == localUPF {
		return "", "", false
	}
	peerUPF := canonicalUPFID(session.N9PeerIP, aliases)
	if peerUPF == localUPF {
		return "", "", false
	}
	switch session.N9Direction {
	case "towards-core":
		return localUPF, peerUPF, true
	case "towards-access":
		return peerUPF, localUPF, true
	default:
		// A peer address without interface direction is insufficient evidence
		// to invent an N9 path.
		return "", "", false
	}
}

func appendUniqueRole(roles []string, role string) []string {
	for _, existing := range roles {
		if existing == role {
			return roles
		}
	}
	return append(roles, role)
}

func hasRole(roles []string, role string) bool {
	for _, existing := range roles {
		if existing == role {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func flowRuleSelectorLabel(rule FlowRule) string {
	if rule.DestinationSelector != "" {
		return rule.DestinationSelector
	}
	if !rule.SDFObserved {
		return "all traffic (no SDF filter)"
	}
	return ""
}

func optionalStringSlice(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func mergeTopologyNode(nodes map[string]TopologyNode, node TopologyNode) {
	existing, found := nodes[node.ID]
	if !found {
		nodes[node.ID] = node
		return
	}
	if existing.IP == "" {
		existing.IP = node.IP
	}
	if existing.N3IP == "" {
		existing.N3IP = node.N3IP
	}
	if existing.N4IP == "" {
		existing.N4IP = node.N4IP
	}
	for _, role := range node.Roles {
		existing.Roles = appendUniqueRole(existing.Roles, role)
	}
	if existing.RoleSource == "" {
		existing.RoleSource = node.RoleSource
	}
	if node.Confidence > existing.Confidence {
		existing.Confidence = node.Confidence
	}
	nodes[node.ID] = existing
}

func normalizedDNN(dnn string) string {
	return strings.TrimSpace(strings.Trim(dnn, "\x00"))
}

func (s *Server) handleTopology(c *gin.Context) {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	nodes := make(map[string]TopologyNode)
	links := make([]TopologyLink, 0)

	// Track which links have active traffic (key: "source->target")
	activeLinkTraffic := make(map[string]struct {
		active      bool
		trafficRate float64
		lastSeen    string
	})

	// Combine all session types for topology visualization
	// In ULCL, we need to show the network structure even if sessions are stale
	allSessions := make([]SessionInfo, 0, len(s.sessions)+len(s.staleSessions)+
		len(s.pendingSessions)+len(s.unclassifiedSessions))
	allSessions = append(allSessions, s.sessions...)
	allSessions = append(allSessions, s.staleSessions...)
	allSessions = append(allSessions, s.pendingSessions...)
	allSessions = append(allSessions, s.unclassifiedSessions...)

	// First, identify all UPFs from N9PeerIP (these are definitely UPFs)
	upfIPs := make(map[string]bool)
	upfAliases := make(map[string]string)
	for _, session := range allSessions {
		if session.UPFIP != "" {
			upfIPs[session.UPFIP] = true
			upfAliases[session.UPFIP] = session.UPFIP
			if session.UPFN3IP != "" {
				upfIPs[session.UPFN3IP] = true
				upfAliases[session.UPFN3IP] = session.UPFIP
			}
		}
		if session.N9PeerIP != "" {
			upfIPs[session.N9PeerIP] = true
		}
		for _, rule := range session.FlowRules {
			if rule.PathType == "n9" && rule.OuterDst != "" {
				upfIPs[rule.OuterDst] = true
			}
		}
		// UplinkPeerIP could be a RAN or UPF peer; resolve it after this pass.
	}
	for i := range allSessions {
		allSessions[i] = resolveSessionPeers(allSessions[i], upfIPs)
	}

	// Pass 1: Create all nodes
	for _, session := range allSessions {
		// UE Node
		if session.UEIP != "" {
			nodes[session.UEIP] = TopologyNode{
				ID:    session.UEIP,
				Type:  "ue",
				Label: "UE",
				IP:    session.UEIP,
			}
		}

		// UPF Node (from session)
		upfIP := session.UPFIP
		if upfIP == "" {
			// A local observation ID is not a network endpoint. Keep the UE
			// evidence above, but do not fabricate a placeholder UPF node.
			continue
		}
		upfN3IP := session.UPFN3IP
		if existing, exists := nodes[upfIP]; exists && upfN3IP == "" {
			upfN3IP = existing.N3IP
		}
		upfDisplayIP := upfIP
		if upfN3IP != "" {
			upfDisplayIP = upfN3IP
		}
		roles := make([]string, 0, 2)
		if session.GNBIP != "" {
			roles = appendUniqueRole(roles, "access")
		}
		if session.HasN6 {
			roles = appendUniqueRole(roles, "anchor")
		}
		if session.N9PeerIP != "" && session.GNBIP != "" {
			roles = appendUniqueRole(roles, "intermediate")
		}
		for _, rule := range session.FlowRules {
			switch rule.PathType {
			case "n6":
				roles = appendUniqueRole(roles, "anchor")
			case "n9":
				if session.GNBIP != "" {
					roles = appendUniqueRole(roles, "intermediate")
				}
			}
		}
		roleSource := ""
		confidence := 0.0
		if len(roles) > 0 {
			roleSource = "pfcp+ebpf-correlation"
			confidence = 0.9
		}
		mergeTopologyNode(nodes, TopologyNode{
			ID:         upfIP,
			Type:       "upf",
			Label:      "UPF",
			IP:         upfDisplayIP,
			N3IP:       upfN3IP,
			N4IP:       session.UPFIP,
			Roles:      roles,
			RoleSource: roleSource,
			Confidence: confidence,
		})

		// A PFCP-classified or graph-correlated N9 peer is known to be a UPF,
		// but no deployment-specific role name is asserted here.
		if session.N9PeerIP != "" {
			peerUPFID := canonicalUPFID(session.N9PeerIP, upfAliases)
			mergeTopologyNode(nodes, TopologyNode{
				ID:         peerUPFID,
				Type:       "upf",
				Label:      "UPF",
				IP:         session.N9PeerIP,
				RoleSource: session.N9Evidence,
				Confidence: 0.85,
			})
		}
		for _, rule := range session.FlowRules {
			if rule.PathType != "n9" || rule.OuterDst == "" {
				continue
			}
			peerUPFID := canonicalUPFID(rule.OuterDst, upfAliases)
			mergeTopologyNode(nodes, TopologyNode{
				ID:         peerUPFID,
				Type:       "upf",
				Label:      "UPF",
				IP:         rule.OuterDst,
				RoleSource: "pfcp:pdr-far",
				Confidence: 1,
			})
		}

		// Add an observed uplink peer as gNB only when it is not any known UPF.
		uplinkPeer := session.UplinkPeerIP
		if uplinkPeer != "" && uplinkPeer != session.N9PeerIP && !upfIPs[uplinkPeer] {
			// This is likely the gNB
			if _, exists := nodes[uplinkPeer]; !exists {
				nodes[uplinkPeer] = TopologyNode{
					ID:    uplinkPeer,
					Type:  "gnb",
					Label: "gNB",
					IP:    uplinkPeer,
				}
			}
		}

		// Also check GNBIP (signaled gNB address)
		if session.GNBIP != "" && !upfIPs[session.GNBIP] {
			if _, exists := nodes[session.GNBIP]; !exists {
				nodes[session.GNBIP] = TopologyNode{
					ID:    session.GNBIP,
					Type:  "gnb",
					Label: "gNB",
					IP:    session.GNBIP,
				}
			}
		}
	}

	// Pass 2: Calculate traffic activity for each session's links
	for _, session := range allSessions {
		upfIP := session.UPFIP
		if upfIP == "" {
			continue
		}

		sessionActive := isSessionActive(session)
		trafficRate := s.currentSessionTrafficRate(session)

		// Determine gNB (the actual radio access point)
		gnbIP := session.GNBIP
		n9Source, n9Target, hasN9 := n9Endpoints(session, upfIP, upfAliases)

		// Link: UE -> gNB (Radio)
		if session.UEIP != "" && gnbIP != "" {
			linkKey := session.UEIP + "->" + gnbIP
			if existing, ok := activeLinkTraffic[linkKey]; !ok || sessionActive {
				activeLinkTraffic[linkKey] = struct {
					active      bool
					trafficRate float64
					lastSeen    string
				}{
					active:      existing.active || sessionActive,
					trafficRate: existing.trafficRate + trafficRate,
					lastSeen:    session.LastActive,
				}
			}
		}

		// N3 terminates on the local UPF represented by this PFCP session.
		if gnbIP != "" && upfIP != "" {
			linkKey := gnbIP + "->" + upfIP
			if existing, ok := activeLinkTraffic[linkKey]; !ok || sessionActive {
				activeLinkTraffic[linkKey] = struct {
					active      bool
					trafficRate float64
					lastSeen    string
				}{
					active:      existing.active || sessionActive,
					trafficRate: existing.trafficRate + trafficRate,
					lastSeen:    session.LastActive,
				}
			}
		}

		if hasN9 {
			linkKey := n9Source + "->" + n9Target
			n9Active := hasActiveFlowToN9Peer(session)
			if existing, ok := activeLinkTraffic[linkKey]; !ok || n9Active {
				n9TrafficRate := 0.0
				if n9Active {
					n9TrafficRate = trafficRate
				}
				activeLinkTraffic[linkKey] = struct {
					active      bool
					trafficRate float64
					lastSeen    string
				}{
					active:      existing.active || n9Active,
					trafficRate: existing.trafficRate + n9TrafficRate,
					lastSeen:    session.LastActive,
				}
			}
		}
	}

	// Pass 3: Create links with activity information
	linkSet := make(map[string]bool)

	for _, session := range allSessions {
		upfIP := session.UPFIP
		if upfIP == "" {
			continue
		}

		sessionActive := isSessionActive(session)
		gnbIP := session.GNBIP
		n9Source, n9Target, hasN9 := n9Endpoints(session, upfIP, upfAliases)

		// Radio Link: UE -> gNB
		if session.UEIP != "" && gnbIP != "" {
			linkKey := session.UEIP + "->" + gnbIP
			if !linkSet[linkKey] {
				linkSet[linkKey] = true
				activity := activeLinkTraffic[linkKey]
				links = append(links, TopologyLink{
					Source:           session.UEIP,
					Target:           gnbIP,
					Label:            "Radio",
					Type:             "radio",
					HasActiveTraffic: activity.active || sessionActive,
					TrafficRate:      activity.trafficRate,
					LastSeen:         activity.lastSeen,
				})
			}
		}

		// N3 Link: gNB -> the local UPF observed in this PFCP session.
		if gnbIP != "" && upfIP != "" {
			linkKey := gnbIP + "->" + upfIP
			if !linkSet[linkKey] {
				linkSet[linkKey] = true
				activity := activeLinkTraffic[linkKey]
				links = append(links, TopologyLink{
					Source:           gnbIP,
					Target:           upfIP,
					Label:            "N3",
					Type:             "n3",
					HasActiveTraffic: activity.active || sessionActive,
					TrafficRate:      activity.trafficRate,
					LastSeen:         activity.lastSeen,
					Evidence:         "pfcp-access-peer+observed-upf",
					Confidence:       0.9,
				})
			}
		}

		if hasN9 {
			linkKey := n9Source + "->" + n9Target
			if !linkSet[linkKey] {
				linkSet[linkKey] = true
				activity := activeLinkTraffic[linkKey]

				// Link existence comes from PFCP semantics; active state requires
				// flow evidence and is not inferred from generic session activity.
				n9Active := activity.active

				links = append(links, TopologyLink{
					Source:           n9Source,
					Target:           n9Target,
					Label:            "N9",
					Type:             "n9",
					HasActiveTraffic: n9Active,
					TrafficRate:      activity.trafficRate,
					LastSeen:         activity.lastSeen,
					Evidence:         session.N9Evidence,
					Confidence:       0.9,
				})
			}
		}
	}

	// Add flow selectors to N9 paths. Link existence and selectors come from
	// PFCP PDR/FAR rules; current activity remains false unless flow-level
	// packet evidence exists.
	n9LinkIndex := make(map[string]int)
	for index := range links {
		if links[index].Type == "n9" {
			n9LinkIndex[links[index].Source+"->"+links[index].Target] = index
		}
	}
	for _, session := range allSessions {
		localUPF := session.UPFIP
		if localUPF == "" {
			continue
		}
		for _, rule := range session.FlowRules {
			if rule.PathType != "n9" || rule.OuterDst == "" {
				continue
			}
			target := canonicalUPFID(rule.OuterDst, upfAliases)
			if target == localUPF {
				continue
			}
			key := localUPF + "->" + target
			selector := flowRuleSelectorLabel(rule)
			if index, exists := n9LinkIndex[key]; exists {
				if selector != "" {
					links[index].FlowSelectors = appendUniqueString(links[index].FlowSelectors, selector)
				}
				links[index].Configured = true
				links[index].HasActiveTraffic = links[index].HasActiveTraffic ||
					hasActiveFlowForRule(session, rule)
				links[index].TrafficRate += s.currentRuleTrafficRate(session, rule)
				continue
			}
			n9LinkIndex[key] = len(links)
			links = append(links, TopologyLink{
				Source:           localUPF,
				Target:           target,
				Label:            "N9",
				Type:             "n9",
				HasActiveTraffic: hasActiveFlowForRule(session, rule),
				TrafficRate:      s.currentRuleTrafficRate(session, rule),
				LastSeen:         session.LastActive,
				Evidence:         "pfcp:pdr-far",
				Confidence:       1,
				FlowSelectors:    optionalStringSlice(selector),
				Configured:       true,
			})
		}
	}

	// Build DNs from every PFCP local-breakout/default N6 rule. This is what
	// distinguishes an ULCL-specific DN from the PSA's default DNN.
	n6LinkIndex := make(map[string]int)
	for _, session := range allSessions {
		ruleBackedN6 := false
		for _, rule := range session.FlowRules {
			if rule.PathType != "n6" {
				continue
			}
			ruleBackedN6 = true
			upfIP := session.UPFIP
			if upfIP == "" {
				continue
			}
			selector := rule.DestinationSelector
			dnName := ""
			// A core-facing intermediate UPF's specific N6 rule is a local
			// breakout DN. At a terminal/PSA UPF, multiple selectors share
			// the same physical Network Instance/DNN and must be one DN node.
			if session.N9Direction == "towards-core" && selector != "" {
				dnName = selector
			} else {
				dnName = normalizedDNN(rule.NetworkInstance)
				if dnName == "" {
					dnName = normalizedDNN(session.DNN)
				}
			}
			if dnName == "" {
				// The N6 rule is real, but no DN identity was observed. A
				// nameless DN node would assert information we do not have.
				continue
			}
			dnID := "DN:" + dnName
			nodes[dnID] = TopologyNode{
				ID:         dnID,
				Type:       "dn",
				Label:      "DN: " + dnName,
				IP:         dnName,
				RoleSource: "pfcp:pdr-far",
				Confidence: 1,
			}
			linkKey := upfIP + "->" + dnID + ":n6"
			active := hasActiveFlowForRule(session, rule)
			flowSelector := flowRuleSelectorLabel(rule)
			if index, exists := n6LinkIndex[linkKey]; exists {
				links[index].HasActiveTraffic = links[index].HasActiveTraffic || active
				links[index].TrafficRate += s.currentRuleTrafficRate(session, rule)
				if flowSelector != "" {
					links[index].FlowSelectors = appendUniqueString(
						links[index].FlowSelectors, flowSelector)
				}
				continue
			}
			n6LinkIndex[linkKey] = len(links)
			links = append(links, TopologyLink{
				Source:           upfIP,
				Target:           dnID,
				Label:            "N6",
				Type:             "n6",
				HasActiveTraffic: active,
				TrafficRate:      s.currentRuleTrafficRate(session, rule),
				LastSeen:         session.LastActive,
				Evidence:         "pfcp:pdr-far",
				Confidence:       1,
				FlowSelectors:    optionalStringSlice(flowSelector),
				Configured:       true,
			})
		}
		if ruleBackedN6 {
			continue
		}

		// A legacy/partial capture may lack the PDR/FAR graph. Only retain an
		// N6 link when both N6 and the DNN were actually observed.
		hasObservedN6 := session.HasN6
		if !hasObservedN6 {
			continue
		}

		upfIP := session.UPFIP
		if upfIP == "" {
			continue
		}
		dnn := normalizedDNN(session.DNN)
		if dnn == "" {
			continue
		}
		dnID := "DN:" + dnn
		nodes[dnID] = TopologyNode{
			ID:         dnID,
			Type:       "dn",
			Label:      "DN: " + dnn,
			IP:         dnn,
			RoleSource: "pfcp:network-instance",
			Confidence: 1,
		}

		linkKey := upfIP + "->" + dnID + ":n6"
		active := isSessionActive(session)
		rate := s.currentSessionTrafficRate(session)
		if index, exists := n6LinkIndex[linkKey]; exists {
			links[index].HasActiveTraffic = links[index].HasActiveTraffic || active
			links[index].TrafficRate += rate
			if session.LastActive != "" {
				links[index].LastSeen = session.LastActive
			}
			continue
		}

		n6LinkIndex[linkKey] = len(links)
		links = append(links, TopologyLink{
			Source:           upfIP,
			Target:           dnID,
			Label:            "N6",
			Type:             "n6",
			HasActiveTraffic: active,
			TrafficRate:      rate,
			LastSeen:         session.LastActive,
			Evidence:         "pfcp:destination-interface-n6",
			Confidence:       1,
		})
	}

	// Deployment-independent semantic labels derived from graph position.
	// No container name, compose filename, or IP address participates.
	for id, node := range nodes {
		if node.Type != "upf" {
			continue
		}
		switch {
		case hasRole(node.Roles, "intermediate") && hasRole(node.Roles, "access"):
			node.Label = "I-UPF"
		case hasRole(node.Roles, "anchor") && !hasRole(node.Roles, "access"):
			node.Label = "PSA-UPF"
		default:
			node.Label = "UPF"
		}
		nodes[id] = node
	}

	// Convert map to slice
	nodeList := make([]TopologyNode, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}

	c.JSON(http.StatusOK, Topology{
		Nodes:       nodeList,
		Links:       links,
		Diagnostics: topologyDiagnostics(len(allSessions), s.stats, s.captureStatus),
	})
}
