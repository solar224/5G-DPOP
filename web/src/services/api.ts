// API Types
export interface TrafficStats {
    uplink: DirectionStats
    downlink: DirectionStats
}

export interface DirectionStats {
    packets: number             // cumulative successful PDU packets
    bytes: number               // cumulative successful PDU bytes
    packets_per_second: number  // packets/second over the last API sample
    throughput_mbps: number     // decimal megabits/second
    last_updated: string
}

export interface DropStats {
    total: number
    user_plane_total: number
    infrastructure_total: number
    uncorrelated_total: number
    rate_percent: number
    rate_basis: string
    recent_drops: DropEvent[]
    by_reason: Record<string, number>
}

export interface DropEvent {
    timestamp: string
    kernel_timestamp_ns?: number
    teid?: string
    src_ip?: string
    dst_ip?: string
    src_port?: number
    dst_port?: number
    reason: string
    direction: 'uplink' | 'downlink' | 'unknown'
    pkt_len: number
    family: 'ipv4' | 'ipv6' | 'unknown'
    protocol: string
    origin: string
    icmp_type?: number
    valid_fields: string[]
    scope: 'user-plane' | 'infrastructure' | 'uncorrelated'
    classification: string
    session_correlated: boolean
    correlated_observation_id?: string
    // Extended session correlation info (populated by frontend from sessions data)
    session?: {
        observation_id?: string
        cp_seid?: string
        up_seid?: string
        ue_ip?: string
        supi?: string
        dnn?: string
        gnb_ip?: string
        upf_ip?: string
        qfi?: number
        status?: string
    }
}

// Drop reason metadata for detailed explanations
export interface DropReasonInfo {
    code: string
    name: string
    description: string
    impact: string
    possibleCauses: string[]
    suggestedActions: string[]
    severity: 'critical' | 'warning' | 'info'
    layer: 'GTP' | 'PFCP' | 'Kernel' | 'QoS' | 'Routing'
}

// Complete drop reason database - Direct 1:1 mapping with gtp5g error codes
// These match exactly with gtp5g/src/gtpu/encap.c definitions (codes 1-17)
// Note: Some codes are defined but not yet used in kernel (marked with [RESERVED])
export const DROP_REASON_DATABASE: Record<string, DropReasonInfo> = {
    'PKT_DROPPED': {
        code: '1',
        name: 'Packet Dropped (FAR Action)',
        description: 'Packet intentionally dropped due to FAR action being set to DROP. This is a policy-based drop configured by SMF.',
        impact: 'Packet dropped by network policy. This is intentional behavior, not an error.',
        possibleCauses: [
            'FAR action configured as DROP by SMF',
            'Session policy requires dropping this traffic',
            'Traffic filtering rule in effect',
            'Intentional traffic blocking'
        ],
        suggestedActions: [
            'Check if this is expected policy behavior',
            'Review SMF session FAR configuration',
            'Check 5G-DPOP session details for FAR action',
            'Verify PCF policy rules if unexpected'
        ],
        severity: 'info',
        layer: 'PFCP'
    },
    'ECHO_RESP_CREATE': {
        code: '2',
        name: 'Echo Response Creation Failed',
        description: 'Failed to create GTP Echo Response message. Triggered when skb_push() fails during echo response construction.',
        impact: 'GTP path health check may fail. gNB may consider the path down.',
        possibleCauses: [
            'Memory allocation failure for Echo Response',
            'Socket buffer allocation failed (skb_push returned NULL)',
            'System under memory pressure',
            'High packet rate exhausting skb pool'
        ],
        suggestedActions: [
            'Check system memory: free -h && cat /proc/meminfo | grep -i slab',
            'Check kernel logs: dmesg | grep -i "gtp5g\|echo" | tail -30',
            'Monitor socket buffer usage: ss -u -a | grep 2152',
            'Check GTP-U socket: netstat -anu | grep 2152'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'NO_ROUTE': {
        code: '3',
        name: 'No Route',
        description: 'No routing entry found for the packet destination. ip4_find_route() failed in kernel.',
        impact: 'Packet cannot reach destination. Complete connectivity failure for this flow.',
        possibleCauses: [
            'Missing route to destination network',
            'Routing table not configured properly',
            'Next hop unreachable',
            'UPF N6 interface not configured',
            'Docker network misconfiguration'
        ],
        suggestedActions: [
            'Check routing table: ip route show table all',
            'Test route to destination: ip route get <dst_ip_from_drop_event>',
            'Check UPF container routes: docker exec upf ip route',
            'Verify N6 interface exists: ip link show | grep -E "upf|n6"',
            'Check iptables rules: iptables -L -n -v | head -30'
        ],
        severity: 'critical',
        layer: 'Routing'
    },
    'PULL_FAILED': {
        code: '4',
        name: 'SKB Pull Failed',
        description: 'pskb_may_pull() returned false - packet too short to contain expected GTP header. Common with fragmented or truncated packets.',
        impact: 'Packet parsing failed. Cannot extract GTP header.',
        possibleCauses: [
            'Packet too short (truncated in transit)',
            'MTU issue causing IP fragmentation',
            'Malformed GTP packet from gNB',
            'Network corruption'
        ],
        suggestedActions: [
            'Capture GTP packets: tcpdump -i any port 2152 -s 0 -w gtp_capture.pcap',
            'Check interface MTU: ip link show | grep mtu',
            'Check for interface errors: ip -s link show',
            'Analyze in Wireshark: Look for truncated GTP packets'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'INVALID_EXT_HDR': {
        code: '5',
        name: 'Invalid Extension Header',
        description: 'GTP-U extension header length is 0 (invalid per 3GPP TS 29.281). Extension header must be n*4 octets where n>=1.',
        impact: 'GTP packet dropped. UE traffic for this PDU session affected.',
        possibleCauses: [
            'Malformed extension header with length=0',
            'gNB bug in GTP-U encapsulation',
            'Packet corruption in N3 tunnel',
            'Incompatible GTP-U extension header type'
        ],
        suggestedActions: [
            'Capture GTP packets: tcpdump -i any port 2152 -s 0 -w gtp.pcap',
            'Analyze with Wireshark: filter "gtpv2" and check extension headers',
            'Check gNB/UERANSIM logs for GTP errors',
            'Verify N3 network path integrity'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'NO_PDR': {
        code: '6',
        name: 'No PDR Match',
        description: 'No Packet Detection Rule (PDR) found for this packet. UPF cannot determine how to handle it. This is the most common drop reason.',
        impact: 'Packet dropped. User may experience connection timeout or data loss.',
        possibleCauses: [
            'PDU Session not fully established',
            'PFCP Session Establishment incomplete',
            'SMF failed to create PDR in UPF',
            'Stale session - PDR already deleted',
            'Race condition during handover',
            'TEID not registered in any PDR'
        ],
        suggestedActions: [
            'Check gtp5g kernel logs: dmesg | grep -i "no pdr" | tail -20',
            'Check SMF logs: docker logs smf 2>&1 | grep -i pfcp',
            'Verify PFCP session: Check SMF-UPF PFCP association status',
            'List UPF sessions via 5G-DPOP API: curl localhost:8080/api/v1/sessions',
            'Check if TEID exists in active sessions'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'GENERAL': {
        code: '7',
        name: 'General Error',
        description: 'A generic gtp5g drop was reported. Code 7 is shared by several call sites, so the origin and packet metadata must be used before assigning a specific cause.',
        impact: 'Impact depends on event scope. Uncorrelated infrastructure events may be harmless; correlated user-plane events require investigation.',
        possibleCauses: [
            'Unsupported L3 protocol on the gtp5g device',
            'Socket-buffer preparation failure',
            'Missing or invalid FAR/OHR forwarding state',
            'Unhandled forwarding action'
        ],
        suggestedActions: [
            'Check dmesg for gtp5g errors: dmesg | grep -i gtp5g | tail -50',
            'Verify gtp5g device status: ip link show type gtp5g',
            'Check UPF status: docker ps | grep upf',
            'Review 5G-DPOP sessions: curl localhost:8080/api/v1/sessions'
        ],
        severity: 'warning',
        layer: 'Kernel'
    },
    'UNSUPPORTED_L3': {
        code: '18',
        name: 'Unsupported L3 Protocol',
        description: 'gtp5g_dev_xmit received a non-IPv4 packet. The current gtp5g data path only handles IPv4 payloads.',
        impact: 'The packet is rejected by the gtp5g interface. Automatic IPv6 control traffic is classified as infrastructure and excluded from the user-plane ratio.',
        possibleCauses: [
            'Automatic IPv6 Router Solicitation during interface creation',
            'IPv6 traffic sent to an IPv4-only PDU session',
            'Incorrect route directing non-IPv4 traffic to upfgtp'
        ],
        suggestedActions: [
            'Inspect interface addresses: ip address show upfgtp',
            'Inspect routes: ip -6 route show dev upfgtp',
            'Disable IPv6 on upfgtp if IPv6 PDU sessions are not supported'
        ],
        severity: 'info',
        layer: 'Kernel'
    },
    'SKB_PREPARE_FAIL': {
        code: '19',
        name: 'Packet Buffer Preparation Failed',
        description: 'gtp5g could not reserve the socket-buffer headroom required for encapsulation.',
        impact: 'A user-plane packet could not be prepared for forwarding.',
        possibleCauses: ['Kernel memory pressure', 'Invalid device headroom configuration'],
        suggestedActions: [
            'Check kernel memory pressure: dmesg | tail -100',
            'Inspect gtp5g device details: ip -details link show upfgtp'
        ],
        severity: 'critical',
        layer: 'Kernel'
    },
    'FAR_MISSING': {
        code: '20',
        name: 'FAR Missing',
        description: 'The matched PDR does not reference an available Forwarding Action Rule.',
        impact: 'The UPF cannot determine the forwarding action for this packet.',
        possibleCauses: ['Incomplete PFCP session programming', 'FAR removed before the PDR'],
        suggestedActions: [
            'Inspect SMF PFCP logs',
            'Compare the active PDR and FAR state in gtp5g'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'INVALID_FAR_ACTION': {
        code: '21',
        name: 'Invalid FAR Action',
        description: 'The FAR apply-action combination is not handled by the current gtp5g data path.',
        impact: 'The packet cannot be forwarded or buffered according to the FAR.',
        possibleCauses: ['Unsupported FAR flag combination', 'Malformed PFCP rule programming'],
        suggestedActions: [
            'Inspect FAR apply-action flags in the SMF PFCP trace',
            'Verify SMF and UPF version compatibility'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'OHR_MISSING': {
        code: '22',
        name: 'Outer Header Removal Missing',
        description: 'An uplink rule matched but does not contain the required Outer Header Removal instruction.',
        impact: 'The UPF cannot remove the incoming GTP-U outer header.',
        possibleCauses: ['Incomplete uplink PDR', 'PFCP rule programming mismatch'],
        suggestedActions: ['Inspect the uplink PDR Outer Header Removal IE'],
        severity: 'critical',
        layer: 'PFCP'
    },
    'OHC_MISSING': {
        code: '23',
        name: 'Outer Header Creation Missing',
        description: 'A forwarding FAR does not contain the required Outer Header Creation information.',
        impact: 'The UPF cannot construct the outgoing GTP-U tunnel header.',
        possibleCauses: ['Missing FAR forwarding parameters', 'RAN or peer-UPF endpoint absent from the observed FAR'],
        suggestedActions: ['Inspect FAR Forwarding Parameters and Outer Header Creation IE'],
        severity: 'critical',
        layer: 'PFCP'
    },
    'UL_GATE_CLOSED': {
        code: '8',
        name: 'Uplink Gate Closed',
        description: 'QoS Enforcement Rule (QER) has uplink gate set to CLOSED (QER_UL_GATE_CLOSE flag). This is a policy decision, not an error.',
        impact: 'All uplink traffic for this PDU session is intentionally blocked by network policy.',
        possibleCauses: [
            'QER configured with UL gate=CLOSED by SMF/PCF',
            'Session suspended for charging/policy reasons',
            'Network-initiated service restriction',
            'Intentional traffic blocking during session modification'
        ],
        suggestedActions: [
            'Check if this is expected policy behavior',
            'Review SMF logs: docker logs smf 2>&1 | grep -i qer',
            'Check PCF policy: docker logs pcf 2>&1 | tail -50',
            'Verify session QoS via 5G-DPOP: Look at session details in dashboard',
            'This may be intentional - verify with network policy'
        ],
        severity: 'warning',
        layer: 'QoS'
    },
    'DL_GATE_CLOSED': {
        code: '9',
        name: 'Downlink Gate Closed',
        description: 'QoS Enforcement Rule (QER) has downlink gate set to CLOSED (QER_DL_GATE_CLOSE flag). This is a policy decision, not an error.',
        impact: 'All downlink traffic for this PDU session is intentionally blocked by network policy.',
        possibleCauses: [
            'QER configured with DL gate=CLOSED by SMF/PCF',
            'UE in CM-IDLE state, DL buffering active',
            'Session suspended for charging/policy reasons',
            'Intentional traffic blocking during handover'
        ],
        suggestedActions: [
            'Check if UE is in idle mode (expected for DL buffering)',
            'Review SMF logs: docker logs smf 2>&1 | grep -i qer',
            'Check AMF for UE state: docker logs amf 2>&1 | grep -i "cm-idle\|paging"',
            'Verify session via 5G-DPOP dashboard',
            'This may be intentional - verify with network policy'
        ],
        severity: 'warning',
        layer: 'QoS'
    },
    'PDR_NULL': {
        code: '10',
        name: 'PDR Pointer NULL',
        description: 'PDR pointer is NULL in gtp5g_fwd_skb_encap. Internal consistency check failed during uplink forwarding.',
        impact: 'Uplink packet dropped due to internal error. Session may be corrupted.',
        possibleCauses: [
            'Race condition during PDR deletion',
            'Internal gtp5g state inconsistency',
            'PFCP session being modified while packet in flight',
            'Memory corruption (rare)'
        ],
        suggestedActions: [
            'Check for recent PFCP session modifications',
            'Review dmesg for errors: dmesg | grep -i "pdr.*null" | tail -20',
            'Verify UPF stability: Check for other error patterns',
            'If persistent, restart UPF or reload gtp5g module'
        ],
        severity: 'critical',
        layer: 'PFCP'
    },
    'NO_F_TEID': {
        code: '11',
        name: 'No F-TEID',
        description: 'FAR or Outer Header Creation info not found. Cannot determine GTP tunnel endpoint for forwarding.',
        impact: 'Packet cannot be encapsulated/forwarded. Session setup may be incomplete.',
        possibleCauses: [
            'FAR not associated with PDR',
            'FAR missing forwarding parameters',
            'Outer Header Creation not configured',
            'PFCP Session Establishment incomplete',
            'f_teid not set in PDI'
        ],
        suggestedActions: [
            'Check SMF logs for FAR creation: docker logs smf 2>&1 | grep -i far',
            'Verify PFCP Session Establishment completed',
            'Check 5G-DPOP session details for FAR info',
            'Review dmesg: dmesg | grep -i "f_teid\|far" | tail -20'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'URR_REPORT_FAIL': {
        code: '12',
        name: 'URR Report Drop',
        description: 'Packet dropped due to URR (Usage Reporting Rule) policy. Typically first uplink packet before buffering is complete.',
        impact: 'First uplink packet dropped per URR policy. Subsequent packets should proceed normally.',
        possibleCauses: [
            'DONT_SEND_UL_PACKET flag set by URR',
            'First uplink packet before session fully ready',
            'URR buffering/reporting mechanism active',
            'Normal behavior for some URR configurations'
        ],
        suggestedActions: [
            'Check if this is first packet of session (expected)',
            'Review URR configuration in SMF',
            'Check dmesg: dmesg | grep -i "urr\|usage" | tail -20',
            'If persistent, check PFCP URR setup'
        ],
        severity: 'info',
        layer: 'PFCP'
    },
    'RED_PACKET': {
        code: '13',
        name: 'RED Packet Drop',
        description: 'Packet marked as RED by trTCM (Two Rate Three Color Marker) QoS policer. Traffic exceeded MBR (Maximum Bit Rate) configured in QER.',
        impact: 'Packet dropped due to rate limiting. This is normal QoS enforcement, not an error.',
        possibleCauses: [
            'Traffic rate exceeded session MBR',
            'Burst traffic exceeding token bucket',
            'QER rate limiting working as designed',
            'Network congestion control active'
        ],
        suggestedActions: [
            'Check session QoS parameters in 5G-DPOP dashboard',
            'Review QER MBR/GBR settings: Check SMF session config',
            'Monitor traffic rate: Compare with configured limits',
            'If legitimate traffic, consider increasing MBR in subscription',
            'This is expected behavior under load - verify if intentional'
        ],
        severity: 'info',
        layer: 'QoS'
    },
    'IP_XMIT_FAIL': {
        code: '14',
        name: 'IP Transmit Failed',
        description: 'ip_xmit() failed to transmit packet after GTP decapsulation. Network layer transmission error in uplink path.',
        impact: 'Uplink packet lost after GTP processing. UE internet access may fail.',
        possibleCauses: [
            'N6 interface down or misconfigured',
            'ARP resolution failed for next hop',
            'Destination unreachable',
            'iptables/nftables blocking traffic',
            'Docker network routing issue'
        ],
        suggestedActions: [
            'Check network interfaces: ip link show',
            'Check routing: ip route get <dst_ip_from_drop>',
            'Check ARP table: ip neigh show',
            'Check iptables: iptables -L -n -v | head -40',
            'Check UPF container network: docker exec upf ip route'
        ],
        severity: 'critical',
        layer: 'Routing'
    },
    'NOT_TPDU': {
        code: '15',
        name: 'Not T-PDU',
        description: 'GTP message type is not T-PDU in uplink forwarding path. Only T-PDU (0xFF) messages carry user data.',
        impact: 'Non-user-data GTP message dropped. May be Echo or other control message in wrong path.',
        possibleCauses: [
            'GTP Echo Request/Response in data path',
            'Error Indication message',
            'End Marker message after PDR match',
            'Unsupported GTP message type'
        ],
        suggestedActions: [
            'Capture GTP packets: tcpdump -i any port 2152 -w gtp.pcap',
            'Analyze with Wireshark: Check GTP message type field',
            'Check gNB/UERANSIM GTP implementation',
            'Review dmesg: dmesg | grep -i "tpdu\|msg type" | tail -20'
        ],
        severity: 'warning',
        layer: 'GTP'
    },
    'PULL_HDR_FAIL': {
        code: '16',
        name: 'Header Pull Failed',
        description: 'iptunnel_pull_header() failed to remove GTP-U and UDP headers after PDR match. Packet structure invalid.',
        impact: 'Uplink packet cannot be decapsulated. Packet dropped.',
        possibleCauses: [
            'Packet too short after GTP header stripping',
            'Corrupted inner IP header',
            'Malformed GTP encapsulation',
            'MTU issues causing truncation'
        ],
        suggestedActions: [
            'Capture packets: tcpdump -i any port 2152 -s 0 -w capture.pcap',
            'Check interface MTU: ip link show',
            'Look for fragmentation issues',
            'Review dmesg: dmesg | grep -i "pull.*header" | tail -20'
        ],
        severity: 'critical',
        layer: 'GTP'
    },
    'NETIF_RX_FAIL': {
        code: '17',
        name: 'Netif RX Failed',
        description: 'netif_rx() returned failure when delivering decapsulated packet to network stack. Kernel network backlog full.',
        impact: 'Uplink packet lost after successful GTP decapsulation. UE internet traffic affected.',
        possibleCauses: [
            'Kernel network stack overloaded',
            'CPU softirq backlog full',
            'High packet rate exceeding system capacity',
            'Memory pressure'
        ],
        suggestedActions: [
            'Check CPU softirq: cat /proc/softirqs | grep NET',
            'Check backlog: sysctl net.core.netdev_max_backlog',
            'Monitor system load: top -b -n 1 | head -15',
            'Increase backlog if needed: sysctl -w net.core.netdev_max_backlog=10000'
        ],
        severity: 'critical',
        layer: 'Kernel'
    },
    'UNKNOWN': {
        code: '255',
        name: 'Unclassified Error Code',
        description: 'The agent observed a drop code that is not present in its current reason mapping.',
        impact: 'The packet was dropped; the specific kernel reason cannot be classified from the observed code.',
        possibleCauses: [
            'New error code not yet mapped',
            'gtp5g module version mismatch',
            'Corrupted error code',
            'Internal error'
        ],
        suggestedActions: [
            'Check gtp5g module version',
            'Review dmesg for errors',
            'Update 5G-DPOP if gtp5g was updated',
            'Report issue if persistent'
        ],
        severity: 'warning',
        layer: 'GTP'
    }
}

export interface SessionInfo {
    // Evidence-backed identifiers. observation_id is local to this agent and
    // must never be presented as a PFCP SEID.
    observation_id: string
    cp_seid?: string
    up_seid?: string
    source?: 'pfcp' | 'demo' | 'manual' | 'log' | string
    ue_ip?: string
    local_f_teids?: string[]
    created_at?: string     // RFC3339 timestamp, only when observed

    // Packet statistics
    packets_ul: number
    packets_dl: number
    bytes_ul: number
    bytes_dl: number

    // 5G identifiers
    supi?: string          // "imsi-208930000000001"
    dnn?: string           // "internet"
    s_nssai?: string       // "SST:1, SD:010203"
    qfi?: number           // QoS Flow ID
    session_type?: string  // "IPv4"
    pdu_session_id?: number

    // Network node IPs
    upf_ip?: string
    upf_n3_ip?: string
    gnb_ip?: string
    access_peer_ip?: string
    uplink_peer_ip?: string
    n9_peer_ip?: string
    n9_direction?: 'towards-core' | 'towards-access'
    n9_evidence?: string
    has_n6?: boolean
    flow_rules?: FlowRule[]
    flow_traffic?: FlowTraffic[]

    // QoS parameters
    gbr_ul_kbps?: number
    gbr_dl_kbps?: number
    mbr_ul_kbps?: number
    mbr_dl_kbps?: number

    // Status
    status?: string
    duration?: string
    last_active?: string
    establishment_status?: 'Pending' | 'Established' | 'Failed' | string
    data_plane_status?: 'Active' | 'Stale' | 'Inactive' | string
    last_packet_time?: string
    monitoring_state?: 'active' | 'stale' | 'pending' | 'failed'
}

export interface FlowRule {
    pdr_id: number
    far_id: number
    precedence: number
    source_interface: number
    source_interface_type: number
    destination_interface: number
    interface_type: number
    local_f_teid?: string
    local_f_teid_ip?: string
    sdf_observed: boolean
    sdf?: string
    destination_selector?: string
    network_instance?: string
    outer_dst?: string
    outer_teid?: string
    path_type?: 'n3' | 'n6' | 'n9' | 'access-tunnel' | 'tunnel' | 'local'
}

export interface FlowTraffic {
    dest_ip: string
    packets: number
    bytes: number
    last_active?: string
    outer_src?: string
    outer_dst?: string
    direction?: string
}

export interface TopologyNode {
    id: string
    type: 'ue' | 'gnb' | 'upf' | 'dn'
    label: string
    ip?: string
    n3_ip?: string
    n4_ip?: string
    roles?: string[]
    role_source?: string
    confidence?: number
    // Data plane verification status
    verified?: boolean           // Whether verified against gtp5g kernel state
    verifyMethod?: 'gtp5g' | 'pfcp' | 'ebpf' | 'docker'  // Verification source
    lastVerified?: string        // ISO timestamp of last verification
    activeSessionCount?: number  // Active sessions through this node
    dataPlaneStatus?: 'active' | 'stale' | 'inactive' | 'unknown'
}

export interface TopologyLink {
    source: string
    target: string
    type: 'n3' | 'n4' | 'n6' | 'n9' | 'radio'
    label?: string
    hasActiveTraffic?: boolean   // Whether there's active traffic on this link
    trafficRate?: number         // Traffic rate in bytes/sec
    lastSeen?: string            // Timestamp of last traffic
    evidence?: string
    confidence?: number
    flow_selectors?: string[]
    configured?: boolean
    // Data plane verification status
    verified?: boolean           // Whether verified in gtp5g FAR/PDR
    teid?: string                // Associated TEID for this tunnel
    packetCount?: number         // Packets observed on this link
    bytesTotal?: number          // Total bytes observed
    latencyMs?: number           // Measured latency (if available)
}

export interface TopologyData {
    nodes: TopologyNode[]
    links: TopologyLink[]
    diagnostics?: TopologyDiagnostic[]
}

export interface TopologyDiagnostic {
    severity: 'error' | 'warning' | 'info'
    code: string
    message: string
    action: string
}

// API Functions
const API_BASE = '/api/v1'

export async function fetchHealth(): Promise<{ status: string; timestamp: string }> {
    const response = await fetch(`${API_BASE}/health`)
    if (!response.ok) throw new Error('Health check failed')
    return response.json()
}

export async function fetchTrafficMetrics(): Promise<TrafficStats> {
    const response = await fetch(`${API_BASE}/metrics/traffic`)
    if (!response.ok) throw new Error('Failed to fetch traffic metrics')
    return response.json()
}

export async function fetchDropMetrics(): Promise<DropStats> {
    const response = await fetch(`${API_BASE}/metrics/drops`)
    if (!response.ok) throw new Error('Failed to fetch drop metrics')
    return response.json()
}

export async function fetchSessions(): Promise<{
    total: number;
    total_all?: number;
    sessions: SessionInfo[];
    stale_sessions?: SessionInfo[];
    pending_sessions?: SessionInfo[];
    failed_sessions?: SessionInfo[];
    unclassified_sessions?: SessionInfo[];
    counts?: {
        active: number;
        stale: number;
        pending: number;
        failed: number;
        unclassified?: number;
    };
}> {
    const response = await fetch(`${API_BASE}/sessions`)
    if (!response.ok) throw new Error('Failed to fetch sessions')
    return response.json()
}

export async function fetchTopology(): Promise<TopologyData> {
    const response = await fetch(`${API_BASE}/topology`)
    if (!response.ok) throw new Error('Failed to fetch topology')
    return response.json()
}

export async function injectFault(type: string, target: string, count: number): Promise<void> {
    const response = await fetch(`${API_BASE}/fault/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, target, count }),
    })
    if (!response.ok) throw new Error('Failed to inject fault')
}

// WebSocket connection helper
export function createMetricsWebSocket(
    onMessage: (data: any) => void,
    onError: (error: Event) => void,
    onClose: () => void
): WebSocket {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    // Use the same host - vite proxy will handle forwarding to API server
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/metrics`)

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data)
            onMessage(data)
        } catch (e) {
            console.error('Failed to parse WebSocket message:', e)
        }
    }

    ws.onerror = onError
    ws.onclose = onClose

    return ws
}
