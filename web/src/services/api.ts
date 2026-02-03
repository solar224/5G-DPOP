// API Types
export interface TrafficStats {
    uplink: DirectionStats
    downlink: DirectionStats
}

export interface DirectionStats {
    packets: number
    bytes: number
    throughput_mbps: number
    last_updated: string
}

export interface DropStats {
    total: number
    rate_percent: number
    recent_drops: DropEvent[]
    by_reason: Record<string, number>
}

export interface DropEvent {
    timestamp: string
    teid: string
    src_ip: string
    dst_ip: string
    src_port?: number
    dst_port?: number
    reason: string
    direction: string
    pkt_len: number
    // Extended session correlation info (populated by frontend from sessions data)
    session?: {
        seid?: string
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
        description: 'Generic error in gtp5g module from dev.c. Triggered when gtp5g_dev_xmit() fails to forward a packet.',
        impact: 'Packet dropped during transmission through gtp5g device.',
        possibleCauses: [
            'gtp5g device transmit error',
            'Packet forwarding failure in gtp5g_handle_skb_ipv4',
            'No matching PDR for downlink packet',
            'FAR action processing error'
        ],
        suggestedActions: [
            'Check dmesg for gtp5g errors: dmesg | grep -i gtp5g | tail -50',
            'Verify gtp5g device status: ip link show type gtp5g',
            'Check UPF status: docker ps | grep upf',
            'Review 5G-DPOP sessions: curl localhost:8080/api/v1/sessions'
        ],
        severity: 'warning',
        layer: 'GTP'
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
        name: 'Unknown Error',
        description: 'Unknown or unclassified drop reason. Error code not recognized.',
        impact: 'Packet dropped for unknown reason.',
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
    // 基本識別 (後端回傳字串格式)
    seid: string           // "0x1234" 格式
    ue_ip: string
    teids: string[]        // ["0x1a", "0x1b"] 格式
    teid_ul?: string       // Uplink TEID (gNB -> UPF) "0x1a" 格式
    teid_dl?: string       // Downlink TEID (UPF -> gNB) "0x1b" 格式
    created_at: string     // RFC3339 格式 "2025-11-29T16:22:12Z"

    // 封包統計
    packets_ul: number
    packets_dl: number
    bytes_ul: number
    bytes_dl: number

    // 5G 識別資訊
    supi?: string          // "imsi-208930000000001"
    dnn?: string           // "internet"
    s_nssai?: string       // "SST:1, SD:010203"
    qfi?: number           // QoS Flow ID
    session_type?: string  // "IPv4"
    pdu_session_id?: number

    // 網路節點 IP
    upf_ip?: string
    gnb_ip?: string

    // QoS 參數
    qos_5qi?: number       // 5QI 值
    arp_priority?: number
    gbr_ul_kbps?: number
    gbr_dl_kbps?: number
    mbr_ul_kbps?: number
    mbr_dl_kbps?: number

    // 狀態
    status: string
    duration?: string
    last_active?: string
}

export interface TopologyNode {
    id: string
    type: 'ue' | 'gnb' | 'upf' | 'dn'
    label: string
    ip?: string
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
    counts?: {
        active: number;
        stale: number;
        pending: number;
        failed: number;
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
