// go:build ignore

// upf_monitor.bpf.c - eBPF program to monitor gtp5g kernel module
// This program hooks into gtp5g functions to collect traffic statistics
// and detect packet drops.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Constants
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define IPPROTO_ICMPV6 58
#define GTP_U_PORT 2152

// Traffic direction
#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1
#define DIRECTION_UNKNOWN 255

// Packet metadata validity. Invalid fields must never be displayed as facts.
#define FIELD_TEID (1U << 0)
#define FIELD_SRC_IP (1U << 1)
#define FIELD_DST_IP (1U << 2)
#define FIELD_SRC_PORT (1U << 3)
#define FIELD_DST_PORT (1U << 4)

// Hook which established the packet context.
#define ORIGIN_UNKNOWN 0
#define ORIGIN_TRACE_DROP 1
#define ORIGIN_ENCAP_RECV 2
#define ORIGIN_DEV_XMIT 3
#define ORIGIN_KFREE_SKB 4
#define ORIGIN_IP_FORWARD 5

// Drop reasons - Direct mapping from gtp5g error codes (1:1)
// These match exactly with gtp5g/src/gtpu/encap.c definitions
#define DROP_REASON_PKT_DROPPED 1      // Generic packet dropped
#define DROP_REASON_ECHO_RESP_CREATE 2 // GTP Echo Response creation failed
#define DROP_REASON_NO_ROUTE 3         // No route to destination
#define DROP_REASON_PULL_FAILED 4      // skb_pull failed
#define DROP_REASON_INVALID_EXT_HDR 5  // Invalid GTP extension header
#define DROP_REASON_NO_PDR 6           // No PDR rule matched
#define DROP_REASON_GENERAL 7          // General error
#define DROP_REASON_UL_GATE_CLOSED 8   // Uplink gate closed (QoS)
#define DROP_REASON_DL_GATE_CLOSED 9   // Downlink gate closed (QoS)
#define DROP_REASON_PDR_NULL 10        // PDR pointer is NULL
#define DROP_REASON_NO_F_TEID 11       // No F-TEID found
#define DROP_REASON_URR_REPORT_FAIL 12 // URR report failed
#define DROP_REASON_RED_PACKET 13      // QoS RED drop
#define DROP_REASON_IP_XMIT_FAIL 14    // IP transmit failed
#define DROP_REASON_NOT_TPDU 15        // Not a T-PDU
#define DROP_REASON_PULL_HDR_FAIL 16   // Header pull failed
#define DROP_REASON_NETIF_RX_FAIL 17   // netif_rx failed
#define DROP_REASON_UNSUPPORTED_L3 18  // L3 protocol unsupported by gtp5g device
#define DROP_REASON_SKB_PREPARE_FAIL 19 // skb headroom preparation failed
#define DROP_REASON_FAR_MISSING 20      // PDR has no FAR
#define DROP_REASON_INVALID_FAR_ACTION 21 // FAR apply action is unsupported
#define DROP_REASON_OHR_MISSING 22      // Outer Header Removal is missing
#define DROP_REASON_OHC_MISSING 23      // Outer Header Creation is missing
#define DROP_REASON_UNKNOWN 255        // Unknown/other reasons

// ============================================================================
// Data Structures
// ============================================================================

// Traffic counter structure
struct traffic_counter
{
    __u64 packets;
    __u64 bytes;
    __u64 timestamp;
};

// Drop event structure (sent to userspace via ring buffer)
struct drop_event
{
    __u64 timestamp;
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_len;
    __u16 src_port;
    __u16 dst_port;
    __u16 valid_fields;
    __u8 reason;
    __u8 direction;
    __u8 family;
    __u8 l4_protocol;
    __u8 origin;
    __u8 icmp_type;
    __u8 pad[4];
};

// Packet event structure (for detailed tracing)
struct packet_event
{
    __u64 timestamp;
    __u32 teid;
    // Outer GTP-U endpoints. Zero for packets observed before encapsulation.
    __u32 src_ip;
    __u32 dst_ip;
    // Inner PDU endpoints used for ULCL flow/path attribution.
    __u32 inner_src_ip;
    __u32 inner_dst_ip;
    __u32 pkt_len;
    __u8 direction;
    __u8 qfi;
    __u8 pad[2];
};

// Session info (populated from userspace via PFCP sniffer)
struct session_info
{
    __u64 seid;
    __u32 ue_ip;
    __u32 upf_ip;
    __u64 created_at;
};

// ============================================================================
// BPF Maps
// ============================================================================

// Per-CPU traffic counters (avoids lock contention)
// Key: 0 = uplink, 1 = downlink
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct traffic_counter);
} traffic_stats SEC(".maps");

// Ring buffer for drop events (sent to userspace)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} drop_events SEC(".maps");

// Ring buffer for packet events (optional detailed tracing)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512KB
} packet_events SEC(".maps");

// TEID to Session mapping (populated from userspace)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // TEID
    __type(value, struct session_info);
} teid_session_map SEC(".maps");

// Per-TEID counters (for uplink, keyed by TEID)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // TEID
    __type(value, struct traffic_counter);
} teid_stats SEC(".maps");

// Per-UE IP counters (for downlink, keyed by UE IP)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // UE IP address
    __type(value, struct traffic_counter);
} ue_ip_stats SEC(".maps");

// Configuration flags (set from userspace)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} agent_config SEC(".maps");

// Pending packet info - for passing data from kprobe to kretprobe
// Keyed by task PID to support concurrent packets
struct pending_pkt_info
{
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u32 counted_len;
    __u16 valid_fields;
    __u8 direction;
    __u8 family;
    __u8 l4_protocol;
    __u8 origin;
    __u8 icmp_type;
    __u8 valid;
    __u8 counted;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // PID/TID
    __type(value, struct pending_pkt_info);
} pending_pkts SEC(".maps");

// ============================================================================
// PDR Lookup Event - for session validation via fentry/fexit
// ============================================================================

// PDR lookup event structure (sent to userspace for session validation)
struct pdr_lookup_event
{
    __u64 timestamp;
    __u32 teid;            // TEID being looked up (if available)
    __u8 pdr_found;        // 1 = found, 0 = not found
    __u8 direction;        // 0 = uplink (by TEID), 1 = downlink (by IP)
    __u8 pad[2];
    __u64 lookup_latency_ns;
};

// Ring buffer for PDR lookup events
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024); // 64KB
} pdr_events SEC(".maps");

// Pending PDR query info - for passing data from fentry to fexit
struct pending_pdr_query
{
    __u64 timestamp;
    __u32 teid;
    __u32 ue_ip;
    __u8 direction;
    __u8 pad[3];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32); // PID/TID
    __type(value, struct pending_pdr_query);
} pending_pdr_queries SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

static __always_inline void update_traffic_counter(__u32 direction, __u32 len)
{
    struct traffic_counter *counter;

    counter = bpf_map_lookup_elem(&traffic_stats, &direction);
    if (counter)
    {
        counter->packets++;
        counter->bytes += len;
        counter->timestamp = bpf_ktime_get_ns();
    }
}

static __always_inline void decrement_traffic_counter(__u32 direction,
                                                       __u32 len)
{
    struct traffic_counter *counter;

    counter = bpf_map_lookup_elem(&traffic_stats, &direction);
    if (counter)
    {
        if (counter->packets > 0)
            counter->packets--;
        if (counter->bytes >= len)
            counter->bytes -= len;
        else
            counter->bytes = 0;
        counter->timestamp = bpf_ktime_get_ns();
    }
}

static __always_inline void update_teid_counter(__u32 teid, __u32 len)
{
    struct traffic_counter *counter;
    struct traffic_counter new_counter = {0};

    counter = bpf_map_lookup_elem(&teid_stats, &teid);
    if (counter)
    {
        __sync_fetch_and_add(&counter->packets, 1);
        __sync_fetch_and_add(&counter->bytes, len);
        counter->timestamp = bpf_ktime_get_ns();
    }
    else
    {
        new_counter.packets = 1;
        new_counter.bytes = len;
        new_counter.timestamp = bpf_ktime_get_ns();
        // Another CPU may create this TEID between lookup and insert. Avoid
        // overwriting its counter; add this packet to the winning entry.
        if (bpf_map_update_elem(&teid_stats, &teid, &new_counter,
                                BPF_NOEXIST) < 0)
        {
            counter = bpf_map_lookup_elem(&teid_stats, &teid);
            if (counter)
            {
                __sync_fetch_and_add(&counter->packets, 1);
                __sync_fetch_and_add(&counter->bytes, len);
                counter->timestamp = bpf_ktime_get_ns();
            }
        }
    }
}

static __always_inline void decrement_teid_counter(__u32 teid, __u32 len)
{
    struct traffic_counter *counter;

    if (!teid)
        return;
    counter = bpf_map_lookup_elem(&teid_stats, &teid);
    if (counter)
    {
        // This drop rolls back the increment performed by this same probe
        // invocation, so the paired values cannot legitimately underflow.
        __sync_fetch_and_sub(&counter->packets, 1);
        __sync_fetch_and_sub(&counter->bytes, len);
        counter->timestamp = bpf_ktime_get_ns();
    }
}

// Update per-UE IP counter (for downlink traffic)
static __always_inline void update_ue_ip_counter(__u32 ue_ip, __u32 len)
{
    struct traffic_counter *counter;
    struct traffic_counter new_counter = {0};

    if (ue_ip == 0)
        return;

    counter = bpf_map_lookup_elem(&ue_ip_stats, &ue_ip);
    if (counter)
    {
        __sync_fetch_and_add(&counter->packets, 1);
        __sync_fetch_and_add(&counter->bytes, len);
        counter->timestamp = bpf_ktime_get_ns();
    }
    else
    {
        new_counter.packets = 1;
        new_counter.bytes = len;
        new_counter.timestamp = bpf_ktime_get_ns();
        if (bpf_map_update_elem(&ue_ip_stats, &ue_ip, &new_counter,
                                BPF_NOEXIST) < 0)
        {
            counter = bpf_map_lookup_elem(&ue_ip_stats, &ue_ip);
            if (counter)
            {
                __sync_fetch_and_add(&counter->packets, 1);
                __sync_fetch_and_add(&counter->bytes, len);
                counter->timestamp = bpf_ktime_get_ns();
            }
        }
    }
}

static __always_inline void decrement_ue_ip_counter(__u32 ue_ip, __u32 len)
{
    struct traffic_counter *counter;

    if (!ue_ip)
        return;
    counter = bpf_map_lookup_elem(&ue_ip_stats, &ue_ip);
    if (counter)
    {
        __sync_fetch_and_sub(&counter->packets, 1);
        __sync_fetch_and_sub(&counter->bytes, len);
        counter->timestamp = bpf_ktime_get_ns();
    }
}

static __always_inline void emit_drop_event(const struct pending_pkt_info *info,
                                            __u8 reason)
{
    struct drop_event *event;

    event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event)
    {
        return;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->teid = info->teid;
    event->src_ip = info->src_ip;
    event->dst_ip = info->dst_ip;
    event->pkt_len = info->pkt_len;
    event->src_port = info->src_port;
    event->dst_port = info->dst_port;
    event->valid_fields = info->valid_fields;
    event->reason = reason;
    event->direction = info->direction;
    event->family = info->family;
    event->l4_protocol = info->l4_protocol;
    event->origin = info->origin;
    event->icmp_type = info->icmp_type;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline int parse_ipv4(unsigned char *ip_header,
                                      struct pending_pkt_info *info)
{
    __u8 version_ihl = 0;
    __u8 ihl;

    if (!ip_header ||
        bpf_probe_read_kernel(&version_ihl, sizeof(version_ihl), ip_header) < 0 ||
        (version_ihl >> 4) != 4)
        return 0;

    ihl = (version_ihl & 0x0f) * 4;
    if (ihl < 20)
        return 0;

    info->family = 4;
    bpf_probe_read_kernel(&info->l4_protocol, sizeof(info->l4_protocol),
                          ip_header + 9);
    if (bpf_probe_read_kernel(&info->src_ip, sizeof(info->src_ip),
                              ip_header + 12) == 0)
        info->valid_fields |= FIELD_SRC_IP;
    if (bpf_probe_read_kernel(&info->dst_ip, sizeof(info->dst_ip),
                              ip_header + 16) == 0)
        info->valid_fields |= FIELD_DST_IP;

    if (info->l4_protocol == IPPROTO_UDP ||
        info->l4_protocol == IPPROTO_TCP)
    {
        __u16 src_port = 0, dst_port = 0;
        unsigned char *l4_header = ip_header + ihl;

        if (bpf_probe_read_kernel(&src_port, sizeof(src_port), l4_header) == 0)
        {
            info->src_port = bpf_ntohs(src_port);
            info->valid_fields |= FIELD_SRC_PORT;
        }
        if (bpf_probe_read_kernel(&dst_port, sizeof(dst_port),
                                  l4_header + 2) == 0)
        {
            info->dst_port = bpf_ntohs(dst_port);
            info->valid_fields |= FIELD_DST_PORT;
        }
    }

    return 1;
}

static __always_inline int parse_ipv6(unsigned char *ip_header,
                                      struct pending_pkt_info *info)
{
    __u8 version = 0;

    if (!ip_header ||
        bpf_probe_read_kernel(&version, sizeof(version), ip_header) < 0 ||
        (version >> 4) != 6)
        return 0;

    info->family = 6;
    bpf_probe_read_kernel(&info->l4_protocol, sizeof(info->l4_protocol),
                          ip_header + 6);
    if (info->l4_protocol == IPPROTO_ICMPV6)
        bpf_probe_read_kernel(&info->icmp_type, sizeof(info->icmp_type),
                              ip_header + 40);
    return 1;
}

static __always_inline void parse_l3(unsigned char *ip_header,
                                     struct pending_pkt_info *info)
{
    if (!parse_ipv4(ip_header, info))
        parse_ipv6(ip_header, info);
}

// Return the inner IPv4 packet length from its own total_length field. This
// gives UL and DL counters the same PDU-layer byte definition and excludes
// GTP-U/UDP overhead and skb padding.
static __always_inline __u32 ipv4_pdu_len(unsigned char *ip_header)
{
    __u8 version_ihl = 0;
    __u16 total_len = 0;

    if (!ip_header ||
        bpf_probe_read_kernel(&version_ihl, sizeof(version_ihl), ip_header) < 0 ||
        (version_ihl >> 4) != 4 ||
        bpf_probe_read_kernel(&total_len, sizeof(total_len), ip_header + 2) < 0)
        return 0;

    total_len = bpf_ntohs(total_len);
    if (total_len < 20)
        return 0;
    return total_len;
}

// Locate the T-PDU payload after the variable-length GTPv1-U header.
static __always_inline __u32 gtp_inner_ipv4_info(unsigned char *gtp_header,
                                                 __u32 *src_ip,
                                                 __u32 *dst_ip)
{
    __u8 flags = 0;
    __u8 message_type = 0;
    __u8 next_ext = 0;
    __u32 offset = 8;

    if (!gtp_header ||
        bpf_probe_read_kernel(&flags, sizeof(flags), gtp_header) < 0 ||
        bpf_probe_read_kernel(&message_type, sizeof(message_type),
                              gtp_header + 1) < 0 ||
        (flags >> 5) != 1 ||
        message_type != 255)
        return 0;

    // E, S or PN means the four-byte optional field is present.
    if (flags & 0x07)
    {
        offset = 12;
        if (flags & 0x04)
            bpf_probe_read_kernel(&next_ext, sizeof(next_ext),
                                  gtp_header + 11);
    }

#pragma unroll
    for (int i = 0; i < 4; i++)
    {
        __u8 ext_units = 0;
        __u8 following_ext = 0;
        __u32 ext_len;

        if (!next_ext)
            break;
        if (bpf_probe_read_kernel(&ext_units, sizeof(ext_units),
                                  gtp_header + offset) < 0 ||
            ext_units == 0)
            return 0;
        ext_len = (__u32)ext_units * 4;
        if (bpf_probe_read_kernel(&following_ext, sizeof(following_ext),
                                  gtp_header + offset + ext_len - 1) < 0)
            return 0;
        offset += ext_len;
        next_ext = following_ext;
    }
    if (next_ext)
        return 0;

    unsigned char *inner_ip = gtp_header + offset;
    __u32 pdu_len = ipv4_pdu_len(inner_ip);
    if (!pdu_len)
        return 0;
    if (src_ip)
        bpf_probe_read_kernel(src_ip, sizeof(*src_ip), inner_ip + 12);
    if (dst_ip)
        bpf_probe_read_kernel(dst_ip, sizeof(*dst_ip), inner_ip + 16);
    return pdu_len;
}

static __always_inline void emit_packet_event(__u32 teid,
                                              __u32 src_ip, __u32 dst_ip,
                                              __u32 inner_src_ip,
                                              __u32 inner_dst_ip,
                                              __u32 pkt_len, __u8 direction,
                                              __u8 qfi)
{
    struct packet_event *event;

    // Check if detailed tracing is enabled
    __u32 key = 0; // config key for detailed_tracing
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return;
    }

    event = bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if (!event)
    {
        return;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->teid = teid;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->inner_src_ip = inner_src_ip;
    event->inner_dst_ip = inner_dst_ip;
    event->pkt_len = pkt_len;
    event->direction = direction;
    event->qfi = qfi;

    bpf_ringbuf_submit(event, 0);
}

// ============================================================================
// gtp5g error code pass-through (1:1 mapping)
// No conversion needed - we pass the error_code directly as drop reason
// ============================================================================
static __always_inline __u8 map_gtp5g_error_to_reason(int error_code)
{
    // Direct pass-through: gtp5g error codes map 1:1 to API reasons.
    if (error_code >= 1 && error_code <= 23)
    {
        return (__u8)error_code;
    }
    return DROP_REASON_UNKNOWN;
}

// ============================================================================
// Kprobes - Hook gtp5g functions
// ============================================================================

// Hook: gtp5g_trace_drop - THE PRIMARY DROP DETECTION HOOK
// This is called by gtp5g whenever a packet is dropped with specific reason
SEC("kprobe/gtp5g_trace_drop")
int BPF_KPROBE(kprobe_gtp5g_trace_drop, int error_code, struct sk_buff *skb)
{
    struct pending_pkt_info info = {0};
    struct pending_pkt_info *pending;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u8 reason = map_gtp5g_error_to_reason(error_code);

    info.direction = DIRECTION_UNKNOWN;
    info.origin = ORIGIN_TRACE_DROP;

    // The skb layout at trace_drop varies by call site. Prefer context saved
    // by the data-plane entry probes over guessing offsets here.
    pending = bpf_map_lookup_elem(&pending_pkts, &tid);
    if (pending)
    {
        info = *pending;
        if (info.counted)
        {
            decrement_traffic_counter(info.direction, info.counted_len);
            if (info.direction == DIRECTION_UPLINK)
                decrement_teid_counter(info.teid, info.counted_len);
            else if (info.direction == DIRECTION_DOWNLINK)
                decrement_ue_ip_counter(info.dst_ip, info.counted_len);
            info.counted = 0;
        }
        bpf_map_delete_elem(&pending_pkts, &tid);
    }
    else if (skb)
    {
        unsigned char *head = BPF_CORE_READ(skb, head);
        __u16 network_header = BPF_CORE_READ(skb, network_header);

        info.pkt_len = BPF_CORE_READ(skb, len);
        if (head)
        {
            parse_l3(head + network_header, &info);
            if (info.family == 4 &&
                info.l4_protocol == IPPROTO_UDP &&
                info.dst_port == GTP_U_PORT)
            {
                __u8 version_ihl = 0;
                __u32 teid = 0;
                unsigned char *gtp_header;

                bpf_probe_read_kernel(&version_ihl, sizeof(version_ihl),
                                      head + network_header);
                gtp_header =
                    head + network_header + ((version_ihl & 0x0f) * 4) + 8;
                if (bpf_probe_read_kernel(&teid, sizeof(teid),
                                          gtp_header + 4) == 0)
                {
                    info.teid = bpf_ntohl(teid);
                    if (info.teid)
                        info.valid_fields |= FIELD_TEID;
                }
            }
        }
    }

    emit_drop_event(&info, reason);
    return 0;
}

// Hook: gtp5g_encap_recv - Entry point for uplink packets
// This function is called when a GTP-U packet is received on the UDP socket
SEC("kprobe/gtp5g_encap_recv")
int BPF_KPROBE(kprobe_gtp5g_encap_recv, struct sock *sk, struct sk_buff *skb)
{
    __u32 len;
    __u32 teid = 0;
    __u32 pdu_len = 0;
    __u32 inner_src_ip = 0;
    __u32 inner_dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    unsigned char *head;
    __u16 transport_header;
    __u16 network_header;
    __u32 tid;
    struct pending_pkt_info pkt_info = {0};

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);
    pkt_info.pkt_len = len;
    pkt_info.direction = DIRECTION_UPLINK;
    pkt_info.origin = ORIGIN_ENCAP_RECV;

    // Extract TEID from GTP-U header
    // GTP-U header: Flags(1) + Type(1) + Length(2) + TEID(4)
    // TEID is at offset 4 from the start of GTP header
    head = BPF_CORE_READ(skb, head);
    transport_header = BPF_CORE_READ(skb, transport_header);
    network_header = BPF_CORE_READ(skb, network_header);

    if (head)
    {
        // UDP header is 8 bytes, GTP-U header starts after UDP
        // GTP TEID is at offset 4 of GTP header
        unsigned char *gtp_header = head + transport_header + 8; // skip UDP header
        if (bpf_probe_read_kernel(&teid, sizeof(teid), gtp_header + 4) == 0)
        {
            teid = bpf_ntohl(teid);
            if (teid)
                pkt_info.valid_fields |= FIELD_TEID;
        }

        // Read outer IP metadata with protocol/version validation.
        parse_l3(head + network_header, &pkt_info);

        // Read UDP ports
        unsigned char *udp_header = head + transport_header;
        if (bpf_probe_read_kernel(&src_port, sizeof(src_port), udp_header) == 0)
        {
            src_port = bpf_ntohs(src_port);
            pkt_info.valid_fields |= FIELD_SRC_PORT;
        }
        if (bpf_probe_read_kernel(&dst_port, sizeof(dst_port),
                                  udp_header + 2) == 0)
        {
            dst_port = bpf_ntohs(dst_port);
            pkt_info.valid_fields |= FIELD_DST_PORT;
        }

        if (teid > 0)
        {
            pdu_len = gtp_inner_ipv4_info(gtp_header, &inner_src_ip,
                                          &inner_dst_ip);
            if (pdu_len > 0)
            {
                update_traffic_counter(DIRECTION_UPLINK, pdu_len);
                update_teid_counter(teid, pdu_len);
                pkt_info.counted_len = pdu_len;
                pkt_info.counted = 1;

                // Emit packet event for detailed tracking
                emit_packet_event(teid, pkt_info.src_ip, pkt_info.dst_ip,
                                  inner_src_ip, inner_dst_ip, pdu_len,
                                  DIRECTION_UPLINK, 0);
            }
        }
    }

    // Save packet info until trace_drop or the cleanup return probe.
    tid = (__u32)bpf_get_current_pid_tgid();
    pkt_info.teid = teid;
    pkt_info.src_port = src_port;
    pkt_info.dst_port = dst_port;
    pkt_info.valid = 1;
    bpf_map_update_elem(&pending_pkts, &tid, &pkt_info, BPF_ANY);

    return 0;
}

// Hook: gtp5g_dev_xmit - Entry point for downlink packets
// This function is called when a packet is transmitted through upfgtp interface
SEC("kprobe/gtp5g_dev_xmit")
int BPF_KPROBE(kprobe_gtp5g_dev_xmit, struct sk_buff *skb, struct net_device *dev)
{
    __u32 len;
    __u32 pdu_len;
    unsigned char *data;
    __u32 data_len;
    __u32 tid;
    struct pending_pkt_info pkt_info = {0};

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);
    pkt_info.pkt_len = len;
    pkt_info.direction = DIRECTION_UNKNOWN;
    pkt_info.origin = ORIGIN_DEV_XMIT;

    // For downlink, we need to find the destination TEID
    // The TEID will be added during encapsulation, but we can try to
    // look it up from the inner IP destination address
    data = BPF_CORE_READ(skb, data);
    data_len = BPF_CORE_READ(skb, len);

    if (data && data_len >= 1)
    {
        parse_l3(data, &pkt_info);

        // gtp5g currently supports IPv4 user-plane payloads. An automatic
        // IPv6 Router Solicitation emitted when upfgtp is created is an
        // infrastructure event, not downlink UE traffic.
        if (pkt_info.family == 4)
        {
            pkt_info.direction = DIRECTION_DOWNLINK;
            pdu_len = ipv4_pdu_len(data);
            if (pdu_len > 0)
            {
                update_traffic_counter(DIRECTION_DOWNLINK, pdu_len);
                pkt_info.counted_len = pdu_len;
                pkt_info.counted = 1;
                if (pkt_info.dst_ip > 0)
                {
                    update_ue_ip_counter(pkt_info.dst_ip, pdu_len);
                    emit_packet_event(0, 0, 0, pkt_info.src_ip,
                                      pkt_info.dst_ip, pdu_len,
                                      DIRECTION_DOWNLINK, 0);
                }
            }
        }
    }

    // Save packet info until trace_drop or the cleanup return probe.
    tid = (__u32)bpf_get_current_pid_tgid();
    pkt_info.valid = 1;
    bpf_map_update_elem(&pending_pkts, &tid, &pkt_info, BPF_ANY);

    return 0;
}

// Cleanup-only return probes. gtp5g returns NETDEV_TX_OK for some errors, so
// their return values are not used as drop signals.
SEC("kretprobe/gtp5g_encap_recv")
int BPF_KRETPROBE(kretprobe_gtp5g_encap_recv_cleanup)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending_pkts, &tid);
    return 0;
}

SEC("kretprobe/gtp5g_dev_xmit")
int BPF_KRETPROBE(kretprobe_gtp5g_dev_xmit_cleanup)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending_pkts, &tid);
    return 0;
}

// Hook: gtp5g_handle_skb - Internal packet handling (if available)
// Some versions of gtp5g have this function for packet processing
SEC("kprobe/gtp5g_handle_skb")
int BPF_KPROBE(kprobe_gtp5g_handle_skb, struct sk_buff *skb)
{
    // This is a placeholder - actual implementation depends on gtp5g version
    return 0;
}

// Hook: kretprobe for pdr_find_by_gtp1u - Detect PDR lookup failures
// NOTE: Drop events are now captured by kprobe_gtp5g_trace_drop which is more reliable
// This kretprobe is kept for potential future use but does not emit drop events
SEC("kretprobe/pdr_find_by_gtp1u")
int BPF_KRETPROBE(kretprobe_pdr_find_by_gtp1u, void *ret)
{
    // kprobe_gtp5g_trace_drop now handles all drop detection
    // This hook is kept as a backup but doesn't emit events to avoid duplicates
    return 0;
}

// Hook: kretprobe for pdr_find_by_ipv4 - Detect PDR lookup failures (downlink)
// NOTE: Drop events are now captured by kprobe_gtp5g_trace_drop which is more reliable
// This kretprobe is kept for potential future use but does not emit drop events
SEC("kretprobe/pdr_find_by_ipv4")
int BPF_KRETPROBE(kretprobe_pdr_find_by_ipv4, void *ret)
{
    // kprobe_gtp5g_trace_drop now handles all drop detection
    // This hook is kept as a backup but doesn't emit events to avoid duplicates
    return 0;
}

// The gtp5g return probes above only remove per-thread context. Drop detection
// remains exclusively in gtp5g_trace_drop to avoid duplicate events.

// Hook: kfree_skb tracepoint - Detect packet drops
// This tracepoint fires whenever a packet is dropped in the kernel
SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb;
    __u32 len;
    __u8 reason = DROP_REASON_GENERAL; // Code 7: General kernel drop
    struct pending_pkt_info info = {0};

    // Check if drop tracing is enabled (config key 1)
    __u32 key = 1;
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    skb = (struct sk_buff *)ctx->skbaddr;

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Only emit if packet has meaningful length (filter noise)
    if (len < 20)
    {
        return 0;
    }

    info.pkt_len = len;
    info.direction = DIRECTION_UNKNOWN;
    info.origin = ORIGIN_KFREE_SKB;
    emit_drop_event(&info, reason);

    return 0;
}

// Hook: nf_hook_slow - Detect netfilter drops (firewall/iptables)
// This catches packets dropped by iptables rules
SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(kprobe_nf_hook_slow, struct sk_buff *skb)
{
    // Check if this tracing is enabled
    __u32 key = 2; // config key for netfilter tracing
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    // This is entry probe, we need kretprobe to check verdict
    return 0;
}

// Hook: ip_forward - Track forwarded packets
SEC("kprobe/ip_forward")
int BPF_KPROBE(kprobe_ip_forward, struct sk_buff *skb)
{
    // Track IP forwarding for routing analysis
    return 0;
}

// Hook: kretprobe for ip_forward - Detect routing drops
SEC("kretprobe/ip_forward")
int BPF_KRETPROBE(kretprobe_ip_forward, int ret)
{
    __u32 key = 2;
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    if (ret != 0)
    {
        struct pending_pkt_info info = {0};
        info.direction = DIRECTION_UNKNOWN;
        info.origin = ORIGIN_IP_FORWARD;
        emit_drop_event(&info, DROP_REASON_NO_ROUTE);
    }
    return 0;
}

// ============================================================================
// fentry/fexit hooks - Higher efficiency PDR lookup tracking
// Reference: gtp5g-tracer project
// ============================================================================

// Helper: emit PDR lookup event to userspace
static __always_inline void emit_pdr_lookup_event(__u32 teid, __u8 pdr_found,
                                                   __u8 direction, __u64 latency_ns)
{
    struct pdr_lookup_event *event;

    event = bpf_ringbuf_reserve(&pdr_events, sizeof(*event), 0);
    if (!event)
    {
        return;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->teid = teid;
    event->pdr_found = pdr_found;
    event->direction = direction;
    event->lookup_latency_ns = latency_ns;

    bpf_ringbuf_submit(event, 0);
}

// fentry hook for pdr_find_by_gtp1u - Entry point for uplink PDR lookup
// This provides more efficient tracking than kretprobe
SEC("fentry/pdr_find_by_gtp1u")
int BPF_PROG(fentry_pdr_find_by_gtp1u)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pending_pdr_query query = {0};

    query.timestamp = bpf_ktime_get_ns();
    query.direction = DIRECTION_UPLINK;
    // TEID extraction would require access to function args
    // For now, we track timing and result

    bpf_map_update_elem(&pending_pdr_queries, &pid, &query, BPF_ANY);
    return 0;
}

// fexit hook for pdr_find_by_gtp1u - Capture PDR lookup result
SEC("fexit/pdr_find_by_gtp1u")
int BPF_PROG(fexit_pdr_find_by_gtp1u, void *ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pending_pdr_query *query;

    query = bpf_map_lookup_elem(&pending_pdr_queries, &pid);
    if (!query)
    {
        return 0;
    }

    __u64 latency = bpf_ktime_get_ns() - query->timestamp;
    __u8 pdr_found = (ret != NULL) ? 1 : 0;

    // Emit event for userspace processing
    emit_pdr_lookup_event(query->teid, pdr_found, query->direction, latency);

    // Cleanup
    bpf_map_delete_elem(&pending_pdr_queries, &pid);
    return 0;
}

// fentry hook for pdr_find_by_ipv4 - Entry point for downlink PDR lookup
SEC("fentry/pdr_find_by_ipv4")
int BPF_PROG(fentry_pdr_find_by_ipv4)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pending_pdr_query query = {0};

    query.timestamp = bpf_ktime_get_ns();
    query.direction = DIRECTION_DOWNLINK;

    bpf_map_update_elem(&pending_pdr_queries, &pid, &query, BPF_ANY);
    return 0;
}

// fexit hook for pdr_find_by_ipv4 - Capture downlink PDR lookup result
SEC("fexit/pdr_find_by_ipv4")
int BPF_PROG(fexit_pdr_find_by_ipv4, void *ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pending_pdr_query *query;

    query = bpf_map_lookup_elem(&pending_pdr_queries, &pid);
    if (!query)
    {
        return 0;
    }

    __u64 latency = bpf_ktime_get_ns() - query->timestamp;
    __u8 pdr_found = (ret != NULL) ? 1 : 0;

    emit_pdr_lookup_event(0, pdr_found, query->direction, latency);

    bpf_map_delete_elem(&pending_pdr_queries, &pid);
    return 0;
}

// fentry hook for policePacket - QoS enforcement entry
// From gtp5g-tracer: tracks when QoS policing is applied
SEC("fentry/policePacket")
int BPF_PROG(fentry_policePacket)
{
    // QoS policing is being applied
    // This can be extended to emit QoS events in the future
    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "GPL";
