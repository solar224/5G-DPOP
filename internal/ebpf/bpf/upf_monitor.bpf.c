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
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define GTP_U_PORT 2152

// Traffic direction
#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1

// Drop reasons - Enhanced categories
#define DROP_REASON_NO_PDR 0          // No PDR rule matched
#define DROP_REASON_INVALID_TEID 1    // Invalid or unknown TEID
#define DROP_REASON_QOS 2             // QoS policy violation
#define DROP_REASON_KERNEL 3          // Generic kernel drop
#define DROP_REASON_NO_FAR 4          // No FAR action defined
#define DROP_REASON_BUFFER_OVERFLOW 5 // Ring buffer or queue overflow
#define DROP_REASON_TTL_EXPIRED 6     // TTL/Hop limit expired
#define DROP_REASON_MTU_EXCEEDED 7    // Packet too large
#define DROP_REASON_MALFORMED 8       // Malformed GTP header
#define DROP_REASON_NO_TUNNEL 9       // GTP tunnel not found
#define DROP_REASON_ENCAP_FAIL 10     // Encapsulation failed
#define DROP_REASON_DECAP_FAIL 11     // Decapsulation failed
#define DROP_REASON_ROUTING 12        // Routing decision drop
#define DROP_REASON_POLICY 13         // Policy/ACL drop
#define DROP_REASON_MEMORY 14         // Memory allocation failure

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
    __u16 src_port;
    __u16 dst_port;
    __u32 pkt_len;
    __u8 reason;
    __u8 direction;
    __u8 pad[2];
};

// Packet event structure (for detailed tracing)
struct packet_event
{
    __u64 timestamp;
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
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

static __always_inline void update_teid_counter(__u32 teid, __u32 len)
{
    struct traffic_counter *counter;
    struct traffic_counter new_counter = {0};

    counter = bpf_map_lookup_elem(&teid_stats, &teid);
    if (counter)
    {
        counter->packets++;
        counter->bytes += len;
        counter->timestamp = bpf_ktime_get_ns();
    }
    else
    {
        new_counter.packets = 1;
        new_counter.bytes = len;
        new_counter.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&teid_stats, &teid, &new_counter, BPF_ANY);
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
        counter->packets++;
        counter->bytes += len;
        counter->timestamp = bpf_ktime_get_ns();
    }
    else
    {
        new_counter.packets = 1;
        new_counter.bytes = len;
        new_counter.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&ue_ip_stats, &ue_ip, &new_counter, BPF_ANY);
    }
}

static __always_inline void emit_drop_event(__u32 teid, __u32 src_ip, __u32 dst_ip,
                                            __u32 pkt_len, __u8 reason, __u8 direction)
{
    struct drop_event *event;

    event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event)
    {
        return;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->teid = teid;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->pkt_len = pkt_len;
    event->reason = reason;
    event->direction = direction;
    event->src_port = 0;
    event->dst_port = 0;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_packet_event(__u32 teid, __u32 src_ip, __u32 dst_ip,
                                              __u32 pkt_len, __u8 direction, __u8 qfi)
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
    event->pkt_len = pkt_len;
    event->direction = direction;
    event->qfi = qfi;

    bpf_ringbuf_submit(event, 0);
}

// ============================================================================
// Kprobes - Hook gtp5g functions
// ============================================================================

// Hook: gtp5g_encap_recv - Entry point for uplink packets
// This function is called when a GTP-U packet is received on the UDP socket
SEC("kprobe/gtp5g_encap_recv")
int BPF_KPROBE(kprobe_gtp5g_encap_recv, struct sock *sk, struct sk_buff *skb)
{
    __u32 len;
    __u32 teid = 0;
    unsigned char *head;
    __u16 transport_header;

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Update uplink counter
    update_traffic_counter(DIRECTION_UPLINK, len);

    // Extract TEID from GTP-U header
    // GTP-U header: Flags(1) + Type(1) + Length(2) + TEID(4)
    // TEID is at offset 4 from the start of GTP header
    head = BPF_CORE_READ(skb, head);
    transport_header = BPF_CORE_READ(skb, transport_header);

    if (head && transport_header > 0)
    {
        // UDP header is 8 bytes, GTP-U header starts after UDP
        // GTP TEID is at offset 4 of GTP header
        unsigned char *gtp_header = head + transport_header + 8; // skip UDP header
        bpf_probe_read_kernel(&teid, sizeof(teid), gtp_header + 4);
        teid = bpf_ntohl(teid);

        if (teid > 0)
        {
            update_teid_counter(teid, len);

            // Emit packet event for detailed tracking
            __u32 src_ip = 0, dst_ip = 0;
            emit_packet_event(teid, src_ip, dst_ip, len, DIRECTION_UPLINK, 0);
        }
    }

    return 0;
}

// Hook: gtp5g_dev_xmit - Entry point for downlink packets
// This function is called when a packet is transmitted through upfgtp interface
SEC("kprobe/gtp5g_dev_xmit")
int BPF_KPROBE(kprobe_gtp5g_dev_xmit, struct sk_buff *skb, struct net_device *dev)
{
    __u32 len;
    __u32 teid = 0;
    unsigned char *data;
    __u32 data_len;

    if (!skb)
    {
        return 0;
    }

    // Read packet length
    len = BPF_CORE_READ(skb, len);

    // Update downlink counter
    update_traffic_counter(DIRECTION_DOWNLINK, len);

    // For downlink, we need to find the destination TEID
    // The TEID will be added during encapsulation, but we can try to
    // look it up from the inner IP destination address
    data = BPF_CORE_READ(skb, data);
    data_len = BPF_CORE_READ(skb, len);

    if (data && data_len >= 20)
    {
        // Read inner IP header to get destination (UE IP)
        __u32 dst_ip = 0;
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), data + 16); // IP dst at offset 16

        // Update per-UE IP counter for downlink traffic
        if (dst_ip > 0)
        {
            update_ue_ip_counter(dst_ip, len);
            emit_packet_event(0, 0, dst_ip, len, DIRECTION_DOWNLINK, 0);
        }
    }

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

// Hook: kretprobe for gtp5g_encap_recv - Detect uplink drops
// Returns < 0 indicate packet was dropped
SEC("kretprobe/gtp5g_encap_recv")
int BPF_KRETPROBE(kretprobe_gtp5g_encap_recv, int ret)
{
    if (ret < 0)
    {
        // Packet was dropped during uplink processing
        __u8 reason = DROP_REASON_DECAP_FAIL;

        // Map return codes to drop reasons
        if (ret == -2) // ENOENT - no PDR
        {
            reason = DROP_REASON_NO_PDR;
        }
        else if (ret == -22) // EINVAL - invalid TEID
        {
            reason = DROP_REASON_INVALID_TEID;
        }
        else if (ret == -12) // ENOMEM
        {
            reason = DROP_REASON_MEMORY;
        }

        emit_drop_event(0, 0, 0, 0, reason, DIRECTION_UPLINK);
    }
    return 0;
}

// Hook: kretprobe for gtp5g_dev_xmit - Detect downlink drops
SEC("kretprobe/gtp5g_dev_xmit")
int BPF_KRETPROBE(kretprobe_gtp5g_dev_xmit, int ret)
{
    if (ret != 0) // NETDEV_TX_OK = 0
    {
        // Packet was dropped during downlink processing
        __u8 reason = DROP_REASON_ENCAP_FAIL;

        emit_drop_event(0, 0, 0, 0, reason, DIRECTION_DOWNLINK);
    }
    return 0;
}

// Hook: kfree_skb tracepoint - Detect packet drops
// This tracepoint fires whenever a packet is dropped in the kernel
SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb;
    void *location;
    __u32 len;
    __u8 reason = DROP_REASON_KERNEL;

    // Check if drop tracing is enabled (config key 1)
    __u32 key = 1;
    __u32 *enabled = bpf_map_lookup_elem(&agent_config, &key);
    if (!enabled || *enabled == 0)
    {
        return 0;
    }

    skb = (struct sk_buff *)ctx->skbaddr;
    location = (void *)ctx->location;

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

// Try to determine more specific drop reason from drop_reason field (kernel 5.17+)
// The drop_reason is available in newer kernels
#ifdef BPF_CORE_READ_USER
    __u32 drop_reason = 0;
// ctx->reason available in newer kernels
#endif

    emit_drop_event(0, 0, 0, len, reason, 0);

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
        emit_drop_event(0, 0, 0, 0, DROP_REASON_ROUTING, 0);
    }
    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "GPL";
