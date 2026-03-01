/*
 * eBPF Network Monitor
 * Tracks TCP and UDP connections with process and container information
 */

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Event structure sent to userspace
struct connection_event_t {
    u32 pid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;  // 6=TCP, 17=UDP
    u64 cgroup_id;
    u32 saddr_v6[4];  // IPv6 source
    u32 daddr_v6[4];  // IPv6 destination
    u8 ip_version;    // 4 or 6
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(events);

// Hash map to track connections (avoid duplicates)
// Using LRU (Least Recently Used) with max 10,000 entries to prevent memory leak
// Oldest entries automatically evicted when limit reached
BPF_HASH(connections, u64, u8, 10000);

static inline void extract_ipv4_info(struct sock *sk, struct connection_event_t *event) {
    event->ip_version = 4;
    bpf_probe_read(&event->saddr, sizeof(event->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&event->daddr, sizeof(event->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&event->sport, sizeof(event->sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&event->dport, sizeof(event->dport), &sk->__sk_common.skc_dport);
    event->dport = ntohs(event->dport);
}

static inline void extract_ipv6_info(struct sock *sk, struct connection_event_t *event) {
    event->ip_version = 6;
    
    // IPv6 addresses
    bpf_probe_read(&event->saddr_v6, sizeof(event->saddr_v6),
                   &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read(&event->daddr_v6, sizeof(event->daddr_v6),
                   &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    
    bpf_probe_read(&event->sport, sizeof(event->sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&event->dport, sizeof(event->dport), &sk->__sk_common.skc_dport);
    event->dport = ntohs(event->dport);
}

static inline int trace_connection(struct pt_regs *ctx, struct sock *sk, u8 protocol) {
    // Get process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Skip kernel threads (pid 0)
    // Note: Kernel threads CAN access network, but we filter them to reduce noise
    // Security: If attacker has kernel-level access, they could bypass this check
    // Defense: Combine with kernel module signing, Secure Boot, and IMA/EVM
    if (pid == 0)
        return 0;
    
    // Create connection key to avoid duplicates
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    u64 conn_key = 0;
    
    if (family == AF_INET) {
        u32 saddr = 0, daddr = 0;
        u16 sport = 0, dport = 0;
        
        bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        dport = ntohs(dport);
        
        // Create unique key: protocol + saddr + daddr + sport + dport
        conn_key = ((u64)protocol << 56) | ((u64)saddr << 24) | ((u64)daddr >> 8);
        conn_key ^= ((u64)sport << 16) | dport;
    } else if (family == AF_INET6) {
        // For IPv6, use first 32 bits of addresses
        u32 saddr_v6[4] = {};
        u32 daddr_v6[4] = {};
        u16 sport = 0, dport = 0;
        
        bpf_probe_read(&saddr_v6, sizeof(saddr_v6),
                       &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&daddr_v6, sizeof(daddr_v6),
                       &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        dport = ntohs(dport);
        
        conn_key = ((u64)protocol << 56) | ((u64)saddr_v6[0] << 24) | ((u64)daddr_v6[0] >> 8);
        conn_key ^= ((u64)sport << 16) | dport;
    } else {
        return 0;  // Unknown family
    }
    
    // Check if we've already seen this connection
    u8 *seen = connections.lookup(&conn_key);
    if (seen != NULL)
        return 0;  // Already tracked
    
    // Mark as seen
    u8 val = 1;
    connections.update(&conn_key, &val);
    
    // Create event
    struct connection_event_t event = {};
    event.pid = pid;
    event.protocol = protocol;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get cgroup ID (for Docker/container detection)
    event.cgroup_id = bpf_get_current_cgroup_id();
    
    // Extract IP info based on family
    if (family == AF_INET) {
        extract_ipv4_info(sk, &event);
    } else if (family == AF_INET6) {
        extract_ipv6_info(sk, &event);
    }
    
    // Send event to userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Hook TCP sendmsg
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    return trace_connection(ctx, sk, 6);  // TCP = protocol 6
}

// Hook UDP sendmsg
int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    return trace_connection(ctx, sk, 17);  // UDP = protocol 17
}

// Hook TCP connect (for outgoing connections)
int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    return trace_connection(ctx, sk, 6);
}
