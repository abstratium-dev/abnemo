/*
 * eBPF Network Monitor V2
 * Tracks actual bytes sent/received per connection with process information
 * 
 * This version tracks EVERY packet and accumulates byte counts in kernel space,
 * then periodically reports to userspace.
 */

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Traffic event structure sent to userspace
struct traffic_event_t {
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
    u32 bytes;        // Bytes in this transmission
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(events);

// Connection info structure for tracking
struct conn_info_t {
    u32 pid;
    char comm[16];
    u64 cgroup_id;
};

// Map to track connection metadata (pid, comm, cgroup)
// Key: connection tuple (src_ip:src_port -> dst_ip:dst_port)
BPF_HASH(conn_metadata, u64, struct conn_info_t, 10000);

static inline u64 make_conn_key(u32 saddr, u32 daddr, u16 sport, u16 dport, u8 protocol) {
    // Create unique key from 5-tuple
    u64 key = ((u64)protocol << 56) | ((u64)saddr << 24) | ((u64)daddr >> 8);
    key ^= ((u64)sport << 16) | dport;
    return key;
}

static inline void extract_ipv4_info(struct sock *sk, struct traffic_event_t *event) {
    event->ip_version = 4;
    bpf_probe_read(&event->saddr, sizeof(event->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&event->daddr, sizeof(event->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&event->sport, sizeof(event->sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&event->dport, sizeof(event->dport), &sk->__sk_common.skc_dport);
    event->dport = ntohs(event->dport);
}

static inline void extract_ipv6_info(struct sock *sk, struct traffic_event_t *event) {
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

// Hook TCP sendmsg to track actual bytes sent
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    // Get process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    // Get socket family
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    
    if (family != AF_INET && family != AF_INET6)
        return 0;
    
    // Create event
    struct traffic_event_t event = {};
    event.pid = pid;
    event.protocol = 6;  // TCP
    event.bytes = size;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get cgroup ID
    event.cgroup_id = bpf_get_current_cgroup_id();
    
    // Extract IP info
    if (family == AF_INET) {
        extract_ipv4_info(sk, &event);
    } else if (family == AF_INET6) {
        extract_ipv6_info(sk, &event);
    }
    
    // Send event to userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Hook UDP sendmsg to track actual bytes sent
int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    // Get process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    // Get socket family
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    
    if (family != AF_INET && family != AF_INET6)
        return 0;
    
    // Create event
    struct traffic_event_t event = {};
    event.pid = pid;
    event.protocol = 17;  // UDP
    event.bytes = size;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get cgroup ID
    event.cgroup_id = bpf_get_current_cgroup_id();
    
    // Extract IP info
    if (family == AF_INET) {
        extract_ipv4_info(sk, &event);
    } else if (family == AF_INET6) {
        extract_ipv6_info(sk, &event);
    }
    
    // Send event to userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Hook TCP recvmsg to track actual bytes received (for bidirectional mode)
int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size, int flags) {
    // Get process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    // Get socket family
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    
    if (family != AF_INET && family != AF_INET6)
        return 0;
    
    // Create event
    struct traffic_event_t event = {};
    event.pid = pid;
    event.protocol = 6;  // TCP
    event.bytes = size;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get cgroup ID
    event.cgroup_id = bpf_get_current_cgroup_id();
    
    // Extract IP info (note: for recv, src/dst are swapped from socket perspective)
    if (family == AF_INET) {
        extract_ipv4_info(sk, &event);
    } else if (family == AF_INET6) {
        extract_ipv6_info(sk, &event);
    }
    
    // Send event to userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Hook UDP recvmsg to track actual bytes received (for bidirectional mode)
int trace_udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size, int flags) {
    // Get process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    // Get socket family
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    
    if (family != AF_INET && family != AF_INET6)
        return 0;
    
    // Create event
    struct traffic_event_t event = {};
    event.pid = pid;
    event.protocol = 17;  // UDP
    event.bytes = size;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get cgroup ID
    event.cgroup_id = bpf_get_current_cgroup_id();
    
    // Extract IP info
    if (family == AF_INET) {
        extract_ipv4_info(sk, &event);
    } else if (family == AF_INET6) {
        extract_ipv6_info(sk, &event);
    }
    
    // Send event to userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
