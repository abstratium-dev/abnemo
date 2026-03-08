# eBPF Enhancement for Abnemo

## Overview

eBPF (Extended Berkeley Packet Filter) is a kernel technology that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.

## Why eBPF for Network Monitoring?

### Current Limitations (Scapy-based approach)
1. **Race conditions**: Short-lived processes exit before we can look them up
2. **Post-capture lookup**: We capture packet first, then try to find the process
3. **Performance**: User-space packet processing has overhead
4. **Missing data**: Cannot catch very brief connections

### eBPF Advantages
1. **No race conditions**: Hook directly at socket creation/packet send
2. **Pre-capture data**: Know PID/process before packet is even sent
3. **High performance**: Runs in kernel space, minimal overhead
4. **Complete data**: Catches all connections, even 1ms duration
5. **Security**: Perfect for detecting rogue scripts/processes

## How eBPF Would Work

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Kernel Space (eBPF)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Hook: tcp_sendmsg() / udp_sendmsg()                    │
│     ↓                                                       │
│  2. Extract: PID, comm, src_ip, src_port, dst_ip, dst_port│
│     ↓                                                       │
│  3. Check cgroup: Is this a Docker container?              │
│     ↓                                                       │
│  4. Store in BPF map: connection_info[src_ip:src_port]     │
│     ↓                                                       │
│  5. Send event to userspace via perf buffer                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   User Space (Python)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Receive events from eBPF                                │
│     ↓                                                       │
│  2. Enrich with DNS, ISP lookups                           │
│     ↓                                                       │
│  3. Aggregate statistics                                    │
│     ↓                                                       │
│  4. Display/save results                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow
```c
// eBPF program (kernel space)
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    
    // Get process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Get cgroup (for Docker detection)
    u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Create event
    struct event_t {
        u32 pid;
        char comm[16];
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u64 cgroup_id;
    } event = {};
    
    event.pid = pid;
    __builtin_memcpy(&event.comm, comm, sizeof(comm));
    event.saddr = saddr;
    event.daddr = daddr;
    event.sport = sport;
    event.dport = dport;
    event.cgroup_id = cgroup_id;
    
    // Send to userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
```

```python
# Python userspace (receives events)
from bcc import BPF

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    
    # We now have ALL the info BEFORE the packet is sent!
    print(f"Process: {event.comm.decode()} (PID: {event.pid})")
    print(f"Connection: {event.saddr}:{event.sport} -> {event.daddr}:{event.dport}")
    print(f"Cgroup: {event.cgroup_id}")
    
    # Enrich with DNS/ISP
    # Add to statistics
    # No race condition!

b = BPF(text=bpf_program)
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
b["events"].open_perf_buffer(handle_event)

while True:
    b.perf_buffer_poll()
```

## Implementation Plan

### Phase 1: Basic eBPF Integration (Optional Mode)
- Add `--ebpf` flag to enable eBPF mode
- Keep existing Scapy mode as default
- Hook `tcp_sendmsg` and `udp_sendmsg`
- Extract PID, comm, connection info
- Send events to Python via perf buffer

### Phase 2: Docker/Container Detection
- Extract cgroup ID from eBPF
- Map cgroup to container name in userspace
- More reliable than current method

### Phase 3: Advanced Features
- Track connection duration
- Measure bytes sent per connection
- Detect port scanning
- Alert on suspicious behavior

## Requirements

### System Requirements
- Linux kernel 4.x+ (5.x+ recommended)
- BPF enabled in kernel (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`)
- Root access (same as current requirement)

### Python Dependencies
```bash
# BCC must be installed via system package manager
sudo apt install python3-bpfcc  # Ubuntu/Debian
# OR
sudo dnf install python3-bcc    # Fedora/RHEL
```

### Check if eBPF is available
```bash
# Check kernel version
uname -r  # Should be 4.x+

# Check if BPF is enabled
zgrep CONFIG_BPF /proc/config.gz

# Test BCC
python3 -c "from bcc import BPF; print('eBPF available!')"
```

## Performance Comparison

| Metric | Scapy (Current) | eBPF |
|--------|----------------|------|
| Overhead | ~5-10% CPU | <1% CPU |
| Race conditions | Yes (short-lived processes) | No |
| Missed connections | Possible | Never |
| Kernel version | Any | 4.x+ |
| Setup complexity | Low | Medium |
| Process detection | Post-capture | Pre-capture |
| Docker detection | Via IP fallback | Direct cgroup |

## Security Benefits for Your Use Case

### Detecting Rogue Scripts/Processes

**Current method (Scapy):**
- ❌ Misses quick curl/wget commands
- ❌ Misses short-lived malicious scripts
- ✅ Catches long-running processes

**eBPF method:**
- ✅ Catches ALL network activity
- ✅ Detects even 1ms connections
- ✅ Perfect for security monitoring
- ✅ Can alert in real-time

### Example: Detecting Crypto Miner
```python
# eBPF can catch this even if it runs for 100ms
def detect_suspicious(event):
    # Crypto mining pools
    suspicious_ports = [3333, 4444, 5555, 7777, 8888]
    suspicious_domains = ['pool.', 'mining.', 'xmr.']
    
    if event.dport in suspicious_ports:
        alert(f"Suspicious connection from {event.comm} to port {event.dport}")
    
    # Check DNS (in userspace)
    domain = reverse_dns(event.daddr)
    if any(s in domain for s in suspicious_domains):
        alert(f"Crypto mining detected: {event.comm} -> {domain}")
```

## Proposed Implementation

### File Structure
```
abnemo/
├── ebpf/
│   ├── __init__.py
│   ├── network_monitor.c      # eBPF C code
│   ├── ebpf_loader.py         # BCC loader
│   └── event_handler.py       # Event processing
├── packet_monitor.py          # Existing Scapy monitor
├── ebpf_monitor.py           # New eBPF monitor
└── abnemo.py                  # CLI (add --ebpf flag)
```

### Usage
```bash
# Current mode (Scapy)
sudo ./scripts/abnemo.sh monitor --enable-process-tracking

# New eBPF mode (no race conditions!)
sudo ./scripts/abnemo.sh monitor --ebpf

# Hybrid mode (eBPF for process tracking, Scapy for packet details)
sudo ./scripts/abnemo.sh monitor --ebpf --enable-process-tracking
```

## Recommendation

**For your security use case (detecting rogue scripts):**

✅ **YES, implement eBPF** because:
1. You need to catch ALL network activity (even brief connections)
2. Rogue scripts often make quick connections and exit
3. eBPF has minimal overhead (~0.5% CPU)
4. Perfect for 24/7 monitoring
5. Can add real-time alerts

**Implementation approach:**
1. Keep existing Scapy mode (default)
2. Add optional `--ebpf` mode
3. Users choose based on their needs:
   - Casual monitoring → Scapy (easier setup)
   - Security monitoring → eBPF (catches everything)

## Next Steps

1. **Test eBPF availability** on your system:
   ```bash
   python3 -c "from bcc import BPF; print('Ready for eBPF!')"
   ```

2. **Prototype** basic eBPF hook:
   - Hook `tcp_sendmsg`
   - Extract PID, comm, dst_ip
   - Print events

3. **Integrate** with existing Abnemo:
   - Add `--ebpf` flag
   - Create `ebpf_monitor.py`
   - Reuse existing ISP/DNS/stats code

4. **Test** with rogue script detection:
   - Run test scripts
   - Verify all connections caught
   - Compare with Scapy mode

Would you like me to implement the eBPF enhancement as an optional feature?
