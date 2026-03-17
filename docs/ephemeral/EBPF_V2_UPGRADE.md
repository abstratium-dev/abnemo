# eBPF V2 Upgrade - Accurate Byte Counting

## Problem

The original eBPF implementation (V1) tracked **connections**, not **packets**:
- Only fired once per unique connection (src_ip:src_port → dst_ip:dst_port)
- All subsequent packets on the same connection were ignored
- Used a fixed 64-byte estimate per connection
- Could not accurately measure data transfer volumes

**Example:**
- Tcpdump: 288 packets, 64 KB total
- Abnemo V1: 26 connections, 1.6 KB estimated (only 2.6% accuracy)

## Solution

eBPF V2 tracks **every packet** and counts **actual bytes**:
- Hooks `tcp_sendmsg` and `udp_sendmsg` to capture outgoing data
- Hooks `tcp_recvmsg` and `udp_recvmsg` to capture incoming data (for bidirectional mode)
- Reads the actual `size` parameter from the kernel function
- Reports real byte counts to userspace

## Changes Made

### 1. New eBPF Program (`ebpf/network_monitor_v2.c`)
- Removed connection deduplication logic
- Added `bytes` field to event structure
- Captures actual size parameter from sendmsg/recvmsg functions
- Fires on every packet transmission, not just new connections

### 2. Updated eBPF Loader (`ebpf/ebpf_loader.py`)
- Added `use_v2` parameter to choose between V1 and V2
- V2 attaches to both send and recv hooks
- Extracts `bytes` field from V2 events

### 3. Updated Monitor (`src/ebpf_monitor.py`)
- Enabled V2 by default: `EBPFLoader(use_v2=True)`
- Uses actual byte counts instead of estimates
- Verbose logging shows real packet sizes

## Performance Considerations

**V2 generates more events:**
- V1: ~26 events per minute (one per connection)
- V2: ~288 events per minute (one per packet)
- ~11x more events, but still very efficient

**Why this is acceptable:**
- eBPF is extremely fast (runs in kernel space)
- Perf buffers are optimized for high throughput
- Modern systems handle thousands of events per second easily
- The accuracy gain is worth the minimal overhead

## Verification

Run the verification script to compare:
```bash
sudo python3 verification.py
```

**Expected results with V2:**
- Abnemo should capture 80-100% of tcpdump's byte count
- Packet counts should be similar (within 10-20%)
- Both tools should see the same destination IPs

## Rollback

To revert to V1 (connection-based tracking):
```python
# In src/ebpf_monitor.py, line 71:
self.ebpf_loader = EBPFLoader(use_v2=False)  # Use V1
```

## Technical Details

### V1 Approach (Connection-based)
```c
// Check if we've already seen this connection
u8 *seen = connections.lookup(&conn_key);
if (seen != NULL)
    return 0;  // Skip duplicate
```

### V2 Approach (Packet-based)
```c
// Hook sendmsg with size parameter
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, 
                      struct msghdr *msg, size_t size) {
    event.bytes = size;  // Actual bytes being sent
    events.perf_submit(ctx, &event, sizeof(event));
}
```

## Future Enhancements

1. **Kernel-side aggregation**: Accumulate bytes in eBPF maps, report periodically
2. **Sampling**: Only report every Nth packet for high-volume connections
3. **Per-process limits**: Track which processes use the most bandwidth
4. **Real-time alerts**: Trigger on unusual traffic patterns

## References

- [BCC Documentation](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- [eBPF Performance](https://www.brendangregg.com/ebpf.html)
- [Kernel Network Stack](https://www.kernel.org/doc/html/latest/networking/index.html)
