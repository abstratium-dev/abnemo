# Advanced Packet Filtering Concepts

This document describes advanced, theoretical approaches to real-time packet filtering and monitoring in Linux. These are **not implemented** in Abnemo but are documented for educational purposes and future development.

## Identifying Process and Container Origins

### Can You Identify Which Process Sent a Packet?

**Yes, but it depends on the capture method:**

### Method 1: Using iptables Owner Match Module

The **iptables owner module** can match packets by the process that created them. This works at the **socket level** before packets leave the system.

#### Matching by Process ID (PID)

```bash
# Log packets from a specific PID
iptables -A OUTPUT -m owner --pid-owner 1234 -j LOG --log-prefix "PID-1234: "

# Block all traffic from a specific PID
iptables -A OUTPUT -m owner --pid-owner 1234 -j DROP
```

#### Matching by User ID (UID)

```bash
# Log packets from user 'www-data' (UID 33)
iptables -A OUTPUT -m owner --uid-owner 33 -j LOG --log-prefix "WWW-DATA: "

# Block traffic from a specific user
iptables -A OUTPUT -m owner --uid-owner 1000 -j DROP
```

#### Matching by Process Name (via cgroup)

```bash
# Match packets from processes in a specific cgroup
iptables -A OUTPUT -m cgroup --cgroup 0x100001 -j LOG --log-prefix "CGROUP: "
```

**Advantages:**
- ✅ Works at socket creation time
- ✅ Very reliable - kernel knows exactly which process owns the socket
- ✅ Low overhead
- ✅ Can match by PID, UID, GID, or cgroup

**Limitations:**
- ❌ Only works for locally-generated packets (not forwarded traffic)
- ❌ PID matching is tricky (PIDs change, short-lived processes)
- ❌ Doesn't work with Scapy (Scapy captures after iptables processing)

### Method 2: Using /proc/net for Socket Tracking

You can correlate packets with processes by examining `/proc/net/tcp` and `/proc/net/udp`.

#### How It Works

1. Capture packet with source port
2. Look up socket in `/proc/net/tcp` or `/proc/net/udp`
3. Find the inode number of the socket
4. Search `/proc/[pid]/fd/` for that inode
5. Identify the process

#### Python Implementation

```python
import os
import socket
import struct

def find_process_by_socket(local_ip, local_port, protocol='tcp'):
    """Find which process owns a socket"""
    
    # Convert IP to hex format used in /proc/net
    ip_hex = ''.join(['%02X' % int(x) for x in reversed(local_ip.split('.'))])
    port_hex = '%04X' % local_port
    socket_id = f"{ip_hex}:{port_hex}"
    
    # Read /proc/net/tcp or /proc/net/udp
    proc_file = f"/proc/net/{protocol}"
    
    try:
        with open(proc_file, 'r') as f:
            lines = f.readlines()[1:]  # Skip header
            
        for line in lines:
            parts = line.split()
            if parts[1] == socket_id:
                inode = parts[9]
                
                # Find process with this inode
                for pid in os.listdir('/proc'):
                    if not pid.isdigit():
                        continue
                    
                    fd_dir = f"/proc/{pid}/fd"
                    try:
                        for fd in os.listdir(fd_dir):
                            link = os.readlink(f"{fd_dir}/{fd}")
                            if f"socket:[{inode}]" in link:
                                # Found the process!
                                with open(f"/proc/{pid}/cmdline", 'r') as cmd:
                                    cmdline = cmd.read().replace('\x00', ' ')
                                
                                return {
                                    'pid': pid,
                                    'cmdline': cmdline,
                                    'inode': inode
                                }
                    except (PermissionError, FileNotFoundError):
                        continue
    except Exception as e:
        return None
    
    return None

# Example usage
process_info = find_process_by_socket('192.168.1.100', 54321, 'tcp')
if process_info:
    print(f"Process: {process_info['cmdline']} (PID: {process_info['pid']})")
```

**Advantages:**
- ✅ Works with any packet capture method
- ✅ Can identify process name, PID, and command line
- ✅ No kernel modifications needed

**Limitations:**
- ❌ Race condition - socket may close before lookup
- ❌ Requires root access to read /proc
- ❌ Performance overhead for each lookup
- ❌ Short-lived connections may be missed

### Method 3: Using eBPF for Process Tracking

Modern approach using **eBPF** to track socket creation and associate with processes.

#### How It Works

1. eBPF program hooks into socket creation (`sock_init`)
2. Records PID → Socket mapping in eBPF map
3. When packet is sent, lookup PID from socket
4. Export to userspace

#### Example with BCC (BPF Compiler Collection)

```python
from bcc import BPF

# eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Map to store socket -> PID
BPF_HASH(sock_pid, u64, u32);

// Hook socket creation
int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 sock_addr = (u64)sk;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    sock_pid.update(&sock_addr, &pid);
    return 0;
}

// Hook packet send
int trace_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u64 sock_addr = (u64)sk;
    u32 *pid = sock_pid.lookup(&sock_addr);
    
    if (pid) {
        bpf_trace_printk("PID %d sending packet\\n", *pid);
    }
    return 0;
}
"""

b = BPF(text=bpf_program)
b.attach_kprobe(event="tcp_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_sendmsg")

print("Tracing... Ctrl-C to stop")
b.trace_print()
```

**Advantages:**
- ✅ Very fast - runs in kernel
- ✅ Catches all processes
- ✅ Minimal overhead
- ✅ Can track all socket operations

**Limitations:**
- ❌ Requires eBPF support (Linux 4.x+)
- ❌ Complex to program
- ❌ Requires root access

### Method 4: Using ss (Socket Statistics) Command

The `ss` command can show which processes own sockets.

```bash
# Show all TCP connections with process info
ss -tnp

# Show specific connection
ss -tnp | grep :443

# Example output:
# ESTAB  0  0  192.168.1.100:54321  1.2.3.4:443  users:(("firefox",pid=1234,fd=42))
```

**Parse ss output in Python:**

```python
import subprocess
import re

def get_process_for_connection(local_ip, local_port):
    """Use ss command to find process"""
    try:
        result = subprocess.run(
            ['ss', '-tnp'],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.split('\n'):
            if f"{local_ip}:{local_port}" in line:
                # Parse: users:(("process",pid=1234,fd=42))
                match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if match:
                    return {
                        'process': match.group(1),
                        'pid': match.group(2)
                    }
    except Exception as e:
        return None
    
    return None
```

**Advantages:**
- ✅ Simple to use
- ✅ Human-readable output
- ✅ Shows process name and PID

**Limitations:**
- ❌ Requires subprocess call (slow)
- ❌ Only shows active connections
- ❌ Requires root for full info

## Identifying Docker Containers

### Method 1: Using Docker Network Namespaces

Each Docker container runs in its own network namespace. You can identify containers by their namespace.

#### Find Container by Network Namespace

```bash
# Get container's network namespace
docker inspect -f '{{.State.Pid}}' container_name
nsenter -t <PID> -n ip addr

# Or use docker network inspect
docker network inspect bridge
```

#### Python Implementation

```python
import subprocess
import json

def get_container_for_ip(ip_address):
    """Find which Docker container has a specific IP"""
    try:
        # Get all containers
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.ID}}'],
            capture_output=True,
            text=True
        )
        
        for container_id in result.stdout.strip().split('\n'):
            # Inspect container
            inspect = subprocess.run(
                ['docker', 'inspect', container_id],
                capture_output=True,
                text=True
            )
            
            data = json.loads(inspect.stdout)[0]
            networks = data['NetworkSettings']['Networks']
            
            for network_name, network_info in networks.items():
                if network_info['IPAddress'] == ip_address:
                    return {
                        'container_id': container_id,
                        'name': data['Name'].strip('/'),
                        'image': data['Config']['Image'],
                        'ip': ip_address
                    }
    except Exception as e:
        return None
    
    return None

# Example
container = get_container_for_ip('172.17.0.2')
if container:
    print(f"Container: {container['name']} ({container['image']})")
```

### Method 2: Using iptables with Docker Labels

Docker automatically creates iptables rules with container metadata.

```bash
# View Docker's iptables rules
iptables -t nat -L -n -v

# Docker adds comments with container IDs
iptables -L DOCKER -n -v --line-numbers
```

### Method 3: Using cgroups

Docker uses cgroups to isolate containers. You can match processes to containers via cgroups.

```bash
# Find cgroup for a PID
cat /proc/<PID>/cgroup

# Example output:
# 12:pids:/docker/abc123def456...
# The hash is the container ID
```

#### Python Implementation

```python
def get_container_from_pid(pid):
    """Get Docker container ID from process PID"""
    try:
        with open(f'/proc/{pid}/cgroup', 'r') as f:
            for line in f:
                if 'docker' in line:
                    # Extract container ID from cgroup path
                    # Format: 12:pids:/docker/CONTAINER_ID
                    parts = line.strip().split('/')
                    if len(parts) >= 3 and parts[-2] == 'docker':
                        container_id = parts[-1]
                        return container_id[:12]  # Short ID
    except Exception as e:
        return None
    
    return None
```

### Method 4: Monitoring Docker Events

Docker provides an event stream that shows container activity.

```python
import docker

client = docker.from_env()

# Monitor container network events
for event in client.events(decode=True):
    if event['Type'] == 'network':
        print(f"Container {event['Actor']['ID'][:12]}: {event['Action']}")
        print(f"  Network: {event['Actor']['Attributes']['name']}")
```

## Practical Integration Example

Here's how you could extend Abnemo to identify processes:

```python
class ProcessTracker:
    def __init__(self):
        self.socket_cache = {}
    
    def identify_process(self, src_ip, src_port, protocol='tcp'):
        """Identify process that sent packet"""
        cache_key = f"{src_ip}:{src_port}:{protocol}"
        
        # Check cache first
        if cache_key in self.socket_cache:
            return self.socket_cache[cache_key]
        
        # Method 1: Try /proc/net lookup
        process_info = self.lookup_proc_net(src_ip, src_port, protocol)
        
        if process_info:
            # Check if it's a Docker container
            container_info = self.get_container_from_pid(process_info['pid'])
            if container_info:
                process_info['container'] = container_info
            
            self.socket_cache[cache_key] = process_info
            return process_info
        
        return None
    
    def lookup_proc_net(self, ip, port, protocol):
        # Implementation from Method 2 above
        pass
    
    def get_container_from_pid(self, pid):
        # Implementation from cgroups method above
        pass
```

## Summary: Which Method to Use?

| Method | Speed | Accuracy | Docker Support | Complexity |
|--------|-------|----------|----------------|------------|
| iptables owner | Fast | High | Via cgroup | Low |
| /proc/net lookup | Medium | Medium | Via cgroup | Medium |
| eBPF | Very Fast | High | Via cgroup | High |
| ss command | Slow | High | Via cgroup | Low |
| Docker API | Slow | High | Yes | Low |

**Recommendation for Abnemo:**
- Use **/proc/net lookup** for general process identification
- Use **cgroup parsing** to identify Docker containers
- Cache results to minimize overhead
- Accept that short-lived connections may be missed

**Note:** Abnemo currently uses Scapy which captures packets **after** they leave the network stack, so process information is not directly available. To add process tracking, Abnemo would need to:
1. Capture the source port from each packet
2. Look up the socket in /proc/net
3. Find the owning process
4. Check if process is in a Docker container (via cgroups)

This would add overhead but is feasible for moderate traffic volumes.

## Real-time Packet Filtering with NFQUEUE

### Overview

Linux provides the ability to send packets to userspace for inspection and decision-making using **NFQUEUE** (Netfilter Queue). This allows a program to act as a real-time firewall.

### How It Works

```
Packet → iptables → NFQUEUE → Userspace Program → Verdict (ACCEPT/DROP) → Kernel
```

1. **iptables rule** sends packets to a queue number
2. **Kernel** holds the packet in memory
3. **Userspace program** receives packet via `libnetfilter_queue`
4. **Program inspects** packet and makes decision
5. **Program returns verdict** (ACCEPT, DROP, or REPEAT)
6. **Kernel** applies the verdict

### Implementation Example

```bash
# iptables rule to send outgoing packets to queue 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0
```

```python
# Python implementation using NetfilterQueue
from netfilterqueue import NetfilterQueue
import socket

def packet_callback(packet):
    # Get packet data
    ip_header = packet.get_payload()
    
    # Extract destination IP
    dst_ip = socket.inet_ntoa(ip_header[16:20])
    
    # Make decision
    if is_allowed(dst_ip):
        packet.accept()  # Allow packet through
    else:
        packet.drop()    # Block packet
        notify_admin(f"Blocked packet to {dst_ip}")

nfq = NetfilterQueue()
nfq.bind(0, packet_callback)  # Bind to queue 0
nfq.run()
```

### Performance Considerations

**Critical limitations:**
- ⚠️ **Every packet waits** for userspace decision
- ⚠️ **Adds 1-10ms latency** per packet minimum
- ⚠️ **CPU intensive** - Python processing for every packet
- ⚠️ **Single point of failure** - if program crashes, packets are dropped
- ⚠️ **Bandwidth limited** - ~100-500 Mbps maximum throughput

**When to use:**
- Low-bandwidth connections
- Security-critical applications
- Deep packet inspection requirements
- Research/development environments

**When NOT to use:**
- High-bandwidth connections (>100 Mbps)
- Production servers with strict latency requirements
- General internet browsing

## Packet Drop Notifications

### Method 1: iptables LOG Target

The simplest way to get notifications when packets are dropped.

#### Setup

```bash
# Log dropped packets before dropping them
iptables -A OUTPUT -d 192.168.1.100 -j LOG --log-prefix "DROPPED: " --log-level 4
iptables -A OUTPUT -d 192.168.1.100 -j DROP
```

#### Reading Logs

Dropped packets appear in `/var/log/kern.log` or `/var/log/syslog`:

```
Mar 1 12:00:00 hostname kernel: DROPPED: IN= OUT=eth0 SRC=10.0.0.5 DST=192.168.1.100 PROTO=TCP SPT=54321 DPT=80
```

#### Monitoring with Python

```python
import re
import subprocess

def monitor_iptables_logs():
    """Monitor kernel logs for dropped packets"""
    proc = subprocess.Popen(
        ['tail', '-F', '/var/log/kern.log'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    for line in proc.stdout:
        line = line.decode('utf-8')
        if 'DROPPED:' in line:
            # Parse the log line
            match = re.search(r'DST=(\S+)', line)
            if match:
                dst_ip = match.group(1)
                notify_admin(f"Packet dropped to {dst_ip}")
                
                # Extract which rule matched
                # (rule info is in the log prefix)
                print(f"Alert: Packet to {dst_ip} was blocked")
```

**Advantages:**
- ✅ No performance impact on packet flow
- ✅ Kernel handles logging efficiently
- ✅ Can log both dropped and accepted packets
- ✅ Includes full packet metadata

**Disadvantages:**
- ❌ Logs can grow very large
- ❌ Requires parsing text logs
- ❌ Slight delay in notification (log buffer)

### Method 2: ULOG/NFLOG Target

More efficient than LOG target, designed for userspace logging.

#### Setup

```bash
# Send dropped packet info to NFLOG group 1
iptables -A OUTPUT -d 192.168.1.100 -j NFLOG --nflog-group 1 --nflog-prefix "BLOCKED"
iptables -A OUTPUT -d 192.168.1.100 -j DROP
```

#### Python Implementation

```python
from nflog import NFLOG
import socket

def packet_handler(payload):
    """Called for each logged packet"""
    # Extract packet info
    data = payload.get_payload()
    timestamp = payload.get_timestamp()
    
    # Parse IP header
    dst_ip = socket.inet_ntoa(data[16:20])
    
    # Get the rule that matched (from prefix)
    prefix = payload.get_prefix()
    
    # Notify administrator
    notify_admin({
        'action': 'BLOCKED',
        'destination': dst_ip,
        'timestamp': timestamp,
        'rule': prefix
    })

# Create NFLOG handler for group 1
nflog = NFLOG()
nflog.bind(1, packet_handler)
nflog.run()
```

**Advantages:**
- ✅ More efficient than text logs
- ✅ Structured data (not text parsing)
- ✅ Can handle high packet rates
- ✅ Real-time notifications

**Disadvantages:**
- ❌ Requires additional library (`python-nflog`)
- ❌ More complex setup

### Method 3: eBPF with Notifications

Modern approach using eBPF (Extended Berkeley Packet Filter).

#### How It Works

1. **eBPF program** runs in kernel space
2. **Filters packets** at line rate (very fast)
3. **Writes events** to a ring buffer
4. **Userspace program** reads events from buffer
5. **No packet delay** - decisions made in kernel

#### Example Concept

```c
// eBPF program (runs in kernel)
int filter_packet(struct __sk_buff *skb) {
    // Extract IP header
    struct iphdr ip;
    bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip));
    
    // Check against whitelist
    if (!is_allowed(ip.daddr)) {
        // Log the drop event
        struct drop_event evt = {
            .dst_ip = ip.daddr,
            .timestamp = bpf_ktime_get_ns()
        };
        bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
        
        return TC_ACT_SHOT;  // Drop packet
    }
    
    return TC_ACT_OK;  // Accept packet
}
```

```python
# Userspace program reads events
from bcc import BPF

b = BPF(src_file="filter.c")
b.attach_xdp("eth0", b.load_func("filter_packet", BPF.XDP))

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    notify_admin(f"Dropped packet to {event.dst_ip}")

b["events"].open_ring_buffer(handle_event)
while True:
    b.ring_buffer_poll()
```

**Advantages:**
- ✅ **Extremely fast** - runs in kernel
- ✅ **No packet delay** - decisions at wire speed
- ✅ **Efficient notifications** - ring buffer
- ✅ **Modern approach** - actively developed

**Disadvantages:**
- ❌ **Complex** - requires C programming
- ❌ **Limited functionality** - can't do arbitrary operations
- ❌ **Kernel version** - requires Linux 4.x+

## Monitoring Accepted Packets

### Logging Accepted Packets

You can log accepted packets the same way as dropped packets:

```bash
# Log all accepted outgoing packets
iptables -A OUTPUT -j LOG --log-prefix "ACCEPTED: " --log-level 6
iptables -A OUTPUT -j ACCEPT

# Or log specific accepted traffic
iptables -A OUTPUT -d 8.8.8.8 -j LOG --log-prefix "DNS-ACCEPTED: "
iptables -A OUTPUT -d 8.8.8.8 -j ACCEPT
```

### Selective Logging

**Problem**: Logging all accepted packets creates massive logs.

**Solution**: Only log interesting traffic:

```bash
# Log only first packet of new connections
iptables -A OUTPUT -m state --state NEW -j LOG --log-prefix "NEW-CONN: "

# Log only high-bandwidth connections
iptables -A OUTPUT -m connbytes --connbytes 10000000: --connbytes-dir both \
    -j LOG --log-prefix "HIGH-BW: "

# Log only specific ports
iptables -A OUTPUT -p tcp --dport 22 -j LOG --log-prefix "SSH: "
```

## Getting Rule Information in Notifications

### Including Rule Context

When logging, include information about which rule matched:

```bash
# Use descriptive prefixes
iptables -A OUTPUT -d 192.168.1.0/24 -j LOG --log-prefix "BLOCK-INTERNAL: "
iptables -A OUTPUT -d 192.168.1.0/24 -j DROP

iptables -A OUTPUT -p tcp --dport 25 -j LOG --log-prefix "BLOCK-SMTP: "
iptables -A OUTPUT -p tcp --dport 25 -j DROP
```

### Parsing Rule Information

```python
import re

def parse_iptables_log(log_line):
    """Extract detailed information from iptables log"""
    info = {}
    
    # Extract prefix (rule identifier)
    prefix_match = re.search(r'kernel: (\S+):', log_line)
    if prefix_match:
        info['rule'] = prefix_match.group(1)
    
    # Extract source and destination
    src_match = re.search(r'SRC=(\S+)', log_line)
    dst_match = re.search(r'DST=(\S+)', log_line)
    
    if src_match and dst_match:
        info['src'] = src_match.group(1)
        info['dst'] = dst_match.group(1)
    
    # Extract protocol and ports
    proto_match = re.search(r'PROTO=(\S+)', log_line)
    sport_match = re.search(r'SPT=(\d+)', log_line)
    dport_match = re.search(r'DPT=(\d+)', log_line)
    
    if proto_match:
        info['protocol'] = proto_match.group(1)
    if sport_match:
        info['src_port'] = sport_match.group(1)
    if dport_match:
        info['dst_port'] = dport_match.group(1)
    
    return info

# Example usage
log = "Mar 1 12:00:00 host kernel: BLOCK-SMTP: IN= OUT=eth0 SRC=10.0.0.5 DST=1.2.3.4 PROTO=TCP SPT=54321 DPT=25"
info = parse_iptables_log(log)
print(f"Rule: {info['rule']}")  # BLOCK-SMTP
print(f"Blocked: {info['src']}:{info['src_port']} -> {info['dst']}:{info['dst_port']}")
```

## Administrator Notifications

### Real-time Notification System

```python
import smtplib
import requests
from datetime import datetime

class PacketNotifier:
    def __init__(self):
        self.alert_threshold = 10  # Alert after 10 drops
        self.drop_count = {}
    
    def notify_drop(self, packet_info):
        """Notify admin of dropped packet"""
        dst = packet_info['dst']
        rule = packet_info['rule']
        
        # Count drops per destination
        self.drop_count[dst] = self.drop_count.get(dst, 0) + 1
        
        # Alert if threshold exceeded
        if self.drop_count[dst] >= self.alert_threshold:
            self.send_alert(
                f"High drop rate to {dst}",
                f"Rule: {rule}\nDrops: {self.drop_count[dst]}"
            )
            self.drop_count[dst] = 0  # Reset counter
    
    def notify_accept(self, packet_info):
        """Notify admin of accepted packet (if interesting)"""
        # Only notify for specific cases
        if packet_info.get('dst_port') == 22:  # SSH
            self.send_alert(
                "SSH Connection Established",
                f"To: {packet_info['dst']}"
            )
    
    def send_alert(self, subject, message):
        """Send alert via multiple channels"""
        # Email
        self.send_email(subject, message)
        
        # Slack/Discord webhook
        self.send_webhook(subject, message)
        
        # Syslog
        self.send_syslog(subject, message)
    
    def send_email(self, subject, message):
        """Send email notification"""
        # Implementation here
        pass
    
    def send_webhook(self, subject, message):
        """Send to Slack/Discord"""
        webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        requests.post(webhook_url, json={
            'text': f"*{subject}*\n{message}"
        })
    
    def send_syslog(self, subject, message):
        """Log to syslog"""
        import syslog
        syslog.syslog(syslog.LOG_WARNING, f"{subject}: {message}")
```

## Practical Recommendations

### For Production Use

1. **Use iptables LOG/NFLOG** for notifications
   - Efficient and reliable
   - No impact on packet flow
   - Well-tested and stable

2. **Log selectively**
   - Only log NEW connections, not every packet
   - Use rate limiting: `--limit 10/min`
   - Focus on blocked traffic

3. **Aggregate notifications**
   - Don't alert on every packet
   - Alert on patterns (e.g., 10 drops in 1 minute)
   - Use time windows

4. **Monitor log size**
   - Rotate logs frequently
   - Use `logrotate` for automatic management
   - Consider centralized logging (syslog server)

### Example Production Setup

```bash
# Log new blocked connections (rate limited)
iptables -A OUTPUT -m state --state NEW -m limit --limit 10/min \
    -j LOG --log-prefix "BLOCKED-NEW: " --log-level 4

# Apply block rules
iptables -A OUTPUT -d 192.168.1.100 -j DROP

# Log accepted SSH connections
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW \
    -j LOG --log-prefix "SSH-OUT: "
```

## Conclusion

**For Abnemo's use case**, the current approach (passive monitoring + post-analysis) is optimal. Real-time filtering with notifications would be appropriate for:

- **Intrusion Detection Systems (IDS)**
- **Security appliances**
- **Research environments**
- **Low-bandwidth, high-security networks**

For general network monitoring and blocking, the two-step approach (monitor → analyze → block) provides the best balance of:
- Performance
- Reliability
- Ease of use
- Safety
