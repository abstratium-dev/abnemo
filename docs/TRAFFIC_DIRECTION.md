# Traffic Direction Modes

Abnemo supports four traffic direction modes to control what network traffic is monitored and logged.

## Modes

### 1. `outgoing` (Default)
**Tracks only outgoing traffic initiated by your system.**

- **What it captures**: Packets sent from your local machine to remote servers
- **Use case**: Monitor what your applications are connecting to
- **Examples**:
  - Browser requests to websites
  - API calls from applications
  - Database connections
  - Email sending
  - SSH connections to remote servers

**Does NOT capture**:
- Responses from servers (incoming data)
- Unsolicited incoming connections

**Pros**:
- Minimal data volume
- Clear attribution to local processes
- Good for identifying what your system is connecting to

**Cons**:
- Doesn't show actual data transfer volume (responses are larger)
- Can't detect incoming attacks or port scans

---

### 2. `incoming`
**Tracks only unsolicited incoming traffic (server mode).**

- **What it captures**: Only incoming packets that are NOT responses to your outgoing connections
- **Use case**: Monitor server traffic (SSH, web, mail servers)
- **Examples**:
  - SSH login attempts from the internet
  - HTTP requests to your web server
  - Email delivery to your mail server
  - Port scans and attack attempts
  - Any connection initiated FROM the internet TO your server

**Does NOT capture**:
- Outgoing traffic (your requests)
- Responses to your outgoing connections (e.g., YouTube video data)

**How it works**:
- Tracks which remote IPs you've initiated connections to
- Only counts incoming traffic from IPs you HAVEN'T connected to
- Filters out responses to your own requests

**Pros**:
- Clean view of server traffic only
- Identifies who is connecting to your services
- Good for security monitoring
- No noise from your own browsing/downloads

**Cons**:
- Doesn't show your own internet usage
- Can't attribute to processes (no local process initiated the connection)
- Requires running services (SSH, web server, etc.)

---

### 3. `bidirectional`
**Tracks outgoing traffic AND responses to those connections.**

- **What it captures**: 
  - All outgoing packets (local → remote)
  - Incoming packets that are responses to established outgoing connections
- **Use case**: Measure actual bandwidth usage for your applications
- **Examples**:
  - YouTube video download (request + video data)
  - File downloads
  - API responses
  - Database query results
  - WebSocket bidirectional communication

**Does NOT capture**:
- Unsolicited incoming connections (e.g., SSH login attempts, port scans)

**How it works**:
- Tracks which remote IPs you've initiated connections to
- Only counts incoming traffic from those IPs
- Filters out unsolicited incoming traffic

**Pros**:
- Accurate bandwidth measurement
- Still filters out noise from port scans
- Process attribution works for outgoing (inherited for responses)

**Cons**:
- Slightly more complex logic
- Can't detect incoming server traffic

---

### 4. `all`
**Tracks ALL traffic, including unsolicited incoming connections.**

- **What it captures**: Everything
  - Outgoing traffic
  - Responses to outgoing traffic
  - Unsolicited incoming connections (SSH servers, web servers, etc.)
  - Port scans and attack attempts
- **Use case**: 
  - Running servers (SSH, web, mail, etc.)
  - Security monitoring
  - Complete network visibility
- **Examples**:
  - SSH login attempts from the internet
  - Web server requests
  - Email server connections
  - Port scans
  - DDoS attacks

**Pros**:
- Complete network visibility
- Can detect attacks and unauthorized access attempts
- Essential for servers

**Cons**:
- Higher data volume
- Can't attribute incoming connections to processes (no local process initiated them)
- May include noise from port scans

---

## Usage Examples

### Default: Outgoing Only
```bash
# Monitor only what your system connects to
sudo ./abnemo.sh monitor --web

# Equivalent to
sudo python3 abnemo.py monitor --web --traffic-direction outgoing
```

### Bidirectional: Measure Actual Bandwidth
```bash
# Track outgoing requests AND their responses (e.g., YouTube video data)
sudo python3 abnemo.py monitor --web --traffic-direction bidirectional
```

### All Traffic: Server Monitoring
```bash
# Monitor everything including incoming SSH/web server connections
sudo python3 abnemo.py monitor --web --traffic-direction all
```

### Incoming Only: Server Monitoring
```bash
# Monitor only incoming server connections (SSH, web, etc.)
sudo python3 abnemo.py monitor --web --traffic-direction incoming
```

### With eBPF
```bash
# Bidirectional with eBPF process tracking
sudo python3 abnemo.py monitor --ebpf --web --traffic-direction bidirectional
```

---

## Comparison Table

| Feature | `outgoing` | `incoming` | `bidirectional` | `all` |
|---------|-----------|-----------|----------------|-------|
| **Outgoing connections** | ✓ | ✗ | ✓ | ✓ |
| **Responses to outgoing** | ✗ | ✗ | ✓ | ✓ |
| **Unsolicited incoming** | ✗ | ✓ | ✗ | ✓ |
| **Process attribution** | ✓ | ✗ | ✓ (outgoing only) | ✓ (outgoing only) |
| **Bandwidth accuracy** | ~50% | Varies | ~100% | ~100%+ |
| **Data volume** | Low | Low-Medium | Medium | High |
| **Server monitoring** | ✗ | ✓ | ✗ | ✓ |
| **Attack detection** | ✗ | ✓ | ✗ | ✓ |
| **Client usage tracking** | ✓ | ✗ | ✓ | ✓ |

---

## Technical Details

### How Bidirectional Mode Works

1. **Outgoing packet detected**: `local:12345 → remote:443`
   - Creates entry for `remote` IP
   - Tracks bytes/packets

2. **Incoming packet arrives**: `remote:443 → local:12345`
   - Checks if `remote` IP already has an entry
   - If yes: counts as response to established connection
   - If no: filters out (unsolicited)

3. **Result**: Only responses to YOUR connections are counted

### Process Tracking Limitations

- **Outgoing traffic**: Process can be identified (knows which local port)
- **Incoming traffic**: Process cannot be reliably identified
  - The kernel delivers incoming packets to the socket
  - We don't know which process owns that socket without expensive lookups
  - eBPF mode only tracks outgoing connection establishment

---

## Recommendations

### For Desktop/Laptop Users
```bash
# Start with outgoing to see what connects
sudo python3 abnemo.py monitor --web --traffic-direction outgoing

# Switch to bidirectional to measure actual bandwidth
sudo python3 abnemo.py monitor --web --traffic-direction bidirectional
```

### For Servers (Clean Server Traffic Only)
```bash
# Use 'incoming' to monitor only server connections (no client traffic)
sudo python3 abnemo.py monitor --web --traffic-direction incoming

# Or use 'all' to see everything
sudo python3 abnemo.py monitor --web --traffic-direction all --ebpf
```

### For Security Monitoring
```bash
# Use 'all' with longer retention
sudo python3 abnemo.py monitor \
  --web \
  --traffic-direction all \
  --log-retention-days 90 \
  --continuous-log-interval 300
```

---

## Systemd Service Configuration

Update your service file to use the desired mode:

```ini
[Service]
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --web \
    --web-port 5000 \
    --traffic-direction bidirectional \
    --continuous-log-interval 60
```

---

## Performance Impact

| Mode | CPU Impact | Memory Impact | Disk I/O |
|------|-----------|---------------|----------|
| `outgoing` | Low | Low | Low |
| `incoming` | Low | Low | Low-Medium |
| `bidirectional` | Low-Medium | Medium | Medium |
| `all` | Medium | Medium-High | High |

**Note**: Impact depends on network activity. A busy server in `all` mode will generate significantly more data than a desktop in `outgoing` mode.
