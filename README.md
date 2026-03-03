# Abnemo - Network Traffic Monitor & IPTables Rule Generator

A Linux-based network packet monitoring tool that captures outgoing traffic, performs reverse DNS lookups, logs data usage by IP address, and generates iptables rules to block specific destinations.

## Features

- **Real-time packet capture** using Scapy (IPv4 and IPv6)
- **Reverse DNS lookups** to identify destination domains
- **ISP identification** using ip-api.com (free tier or pro with API key)
- **Port mapping** with human-readable descriptions
- **IP classification** (multicast, private, public, reserved) for both IPv4 and IPv6
- **Traffic statistics** tracking bytes and packets per destination
- **Periodic summaries** during monitoring
- **JSON logging** for later analysis
- **iptables rule generation** from captured traffic
- **Interactive mode** for selective IP blocking
- **Continuous monitoring** with automatic log rotation
- **Process and container tracking** (optional) to identify which program sent packets
- **Full IPv6 support** alongside IPv4
- **Live web interface** for real-time traffic monitoring with beautiful UI
- **Configurable traffic direction**: outgoing only (default), bidirectional (with responses), or all traffic (including servers)
- **JSON Logging**: Save detailed traffic logs for later analysis
- **IPTables Rule Generation**: Create iptables rules to block specific IPs or domains
- **Interactive Mode**: Manually select which IPs to block from captured traffic
- **Automatic Blocking**: Set thresholds to auto-block high-traffic destinations

## Quick Start

### Installation (One-time setup)

```bash
# 1. Install dependencies
# Option A: System packages (recommended if using system Python)
sudo apt install python3-scapy python3-dnspython python3-tabulate  # Ubuntu/Debian

# Option B: pip (if you need specific versions or use virtual environments)
pip install -r requirements.txt

# For eBPF support:
sudo apt install python3-bpfcc  # Ubuntu/Debian

# 2. Make wrapper script executable
chmod +x abnemo.sh

# 3. (Optional) Set up IP-API pro key for unlimited ISP lookups
export IPAPI_KEY=your_api_key_here
# Or add to ~/.bashrc for persistence
```

### Basic Workflow

**Step 1: Monitor Traffic**
```bash
# Monitor for 60 seconds with summaries every 10 seconds
./abnemo.sh monitor --duration 60 --summary-interval 10

# Or monitor indefinitely (Ctrl+C to stop)
./abnemo.sh monitor --summary-interval 10

# Monitor with live web interface (access at http://localhost:5000)
./abnemo.sh monitor --summary-interval 10 --web
```

**Step 2: View Captured Logs**
```bash
./abnemo.sh list-logs
```

**Step 3: Generate Block Rules (Interactive)**
```bash
./abnemo.sh generate --log traffic_logs/traffic_log_XXXXXX.json --interactive
```

Select the IPs you want to block by entering their numbers (e.g., `1,3,5`) or `all` for all IPs.

**Step 4: Apply Rules**
```bash
# Block the selected IPs
sudo bash block_rules.sh

# Later, to unblock
sudo bash unblock_rules.sh
```

## Requirements

- Linux operating system
- Python 3.7+
- Root/sudo privileges (required for packet capture)
- iptables (for applying firewall rules)

## Installation

### Option 1: System Packages (Recommended)

If you're using system Python, install dependencies via your package manager:

```bash
# Install Python dependencies
sudo apt install python3-scapy python3-dnspython python3-tabulate  # Ubuntu/Debian
# OR
sudo dnf install python3-scapy python3-dns python3-tabulate        # Fedora/RHEL

# Install BCC system package (for eBPF support)
sudo apt install python3-bpfcc  # Ubuntu/Debian
# OR
sudo dnf install python3-bcc    # Fedora/RHEL

# Make the wrapper script executable
chmod +x abnemo.sh
```

**Benefits:**
- No dependency conflicts
- System-managed updates
- Works seamlessly with eBPF
- No virtual environment needed

### Option 2: pip (Virtual Environments)

If you prefer using pip (e.g., in a virtual environment):

```bash
# Create virtual environment (optional)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install BCC system package (for eBPF support)
sudo apt install python3-bpfcc  # Ubuntu/Debian
# OR
sudo dnf install python3-bcc    # Fedora/RHEL

# Make the wrapper script executable
chmod +x abnemo.sh
```

**Note:** BCC must be installed system-wide and cannot be installed via pip.

### Option 3: Global pip Installation

Install Python packages globally with pip:

```bash
pip install -r requirements.txt
# OR on newer systems that prevent global pip installs:
sudo apt install python3-scapy python3-dnspython python3-tabulate

sudo apt install python3-bpfcc
chmod +x abnemo.sh
```

### Important: Python Path with Sudo

When using `sudo`, the system may use a different Python installation than your user environment. If you get `ModuleNotFoundError`, use one of these solutions:

**Option 1: Use the wrapper script (easiest)**
```bash
./abnemo.sh monitor
```

**Option 2: Install packages system-wide**
```bash
sudo apt install python3-scapy python3-dnspython python3-tabulate
```

**Option 3: Specify full Python path (if using virtual environment)**
```bash
sudo /path/to/venv/bin/python3 abnemo.py monitor
```

## Usage

### 1. Monitor Network Traffic

Capture outgoing network traffic (requires root privileges):

```bash
# Using wrapper script (recommended)
./abnemo.sh monitor

# Or with full Python path
sudo /home/ant/miniconda3/bin/python3 abnemo.py monitor

# Monitor for 60 seconds
./abnemo.sh monitor --duration 60

# Monitor with periodic summaries every 10 seconds
./abnemo.sh monitor --summary-interval 10

# Monitor specific network interface with summaries
./abnemo.sh monitor --interface eth0 --summary-interval 10

# Show top 50 destinations in final summary
./abnemo.sh monitor --top 50

# Continuous monitoring with automatic log rotation
./abnemo.sh monitor --summary-interval 10 --continuous-log-interval 60

# Custom log retention (keep 7 days, max 50MB)
./abnemo.sh monitor --log-retention-days 7 --log-max-size-mb 50

# Enable process tracking (identify which program sent packets)
./abnemo.sh monitor --enable-process-tracking --summary-interval 10

# Monitor with live web interface for real-time visualization
./abnemo.sh monitor --summary-interval 10 --web --web-port 5000
```

#### Live Web Interface

Monitor traffic in real-time with a beautiful web dashboard:

```bash
# Start monitoring with web interface
./abnemo.sh monitor --web --summary-interval 10

# Access the web interface at http://localhost:5000
# The web interface shows:
# - Real-time traffic statistics (IPs, bytes, packets)
# - Sortable table of all destinations
# - Time range selector (last 5min, 15min, 30min, 1hr, 6hr, 24hr)
# - Custom time range picker
# - IP type classification badges
# - Domain and ISP information

# Customize the web server port
./abnemo.sh monitor --web --web-port 8080
```

**How it works:**
- Web server runs in background thread during monitoring
- Reads log files dynamically at request time (no caching)
- Filters files by reading their internal timestamp field
- Only includes files whose timestamp falls within the requested range
- Updates automatically as new log files are created
- Perfect for long-running monitoring sessions

**API Endpoint:**
```
GET /api/traffic?begin=<ISO8601>&end=<ISO8601>
```

Example:
```bash
curl "http://localhost:5000/api/traffic?begin=2026-03-01T20:00:00&end=2026-03-01T21:00:00"
```

The monitor will:
- Capture all outgoing IP packets
- Classify IP addresses (multicast, private, public, reserved)
- Perform reverse DNS lookups for each destination
- Track bytes, packets, and ports per IP
- Optionally identify which process/container sent packets (with `--enable-process-tracking`)
- Display periodic summaries if `--summary-interval` is specified
- Display a final summary when stopped
- Show human-readable port descriptions
- Save results to `traffic_logs/traffic_log_YYYYMMDD_HHMMSS.json`

#### Continuous Monitoring Mode

When running without `--duration`, Abnemo operates in **continuous mode**:

- **Automatic log saving**: Creates a new log file every 60 seconds (configurable)
- **Automatic cleanup**: Deletes old logs based on retention policy
- **No data loss**: Each log captures traffic since the last save
- **Long-term monitoring**: Suitable for running as a service

**Default retention policy:**
- Delete logs older than 30 days
- Delete oldest logs if total size exceeds 100 MB
- Cleanup runs before each new log is saved

**Example continuous monitoring:**
```bash
# Run indefinitely, save logs every minute
./abnemo.sh monitor --continuous-log-interval 60

# Run with custom retention
./abnemo.sh monitor --log-retention-days 7 --log-max-size-mb 50

# Disable continuous logging (only save on exit)
./abnemo.sh monitor --continuous-log-interval 0
```

#### Process Tracking (Optional)

Abnemo can identify **which process or Docker container** sent each packet. This feature is **disabled by default** to avoid performance overhead.

**Enable with:**
```bash
./abnemo.sh monitor --enable-process-tracking --summary-interval 10
```

**What it shows:**
- Process name and PID
- Docker container name (if applicable)
- Kubernetes pod info (if applicable)

**Example output:**
```
1. IP: 52.184.215.111 [public]
   Domain: no domain name known
   ISP: Microsoft Azure Cloud (eastus2) (US)
   Process: firefox (PID: 12345)
   Ports: 443 (HTTPS)
   Traffic: 1,234,567 bytes, 890 packets

2. IP: 172.217.16.142 [public]
   Domain: lhr25s34-in-f14.1e100.net
   ISP: Google LLC (US)
   Process: docker-proxy (PID: 5678) in container: web-server
   Ports: 443 (HTTPS)
   Traffic: 987,654 bytes, 456 packets
```

**How it works:**
- Uses `/proc/net/tcp` and `/proc/net/udp` to match sockets to processes
- Parses `/proc/[pid]/cgroup` to identify Docker containers
- **Fallback for Docker**: If process lookup fails (short-lived process), identifies container by source IP address
- Results are cached to minimize overhead
- Only looks up process info once per unique connection

**Performance impact:**
- **Disabled**: Zero overhead (module not loaded)
- **Enabled**: ~1-5ms per unique connection (first packet only)
- Cached results used for subsequent packets
- Suitable for moderate traffic (hundreds of connections/sec)

**Limitations:**
- Requires root access (already needed for packet capture)
- **May miss short-lived processes** (curl, wget, ping) due to race conditions - the socket may close before Abnemo can look it up
- **Docker containers with brief connections**: Process name may not be detected, but container name will be identified via IP fallback
- Works best for **long-lived connections** (browsers, SSH, persistent services)
- Cannot identify process for forwarded/NAT traffic
- Docker container identification requires Docker CLI access

**Troubleshooting:**
- If processes aren't showing up, they may be completing too quickly
- Use `sudo python3 test_process_lookup.py` to debug
- Check `ss -tnp` to see active connections
- See `PROCESS_TRACKING_NOTES.md` for detailed debugging guide
- **For zero race conditions, use eBPF mode** (see below)

---

## eBPF Mode (Advanced)

**NEW:** Abnemo now supports eBPF (Extended Berkeley Packet Filter) for kernel-level process tracking with **zero race conditions**.

### Why eBPF?

| Feature | Standard Mode | eBPF Mode |
|---------|--------------|-----------|
| Race conditions | Yes (misses short-lived processes) | **No (catches everything)** |
| CPU overhead | ~1-5ms per connection | **<0.1ms** |
| Catches curl/wget | ❌ No | ✅ **Yes** |
| Catches Docker scripts | Sometimes | ✅ **Always** |
| Setup complexity | Easy | Medium |
| Kernel requirement | Any | 4.x+ |

### Installation

BCC must be installed via system package manager (not available in conda):

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3-bpfcc

# Fedora/RHEL
sudo dnf install python3-bcc

# If using conda, deactivate first
conda deactivate

# Verify installation
./build_ebpf.sh
```

**Why BCC requires system packages:**
- Needs kernel headers matching your running kernel
- Requires LLVM/Clang compiler toolchain
- Deep integration with kernel BPF subsystem
- Not available in conda or pip repositories

### Usage

```bash
# eBPF mode (recommended for security monitoring)
sudo ./abnemo.sh monitor --ebpf --summary-interval 10

# Or directly
sudo python3 abnemo.py monitor --ebpf --summary-interval 10 --top 20
```

### How It Works

1. **Kernel hooks**: Attaches to `tcp_sendmsg()`, `udp_sendmsg()`, `tcp_connect()`
2. **Pre-capture**: Extracts PID, process name, cgroup **before** packet is sent
3. **No race condition**: Process info captured even if process exits in 1ms
4. **Zero overhead**: Runs in kernel space, minimal CPU usage
5. **Complete visibility**: Catches ALL network activity, even brief connections

### Perfect For

- ✅ Detecting rogue scripts (curl, wget, python requests)
- ✅ Security monitoring (24/7 with <1% CPU)
- ✅ Docker container tracking (no IP fallback needed)
- ✅ Short-lived processes (crypto miners, scanners)
- ✅ Real-time alerting

### Requirements

- Linux kernel 4.x or higher (5.x recommended)
- BCC (BPF Compiler Collection) installed
- Root privileges (same as standard mode)
- BPF enabled in kernel (usually default)

### Build & Test

```bash
# Check requirements and compile eBPF program
./build_ebpf.sh

# Test eBPF mode
sudo python3 abnemo.py monitor --ebpf --duration 30 --summary-interval 10

# In another terminal, test with short-lived process
curl https://microsoft.com
curl https://google.com

# eBPF will catch these! Standard mode might miss them.
```

### Comparison Example

**Standard mode:**
```bash
sudo ./abnemo.sh monitor --enable-process-tracking --summary-interval 10
# Run: curl https://microsoft.com
# Result: ❌ Might miss (race condition)
```

**eBPF mode:**
```bash
sudo ./abnemo.sh monitor --ebpf --summary-interval 10
# Run: curl https://microsoft.com
# Result: ✅ Always catches (no race condition)
```

### Troubleshooting

**Error: "BCC not found"**
```bash
sudo apt install python3-bpfcc
```

**Error: "Kernel too old"**
```bash
uname -r  # Check version (need 4.x+)
```

**Error: "Permission denied"**
```bash
# eBPF requires root
sudo python3 abnemo.py monitor --ebpf
```

See `EBPF_ENHANCEMENT.md` for detailed architecture and implementation notes.

**See also:** `ADVANCED_FILTERING.md` for detailed technical information about process identification methods.

### Common Commands

```bash
# Monitor specific interface with periodic summaries
./abnemo.sh monitor --interface eth0 --duration 120 --summary-interval 10

# Auto-block IPs with >10MB traffic
./abnemo.sh generate --log traffic_logs/traffic_log_XXXXXX.json --min-bytes 10485760

# Block specific domains
./abnemo.sh generate --log traffic_logs/traffic_log_XXXXXX.json --domains "ads.com,tracker.net"

# Block specific IPs
./abnemo.sh generate --log traffic_logs/traffic_log_XXXXXX.json --ips "1.2.3.4,5.6.7.8"
```

### 2. List Captured Logs

View all previously captured traffic logs:

```bash
python3 abnemo.py list-logs
```

### 3. Generate IPTables Rules

Create iptables rules to block specific IPs based on captured traffic:

#### Interactive Mode (Recommended)

Select IPs manually from a captured log:

```bash
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --interactive
```

This will:
- Display all captured IPs sorted by data volume
- Let you select which IPs to block
- Generate both block and unblock scripts

#### Automatic Mode with Thresholds

Block IPs that exceed certain thresholds:

```bash
# Block IPs that transferred more than 10MB
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --min-bytes 10485760

# Block IPs with more than 1000 packets
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --min-packets 1000
```

#### Block Specific IPs or Domains

```bash
# Block specific IP addresses
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --ips "192.168.1.100,10.0.0.50"

# Block all IPs associated with specific domains
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --domains "ads.example.com,tracker.com"
```

#### Advanced Options

```bash
# Use REJECT instead of DROP
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --interactive --action REJECT

# Generate iptables-restore format (more efficient for many rules)
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --interactive --format restore

# Custom output file
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --interactive --output my_rules.sh
```

### 4. Apply IPTables Rules

After generating rules, apply them:

```bash
# Apply blocking rules
sudo bash block_rules.sh

# Later, remove blocking rules
sudo bash unblock_rules.sh
```

For iptables-restore format:
```bash
sudo iptables-restore < rules.txt
```

## IP Address Classification

Abnemo automatically classifies IP addresses into different categories to help you understand your network traffic. The tool identifies the following types:

### Multicast Addresses (224.0.0.0 - 239.255.255.255)
Used for one-to-many communication. Common multicast addresses include:
- **224.0.0.251** - mDNS (Multicast DNS) - used for local network service discovery
- **224.0.0.252** - LLMNR (Link-Local Multicast Name Resolution)
- **239.255.255.250** - SSDP (Simple Service Discovery Protocol) - used by UPnP devices

**Note**: Multicast traffic is normal for local network operations and typically should not be blocked.

### Private/Local Addresses
Non-routable addresses used within private networks:
- **10.0.0.0 - 10.255.255.255** (Class A) - Large private networks
- **172.16.0.0 - 172.31.255.255** (Class B) - Medium private networks
- **192.168.0.0 - 192.168.255.255** (Class C) - Home/small office networks

**Note**: Private addresses are filtered out by default and not logged.

### Special Purpose Addresses

#### Loopback (127.0.0.0/8)
- **127.0.0.1** - localhost, traffic to your own machine
- Filtered out by default

#### Link-Local (169.254.0.0/16)
- Auto-configured addresses when DHCP is unavailable
- Used for local network communication only

#### Broadcast (255.255.255.255)
- Sends packets to all devices on the local network

### Reserved Addresses
Special ranges reserved for testing and documentation:
- **192.0.0.0/24** - IETF Protocol Assignments
- **192.0.2.0/24** - TEST-NET-1 (documentation/examples)
- **198.51.100.0/24** - TEST-NET-2 (documentation/examples)
- **203.0.113.0/24** - TEST-NET-3 (documentation/examples)
- **198.18.0.0/15** - Benchmark testing
- **192.88.99.0/24** - IPv6 to IPv4 relay (deprecated)
- **240.0.0.0 - 255.255.255.254** - Reserved for future use

### Public Addresses
All other addresses are considered public/internet-routable and represent actual internet destinations.

## Port Descriptions

Abnemo includes a customizable port mapping file (`port_mappings.txt`) that translates port numbers into human-readable descriptions. You can edit this file to add your own port mappings.

### Common Ports Included

**Web Services**:
- 80 (HTTP), 443 (HTTPS), 8080 (HTTP Alternate)

**DNS**:
- 53 (DNS), 5353 (mDNS - Multicast DNS for local network)

**Network Discovery**:
- 1900 (SSDP - UPnP device discovery)

**Email**:
- 25 (SMTP), 143 (IMAP), 993 (IMAPS), 587 (SMTP Submission)

**Remote Access**:
- 22 (SSH), 3389 (RDP), 5900 (VNC)

**Databases**:
- 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)

To add custom ports, edit `port_mappings.txt`:
```
# Format: port_number = description
8888 = My Custom Service
9999 = Development Server
```

## ISP Lookup

Abnemo automatically identifies the ISP (Internet Service Provider) or organization for IP addresses that don't have reverse DNS records. This helps you understand who owns the infrastructure your traffic is going to.

### How It Works

1. **Domain First**: If an IP has a reverse DNS record (domain name), that's displayed
2. **ISP Fallback**: If no domain is found, Abnemo queries the ip-api.com API to get ISP information
3. **Caching**: All ISP lookups are cached in `isp_cache.json` to avoid repeated API calls
4. **Rate Limiting**: Respects API rate limits (45 requests/minute for free tier, unlimited for pro)

### API Key Configuration

Abnemo supports both free and pro tiers of ip-api.com:

**Free Tier** (default):
- 45 requests per minute
- HTTP only
- No API key required

**Pro Tier** (recommended for heavy use):
- Unlimited requests
- HTTPS support
- Requires API key from [ip-api.com](https://members.ip-api.com/)

To use a pro API key, either:

1. **Command line argument**:
```bash
./abnemo.sh monitor --isp-api-key YOUR_API_KEY
```

2. **Environment variable**:
```bash
export IPAPI_KEY=YOUR_API_KEY
./abnemo.sh monitor
```

### Example Output

```
================================================================================
[11:33:24] Periodic Summary (last 30s)
================================================================================
IPs: 5 | Bytes: 35,729 | Packets: 112

Top 5 destinations:
--------------------------------------------------------------------------------

1. IP: 35.223.238.178 [public]
   Domain: 178.238.223.35.bc.googleusercontent.com
   ISP: Google LLC (US)
   Ports: 443 (HTTPS)
   Traffic: 33,265 bytes, 98 packets

2. IP: 239.255.255.250 [multicast]
   Domain: no domain name known
   ISP: ISP lookup pending...
   Ports: 1900 (SSDP (UPnP Discovery))
   Traffic: 860 bytes, 8 packets

3. IP: 52.184.215.111 [public]
   Domain: no domain name known
   ISP: Microsoft Azure Cloud (eastus2) (US)
   Ports: 443 (HTTPS)
   Traffic: 535 bytes, 3 packets
================================================================================
```

### ISP Information Includes

- **Organization**: The company or entity that owns the IP block
- **ISP Name**: Internet service provider name
- **AS Number**: Autonomous System number (e.g., AS8075 Microsoft Corporation)
- **Country**: Country where the IP is registered
- **Country Code**: Two-letter country code (e.g., US, GB, DE)

### Cache Management

The ISP cache is stored in `isp_cache.json` and persists between runs. To clear the cache:

```bash
rm isp_cache.json
```

The cache helps:
- Reduce API calls and respect rate limits
- Speed up subsequent monitoring sessions
- Work offline for previously seen IPs

## Project Structure

```
abnemo/
├── abnemo.py              # Main CLI interface
├── abnemo.sh              # Wrapper script for easy execution
├── packet_monitor.py      # Packet capture and monitoring logic
├── iptables_generator.py  # IPTables rule generation
├── isp_lookup.py          # ISP/organization lookup module
├── port_mappings.txt      # Port number to description mappings
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── .gitignore             # Git ignore rules
├── isp_cache.json         # ISP lookup cache (auto-generated)
└── traffic_logs/          # Directory for traffic logs (auto-generated)
    └── traffic_log_*.json
```

## How It Works - Technical Details

### Packet Capture Architecture

Abnemo uses **Scapy** for live packet capture. Here's what you need to know:

#### Live Monitoring Only

**Abnemo monitors packets in real-time as they traverse your network interface.** It does NOT:
- Read historical packets from the past
- Access kernel packet logs or buffers
- Replay previously captured traffic
- Work with pcap files created by other tools

**To analyze past traffic**, you must:
1. First run `monitor` to create a traffic log file
2. Then use `generate` to analyze that log file

The monitoring process works like this:

```
Network Interface → Scapy Sniffer → Packet Filter → Statistics Aggregation → JSON Log
                                          ↓
                                    DNS Lookup
                                    ISP Lookup
                                    Port Classification
```

#### What Gets Captured

- **Layer**: IP layer (Layer 3) packets only
- **Direction**: Outgoing packets only (packets leaving your machine)
- **Protocols**: All IP-based protocols (TCP, UDP, ICMP, etc.)
- **Filtering**: Automatically filters out loopback (127.0.0.0/8) and link-local traffic

#### Docker Container Monitoring

**Yes, Abnemo monitors Docker container traffic** when run on the host machine:

- **Default Docker bridge network**: Container traffic is captured as it exits the host
- **Host network mode** (`--network host`): Fully captured, appears as host traffic
- **Custom bridge networks**: Captured when packets leave the Docker network
- **Container-to-container**: Only captured if traffic exits the host network

**To monitor Docker traffic:**

```bash
# Run on host (not inside container)
./abnemo.sh monitor --summary-interval 10
```

**What you'll see:**
- External IPs contacted by containers (e.g., Docker Hub, APIs, databases)
- Container traffic appears with the host's source IP
- Cannot distinguish which container generated the traffic (use Docker logs for that)

**To monitor specific Docker network:**
```bash
# Find Docker network interface
docker network inspect bridge | grep com.docker.network.bridge.name

# Monitor that interface
./abnemo.sh monitor --interface docker0
```

**Limitations:**
- Cannot identify which container sent packets (all appear from host)
- Inter-container traffic on same network is not captured
- For per-container monitoring, run Abnemo inside each container (not recommended)

#### Real-time Processing

1. **Packet Sniffing**: Scapy captures each outgoing packet as it's transmitted
2. **Immediate Analysis**: Each packet is analyzed immediately:
   - Extract destination IP, port, and packet size
   - Classify IP type (public, private, multicast, reserved)
   - Perform reverse DNS lookup (cached to avoid duplicates)
   - Track cumulative statistics per destination IP
3. **Deferred ISP Lookup**: ISP information is looked up during summary generation to avoid blocking packet capture
4. **Thread Safety**: Uses locks to ensure statistics are updated safely across threads
5. **Periodic Summaries**: Optional background thread displays summaries at regular intervals

#### No Historical Access

**Important limitation**: Abnemo cannot see packets that were sent before you started monitoring. This is because:
- Scapy operates at the application level, not kernel level
- Linux doesn't maintain a persistent packet history by default
- Packet capture must be active when packets are transmitted

If you need historical packet analysis, you would need:
- A kernel-level packet logger (like `tcpdump` running continuously)
- Netfilter/iptables logging enabled beforehand
- A dedicated packet capture appliance

### Data Storage and Analysis

#### Traffic Logs (JSON Format)

When monitoring completes, Abnemo saves a JSON file containing:
- All destination IPs contacted
- Domain names (from reverse DNS)
- ISP information (if looked up)
- Total bytes and packets per IP
- All ports used per IP
- IP classification type

Example structure:
```json
{
  "timestamp": "2026-03-01 12:00:00",
  "total_bytes": 1234567,
  "total_packets": 890,
  "traffic_by_ip": {
    "52.184.215.111": {
      "bytes": 12345,
      "packets": 45,
      "domains": [],
      "ports": [443],
      "ip_type": "public",
      "isp": {
        "org": "Microsoft Azure Cloud (eastus2)",
        "country_code": "US"
      }
    }
  }
}
```

#### IPTables Rule Generation

The `generate` command:
1. Reads a previously saved JSON log file
2. Filters IPs based on your criteria (bytes, domains, specific IPs)
3. Generates bash scripts with iptables commands
4. Creates both block and unblock scripts

**This is a two-step process**: Monitor first, then generate rules from the log.

### Performance Considerations

- **CPU Usage**: Minimal - only processes outgoing packets
- **Memory**: Grows with number of unique destination IPs
- **Disk I/O**: Only writes JSON at the end of monitoring
- **Network Impact**: Zero - purely passive monitoring
- **DNS Lookups**: Cached to minimize external queries
- **ISP Lookups**: Rate-limited and cached (45/min free, unlimited with API key)

## Security Considerations

- **Root Privileges**: Packet capture requires root access. Review the code before running with sudo.
- **Blocking Risks**: Be careful when blocking IPs - you might block legitimate services.
- **Testing**: Test rules in a safe environment before deploying to production.
- **Backup**: Always generate unblock scripts to reverse changes if needed.

## Troubleshooting

### "BCC Python module not found" (build_ebpf.sh fails)

**Problem**: The build script can't find BCC even though `python3-bpfcc` is installed.

**Cause**: You're in a conda environment, but BCC was installed for system Python.

**Solutions**:

**Solution: Deactivate conda before using eBPF**
```bash
conda deactivate
./build_ebpf.sh
# Note: You'll need to deactivate conda each time you run eBPF mode
```

**How to verify which Python is being used:**
```bash
which python3                    # Shows current Python path
/usr/bin/python3 -c "import bcc" # Test system Python
python3 -c "import bcc"          # Test current environment
```

### "ModuleNotFoundError: No module named 'dns'"

**Problem**: When running with sudo, Python can't find installed packages.

**Solution**: Use the wrapper script `./abnemo.sh` instead of calling Python directly, or specify the full Python path:

```bash
# Option 1: Use wrapper script (easiest)
./abnemo.sh monitor

# Option 2: Specify full Python path
sudo /home/ant/miniconda3/bin/python3 abnemo.py monitor

# Option 3: Install packages system-wide
sudo pip3 install -r requirements.txt
```

### "Permission denied" when monitoring

**Problem**: Packet capture requires root privileges.

**Solution**: The wrapper script automatically uses sudo for monitoring. Just run:
```bash
./abnemo.sh monitor
```

Or run directly with sudo:
```bash
sudo python3 abnemo.py monitor
```

### No packets captured

**Possible causes**:
- Ensure there's active network traffic during monitoring
- Try monitoring a specific interface: `./abnemo.sh monitor --interface eth0`
- Check that you have proper permissions (the script uses sudo)
- Verify firewall rules aren't blocking packet capture

**To test**:
```bash
# List available interfaces
ip link show

# Monitor specific interface
./abnemo.sh monitor --interface wlan0 --duration 30
```

### DNS Lookup Timeouts

- Some IPs may not have reverse DNS records (will show as "no domain name known")
- DNS lookups have a 2-second timeout to avoid blocking packet capture
- Results are cached to improve performance on subsequent runs

### ISP Lookup Failures

- Free tier is limited to 45 requests per minute
- If you exceed the limit, lookups will show "ISP lookup pending..."
- Consider using a pro API key for unlimited lookups
- ISP data is cached, so re-running won't re-query the API

## File Locations

- **Traffic logs**: `traffic_logs/traffic_log_YYYYMMDD_HHMMSS.json`
- **Block rules**: `block_rules.sh` (generated by `generate` command)
- **Unblock rules**: `unblock_rules.sh` (generated by `generate` command)
- **ISP cache**: `isp_cache.json` (auto-generated)
- **Port mappings**: `port_mappings.txt` (user-editable)

## Examples

### Example 1: Monitor and Block High-Traffic Destinations

```bash
# Step 1: Monitor traffic for 5 minutes
sudo python3 abnemo.py monitor --duration 300

# Step 2: Review the log
python3 abnemo.py list-logs

# Step 3: Generate rules interactively
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_143022.json --interactive

# Step 4: Apply rules
sudo bash block_rules.sh
```

### Example 2: Block Advertising/Tracking Domains

```bash
# Monitor traffic while browsing
sudo python3 abnemo.py monitor --duration 120

# Block known ad/tracking domains
python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_143022.json \
  --domains "doubleclick.net,googleadservices.com,facebook.com"

# Apply rules
sudo bash block_rules.sh
```

### Example 3: Monitor Specific Application

```bash
# Start monitoring
sudo python3 abnemo.py monitor &

# Run your application
./my_application

# Stop monitoring (Ctrl+C)
# Review and block suspicious IPs
python3 abnemo.py generate --log traffic_logs/traffic_log_*.json --interactive
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## Disclaimer

This tool is for legitimate network monitoring and security purposes only. Always ensure you have proper authorization before monitoring network traffic. Use responsibly and in accordance with your local laws and network policies.
