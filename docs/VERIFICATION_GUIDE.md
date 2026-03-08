# Traffic Monitoring Verification Guide

This guide explains how to verify that Abnemo is correctly capturing all network traffic and helps you understand the diagnostic commands.

## Quick Verification Commands

```bash
# 1. Check how much traffic Abnemo captured
jq -s 'map(.traffic_by_ip | to_entries | map(.value.bytes) | add // 0) | add' traffic_logs/*.json | numfmt --to=iec

# 2. Check system network statistics
cat /proc/net/dev

# 3. Show detailed interface statistics
ip -s link show

# 4. List all network interfaces
ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | tr -d ':'

# 5. Check default network interface
ip route show default

# 6. Test live packet capture
sudo timeout 10 tcpdump -i any -nn 'tcp port 443' -c 1000 2>&1 | tail -5
```

---

## Understanding the Output

### 1. Abnemo Captured Traffic

**Command:**
```bash
jq -s 'map(.traffic_by_ip | to_entries | map(.value.bytes) | add // 0) | add' traffic_logs/*.json | numfmt --to=iec
```

**What it does:**
- Reads all JSON log files in `traffic_logs/`
- Sums up all bytes for all IPs across all log files
- Converts to human-readable format (KB, MB, GB)

**Example output:**
```
3.4M
```

**What this means:**
- Abnemo has captured 3.4 MB of traffic total
- This is the sum of all traffic to/from all remote IPs

**Interpretation:**
- **`outgoing` mode**: This is only outgoing traffic (requests sent)
- **`bidirectional` mode**: This includes requests + responses
- **`all` mode**: This includes everything including unsolicited incoming

---

### 2. System Network Statistics (`/proc/net/dev`)

**Command:**
```bash
cat /proc/net/dev
```

**Example output:**
```
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    5678    0    0    0     0          0         0  1234567    5678    0    0    0     0       0          0
  eth0: 98765432  123456    0    0    0     0          0      1234 45678901  98765    0    0    0     0       0          0
 wlan0: 0           0       0    0    0     0          0         0  0          0       0    0    0     0       0          0
```

**What each column means:**

| Column | Meaning |
|--------|---------|
| **Receive bytes** | Total bytes received on this interface since boot |
| **Receive packets** | Total packets received |
| **Transmit bytes** | Total bytes sent on this interface since boot |
| **Transmit packets** | Total packets sent |
| **errs** | Errors (should be 0) |
| **drop** | Dropped packets (should be low) |

**Key interfaces:**
- **`lo`** (loopback): Local traffic (127.0.0.1) - ignore this
- **`eth0`**: Wired Ethernet connection
- **`wlan0`/`wlp*`**: WiFi connection
- **`docker0`**: Docker bridge network

**How to interpret:**
```bash
# Find your active interface (the one with high byte counts)
cat /proc/net/dev | grep -v "lo:" | awk 'NR>2 && ($2 > 1000000 || $10 > 1000000) {print $1, "RX:", $2, "TX:", $10}'
```

**Example:**
```
eth0: RX: 98765432 TX: 45678901
```

This means:
- **Received**: 98.7 MB since boot
- **Transmitted**: 45.6 MB since boot
- **Total**: 144.3 MB

**Compare to Abnemo:**
- If Abnemo shows 3.4 MB but system shows 144.3 MB, you're only capturing ~2.4% of traffic
- This could be because:
  - Abnemo was only running for a short time
  - You're using `outgoing` mode (missing incoming responses)
  - You're filtering specific traffic

---

### 3. Detailed Interface Statistics

**Command:**
```bash
ip -s link show
```

**Example output:**
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    RX: bytes  packets  errors  dropped overrun mcast   
    98765432   123456   0       0       0       1234    
    TX: bytes  packets  errors  dropped carrier collsns 
    45678901   98765    0       0       0       0       
```

**What the flags mean:**
- **UP**: Interface is active
- **LOWER_UP**: Physical link is connected (cable plugged in or WiFi connected)
- **BROADCAST**: Can send broadcast packets
- **MULTICAST**: Can send multicast packets

**State meanings:**
- **UP**: Interface is working
- **DOWN**: Interface is disabled
- **UNKNOWN**: Interface state cannot be determined

**What to check:**
1. Is your interface **UP**?
2. Are RX/TX bytes increasing?
3. Are there errors or dropped packets?

---

### 4. List All Network Interfaces

**Command:**
```bash
ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | tr -d ':'
```

**Example output:**
```
lo
eth0
wlan0
docker0
veth1234567
```

**What each interface is:**
- **`lo`**: Loopback (localhost) - ignore
- **`eth0`, `eno1`, `enp*`**: Wired Ethernet
- **`wlan0`, `wlp*`**: WiFi
- **`docker0`**: Docker bridge
- **`veth*`**: Virtual Ethernet (Docker containers)
- **`br-*`**: Bridge networks
- **`tun0`, `tap0`**: VPN interfaces

**Which one should Abnemo monitor?**
- If you don't specify `--interface`, Abnemo monitors **all** interfaces
- To monitor a specific one: `sudo python3 src/abnemo.py monitor --interface eth0`

---

### 5. Check Default Network Interface

**Command:**
```bash
ip route show default
```

**Example output:**
```
default via 192.168.1.1 dev eth0 proto dhcp metric 100
```

**What this means:**
- **Default gateway**: 192.168.1.1 (your router)
- **Interface**: eth0 (your active network interface)
- **Protocol**: DHCP (automatically configured)
- **Metric**: 100 (priority, lower is preferred)

**Why this matters:**
- This tells you which interface handles your internet traffic
- If you see `wlan0`, you're on WiFi
- If you see `eth0`, you're on wired Ethernet
- Abnemo should be capturing traffic on this interface

**Multiple routes:**
```
default via 192.168.1.1 dev eth0 proto dhcp metric 100
default via 192.168.1.1 dev wlan0 proto dhcp metric 600
```
- The one with **lower metric** is used (eth0 in this case)

---

### 6. Test Live Packet Capture

**Command:**
```bash
sudo timeout 10 tcpdump -i any -nn 'tcp port 443' -c 1000 2>&1 | tail -5
```

**What it does:**
- Captures HTTPS traffic (port 443) for 10 seconds
- Maximum 1000 packets
- Shows last 5 lines of output

**Example output:**
```
22:30:15.123456 IP 192.168.1.100.54321 > 142.250.185.46.443: Flags [P.], seq 1:100, ack 1, win 502, length 99
22:30:15.234567 IP 142.250.185.46.443 > 192.168.1.100.54321: Flags [.], ack 100, win 256, length 0
22:30:15.345678 IP 192.168.1.100.54321 > 142.250.185.46.443: Flags [P.], seq 100:200, ack 1, win 502, length 100

1000 packets captured
1000 packets received by filter
0 packets dropped by kernel
```

**What this means:**
- **1000 packets captured**: tcpdump successfully captured packets
- **0 packets dropped**: No packets were missed
- If you see packets, your network interface is working

**If you see "0 packets captured":**
- No HTTPS traffic during the test
- Try a different port: `sudo timeout 10 tcpdump -i any -nn 'tcp port 80' -c 100`
- Or capture all traffic: `sudo timeout 10 tcpdump -i any -nn -c 100`

---

## Complete Verification Workflow

### Step 1: Identify Your Active Interface

```bash
# Find which interface is handling internet traffic
ip route show default
# Output: default via 192.168.1.1 dev eth0 ...
#                                        ^^^^
#                                     This is your interface
```

### Step 2: Check System Traffic on That Interface

```bash
# Replace eth0 with your interface
cat /proc/net/dev | grep "eth0:"
# Output: eth0: 98765432 123456 0 0 0 0 0 1234 45678901 98765 0 0 0 0 0 0
#                ^^^^^^^                      ^^^^^^^^
#                RX bytes                     TX bytes
```

**Calculate total:**
```bash
# RX + TX = Total traffic since boot
# 98765432 + 45678901 = 144,444,333 bytes = 137.7 MB
```

### Step 3: Check Abnemo Captured Traffic

```bash
total=$(jq -s 'map(.traffic_by_ip | to_entries | map(.value.bytes) | add // 0) | add' traffic_logs/*.json)
echo "Abnemo captured: $(numfmt --to=iec $total) ($total bytes)"
```

### Step 4: Calculate Capture Percentage

```bash
# Get system RX+TX for your interface (e.g., eth0)
system_rx=$(cat /proc/net/dev | grep "eth0:" | awk '{print $2}')
system_tx=$(cat /proc/net/dev | grep "eth0:" | awk '{print $10}')
system_total=$((system_rx + system_tx))

# Get Abnemo total
abnemo_total=$(jq -s 'map(.traffic_by_ip | to_entries | map(.value.bytes) | add // 0) | add' traffic_logs/*.json)

# Calculate percentage
percentage=$(echo "scale=2; $abnemo_total * 100 / $system_total" | bc)
echo "Abnemo captured $percentage% of system traffic"
```

### Step 5: Interpret Results

| Percentage | Traffic Mode | Interpretation |
|------------|--------------|----------------|
| **~50%** | `outgoing` | ✓ Normal - only outgoing traffic |
| **~100%** | `bidirectional` | ✓ Normal - outgoing + responses |
| **>100%** | `all` | ✓ Normal - includes server traffic |
| **<10%** | Any | ⚠️ Problem - missing traffic |

---

## Common Issues and Solutions

### Issue 1: Abnemo Shows Much Less Traffic Than System

**Symptoms:**
- System: 100 MB
- Abnemo: 5 MB (5%)

**Possible causes:**

1. **Wrong traffic direction mode**
   ```bash
   # Solution: Use bidirectional mode
   sudo python3 src/abnemo.py monitor --web --traffic-direction bidirectional
   ```

2. **Abnemo only ran for a short time**
   ```bash
   # Check when monitoring started
   ls -lh traffic_logs/*.json | head -1
   
   # System stats are since boot, Abnemo stats are since start
   ```

3. **Filtering local traffic**
   ```bash
   # Abnemo filters out local IPs (10.x.x.x, 192.168.x.x, etc.)
   # This is correct behavior
   ```

4. **Wrong interface**
   ```bash
   # Check default interface
   ip route show default
   
   # Specify it explicitly
   sudo python3 src/abnemo.py monitor --interface eth0 --web
   ```

### Issue 2: No Traffic Captured at All

**Symptoms:**
- Abnemo: 0 bytes
- System: >0 bytes

**Solutions:**

1. **Check permissions**
   ```bash
   # Must run as root
   sudo python3 src/abnemo.py monitor --web
   ```

2. **Check if interface is up**
   ```bash
   ip link show eth0
   # Should show "UP"
   ```

3. **Test packet capture manually**
   ```bash
   sudo timeout 5 tcpdump -i any -c 10
   # Should see packets
   ```

### Issue 3: System Shows Less Traffic Than Abnemo

**Symptoms:**
- System: 50 MB
- Abnemo: 100 MB

**Possible causes:**

1. **System stats reset**
   ```bash
   # Check uptime
   uptime
   # If system recently rebooted, /proc/net/dev resets
   ```

2. **Abnemo counting duplicates**
   ```bash
   # Check for duplicate log files
   ls -lh traffic_logs/*.json
   
   # Remove old logs
   rm traffic_logs/traffic_log_OLD*.json
   ```

---

## Advanced Verification

### Compare Abnemo to tcpdump

```bash
# Run tcpdump for 60 seconds
sudo timeout 60 tcpdump -i any -nn 'not host 127.0.0.1' -w /tmp/capture.pcap

# Analyze capture
tcpdump -r /tmp/capture.pcap -nn | wc -l  # Packet count
capinfos /tmp/capture.pcap  # Detailed stats (if wireshark-cli installed)

# Compare to Abnemo
jq -s 'map(.traffic_by_ip | to_entries | map(.value.packets) | add // 0) | add' traffic_logs/*.json
```

### Monitor in Real-Time

```bash
# Terminal 1: Run Abnemo
sudo python3 src/abnemo.py monitor --web --traffic-direction bidirectional

# Terminal 2: Watch system stats
watch -n 1 'cat /proc/net/dev | grep -E "eth0|wlan0"'

# Terminal 3: Generate traffic
curl -O https://speed.hetzner.de/100MB.bin

# Compare the numbers
```

---

## Expected Results by Mode

### Outgoing Mode (Default)
```bash
# System: 100 MB (50 MB RX + 50 MB TX)
# Abnemo: ~50 MB (only TX)
# Ratio: ~50%
```

### Bidirectional Mode
```bash
# System: 100 MB (50 MB RX + 50 MB TX)
# Abnemo: ~100 MB (TX + RX responses)
# Ratio: ~100%
```

### Incoming Mode
```bash
# System: 100 MB (50 MB RX + 50 MB TX)
# Abnemo: ~10 MB (only unsolicited RX, e.g., SSH attempts)
# Ratio: ~10% (depends on server traffic)
```

### All Mode
```bash
# System: 100 MB (50 MB RX + 50 MB TX)
# Abnemo: ~100 MB+ (everything)
# Ratio: ~100%+
```

---

## Troubleshooting Checklist

- [ ] Running as root (`sudo`)
- [ ] Correct interface specified or using `any`
- [ ] Interface is UP (`ip link show`)
- [ ] Traffic direction mode matches your goal
- [ ] No firewall blocking packet capture
- [ ] Python dependencies installed (`scapy`, etc.)
- [ ] Comparing same time period (system stats vs Abnemo logs)
- [ ] Not comparing boot-time stats to short-run Abnemo stats

---

## Quick Reference

```bash
# Full verification script
cat << 'EOF' > verify_abnemo.sh
#!/bin/bash
echo "=== Abnemo Traffic Verification ==="
echo ""

# 1. Active interface
echo "1. Active Interface:"
ip route show default | grep -oP 'dev \K\S+'
echo ""

# 2. System traffic
echo "2. System Traffic (since boot):"
iface=$(ip route show default | grep -oP 'dev \K\S+' | head -1)
rx=$(cat /proc/net/dev | grep "$iface:" | awk '{print $2}')
tx=$(cat /proc/net/dev | grep "$iface:" | awk '{print $10}')
total=$((rx + tx))
echo "  RX: $(numfmt --to=iec $rx)"
echo "  TX: $(numfmt --to=iec $tx)"
echo "  Total: $(numfmt --to=iec $total)"
echo ""

# 3. Abnemo traffic
echo "3. Abnemo Captured:"
abnemo=$(jq -s 'map(.traffic_by_ip | to_entries | map(.value.bytes) | add // 0) | add' traffic_logs/*.json 2>/dev/null || echo 0)
echo "  Total: $(numfmt --to=iec $abnemo)"
echo ""

# 4. Comparison
if [ $total -gt 0 ]; then
    percentage=$(echo "scale=2; $abnemo * 100 / $total" | bc)
    echo "4. Capture Rate: ${percentage}%"
else
    echo "4. Capture Rate: N/A (no system traffic)"
fi
EOF

chmod +x verify_abnemo.sh
./verify_abnemo.sh
```

Run this script anytime to check if Abnemo is working correctly!
