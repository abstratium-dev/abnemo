# Process Tracking - Issues and Solutions

## Issue #1: Duplicate Process Names ✅ FIXED

**Problem:** Same process appeared multiple times with different PIDs:
```
Processes:
  - windsurf (PID: 2320556)
  - windsurf (PID: 2320905)
  - language_server (PID: 2489390)
  - language_server (PID: 2489390)  # duplicate
```

**Solution:** Implemented deduplication that:
- Groups processes by name
- Shows only unique process names
- Keeps container information separate
- Removes PID from display (only shows process name)

**Result:**
```
Processes:
  - windsurf
  - language_server
```

---

## Issue #2: curl Not Showing Up

**Problem:** Running `curl microsoft.com` doesn't appear in the process list.

**Root Cause:** **Race condition with short-lived processes**

### Why This Happens:

1. **curl** creates a connection and sends HTTP request
2. **Packet is captured** by Scapy
3. **Process tracker** tries to look up the socket in `/proc/net/tcp`
4. **curl has already closed** the connection and exited
5. **Socket no longer exists** in `/proc/net/tcp`
6. **Lookup fails** - no process info recorded

### Timeline:
```
Time 0ms:   curl starts, creates socket
Time 10ms:  curl sends SYN packet → Abnemo captures it
Time 15ms:  Abnemo tries to lookup socket in /proc/net/tcp
Time 12ms:  curl already received response and closed socket
Time 15ms:  Socket not found! (curl already exited)
```

### Solutions:

#### Option A: Accept the Limitation (Current)
- Short-lived processes like `curl`, `wget`, `ping` may be missed
- This is a fundamental limitation of post-capture process lookup
- Document this in README

#### Option B: Use eBPF (Advanced)
- Hook socket creation at kernel level
- Record PID → Socket mapping before packet is sent
- No race condition
- Requires eBPF support and more complex code

#### Option C: Increase Lookup Speed
- Optimize `/proc` scanning
- Use caching more aggressively
- Still won't catch all short-lived processes

**Recommendation:** Accept Option A and document it. For production monitoring, long-lived processes (browsers, servers, Docker containers) are more important than one-off curl commands.

---

## Issue #3: Docker Container Process Not Detected

**Problem:** Traffic from Docker container (Eagle Eye Networks) shows no process info:
```
3. IP: 216.245.88.137 [public]
   Domain: no domain name known
   ISP: Eagle Eye Networks, Inc (DE)
   Ports: 443 (HTTPS)
   Traffic: 14,430 bytes, 41 packets
```

### Possible Causes:

#### 1. **Network Mode Issue**
Docker containers can use different network modes:

- **Bridge mode** (default): Container has own IP, traffic goes through `docker-proxy`
  - Process will show as `docker-proxy` or `dockerd`
  - Container name can be resolved from cgroups

- **Host mode** (`--network host`): Container uses host network stack
  - Process shows as actual container process
  - Easier to detect

- **Overlay/Custom networks**: May use different routing
  - Harder to track

#### 2. **Timing Issue** (Same as curl)
- Container process creates connection
- Packet captured
- Socket already closed before lookup
- More likely with HTTP/HTTPS requests that complete quickly

#### 3. **Permission Issue**
- Abnemo running as root? ✓ (required for packet capture)
- Can read `/proc/net/tcp`? ✓ (should work)
- Can read `/proc/[pid]/fd`? ✓ (should work with root)
- Can read `/proc/[pid]/cgroup`? ✓ (should work with root)

### Debugging Steps:

1. **Check if container is actually running:**
   ```bash
   docker ps
   ```

2. **Find container's network mode:**
   ```bash
   docker inspect <container_name> | grep NetworkMode
   ```

3. **Check active connections from container:**
   ```bash
   # Get container PID
   docker inspect -f '{{.State.Pid}}' <container_name>
   
   # Check its network namespace
   sudo nsenter -t <PID> -n ss -tnp
   ```

4. **Use debug script:**
   ```bash
   sudo python3 test_process_lookup.py
   ```

5. **Enable debug logging in Abnemo:**
   Edit `packet_monitor.py` line 213, uncomment:
   ```python
   elif protocol and src_port:
       print(f"[DEBUG] Could not identify process for {src_ip}:{src_port} -> {dst_ip} ({protocol})")
   ```

### Likely Explanation:

The Eagle Eye Networks container is probably:
1. Using **bridge network mode**
2. Making **short-lived HTTPS connections** (like curl)
3. Connections complete in <10ms
4. Socket closes before Abnemo can look it up

### Solutions:

#### Immediate Fix:
Run the debug script to see what's actually happening:
```bash
sudo python3 test_process_lookup.py
```

Then while it's running, trigger the container to make a connection and immediately check:
```bash
# In another terminal
sudo ss -tnp | grep 216.245.88.137
```

#### Better Container Detection:
The improved Docker container name resolution (searching `/var/lib/docker/containers/`) should help, but only if we can catch the process while the socket is still open.

#### Alternative Approach:
Instead of tracking individual packets, track **established connections**:
```python
# Periodically scan /proc/net/tcp for ESTABLISHED connections
# Map them to processes
# Associate packets with those connections
```

This would catch longer-lived connections but still miss very short ones.

---

## Summary

| Issue | Status | Solution |
|-------|--------|----------|
| Duplicate processes | ✅ Fixed | Deduplication by process name |
| curl not showing | ⚠️ Limitation | Race condition with short-lived processes |
| Docker container missing | 🔍 Investigating | Likely same race condition issue |

## Recommendations

1. **Document the limitation** in README:
   - Process tracking works best for long-lived connections
   - Short-lived processes (curl, wget) may be missed
   - This is a fundamental limitation of post-capture lookup

2. **Add debug mode** for troubleshooting:
   - Enable with `--debug-process-tracking`
   - Logs when process lookup fails
   - Helps diagnose issues

3. **Consider eBPF** for future enhancement:
   - Eliminates race conditions
   - More complex but more reliable
   - Requires Linux 4.x+

4. **Test with the debug script:**
   ```bash
   sudo python3 test_process_lookup.py
   ```

## Testing Process Tracking

To verify process tracking works:

```bash
# Start a long-lived connection (browser, SSH, etc.)
firefox &

# Run Abnemo
sudo ./scripts/abnemo.sh monitor --enable-process-tracking --summary-interval 10

# Browse to a website
# You should see "firefox" in the process list

# For Docker containers:
docker run -d --name test-container nginx
docker exec test-container curl google.com

# You should see process info with container name
```
