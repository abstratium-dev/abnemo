# Docker Container Tracking in eBPF Mode

## Overview

The eBPF monitor now automatically identifies and displays Docker container names for processes running inside containers.

## How It Works

### 1. eBPF Captures Process Info
```c
// In network_monitor.c
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid >> 32;
bpf_get_current_comm(&event.comm, sizeof(event.comm));
event.cgroup_id = bpf_get_current_cgroup_id();
```

### 2. Container Identification (Python)

The monitor uses two methods to identify containers:

**Method 1: cgroup_id lookup**
- Searches `/sys/fs/cgroup` for Docker cgroup directories
- Extracts container ID from paths like `docker-<container_id>.scope`

**Method 2: PID-based lookup (fallback)**
- Reads `/proc/<pid>/cgroup` for the process
- Looks for Docker-specific cgroup paths:
  - systemd format: `/system.slice/docker-<container_id>.scope`
  - cgroupfs format: `/docker/<container_id>`
- Extracts container ID from the path

**Method 3: Docker inspect**
- Uses `docker inspect --format={{.Name}} <container_id>`
- Converts container ID to human-readable name

### 3. Display Format

```
8. IP: 216.245.88.137 [public]
   Domain: no domain name known
   ISP: Eagle Eye Networks, Inc (DE)
   Process: my-container (container)
   Ports: 443 (HTTPS)
   Traffic: 64 bytes, 1 packets
```

Or with image info:
```
   Process: web-server (image: nginx:latest)
```

## Example Output

### Before (without container tracking):
```
Process: python3
```

### After (with container tracking):
```
Process: my-app-container (container)
```

## Requirements

1. **Docker CLI access**: The monitor needs to run `docker inspect`
2. **Root privileges**: Already required for eBPF
3. **Access to /proc and /sys/fs/cgroup**: Standard on Linux

## Caching

Container lookups are cached to minimize overhead:
- First lookup: ~10-50ms (Docker inspect call)
- Subsequent lookups: <1ms (cache hit)
- Cache persists for the monitoring session

## Limitations

1. **Docker only**: Currently only supports Docker containers, not:
   - Podman
   - containerd (without Docker)
   - LXC/LXD
   - Other container runtimes

2. **Process must still exist**: If the process exits before lookup, container name may not be resolved

3. **Docker socket access**: Requires Docker CLI to be accessible

## Troubleshooting

### Container name shows as "python3" instead of container name

**Possible causes:**
1. Process exited before lookup
2. Docker CLI not accessible
3. Container not running via Docker

**Debug:**
```bash
# Check if process is in a container
cat /proc/<pid>/cgroup | grep docker

# Check Docker access
docker ps

# Check container exists
docker inspect <container_id>
```

### "Permission denied" when accessing Docker

**Solution:** Ensure the user running the monitor has Docker access:
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Or run with sudo (already required for eBPF)
sudo ./abnemo.sh monitor --ebpf
```

## Performance Impact

- **Negligible**: Container lookups are cached
- **First connection per container**: ~10-50ms overhead
- **Subsequent connections**: <1ms (cache hit)
- **No impact on packet capture**: Lookup happens after eBPF event

## Code Location

- **eBPF C code**: `ebpf/network_monitor.c` (captures cgroup_id)
- **Python loader**: `ebpf/ebpf_loader.py` (passes cgroup_id to callback)
- **Container resolution**: `ebpf_monitor.py` (identifies container from cgroup/PID)
- **Display logic**: `packet_monitor.py` (formats output)
