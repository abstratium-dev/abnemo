# Docker Enrichment for iptables Visualizer

The iptables visualizer now includes **automatic Docker enrichment** to help you understand how packets flow through Docker containers and networks.

## Features

### 🐳 Container Detection
- **Automatic container discovery**: Finds all running and stopped containers
- **IP-to-container mapping**: Shows container names instead of IP addresses
- **Network association**: Displays which Docker network each container is on

### 🐋 Network Identification
- **Docker network detection**: Identifies `docker0`, `br-*`, and `veth*` interfaces
- **Network naming**: Shows friendly network names (e.g., "bridge", "my-app-network")
- **Subnet mapping**: Maps IP ranges to Docker networks

### 🏠 Special IP Range Detection
- **Private networks**: Identifies 10.x, 172.16-31.x, 192.168.x ranges
- **Loopback**: Marks 127.0.0.1 and ::1
- **Link-local**: Detects 169.254.x.x addresses
- **Multicast**: Identifies multicast addresses

## How It Works

The enrichment happens automatically when you visualize iptables rules:

1. **Docker inspection**: Queries Docker for containers and networks
2. **IP mapping**: Maps container IPs to container names
3. **Interface detection**: Identifies Docker bridge interfaces
4. **Rule enrichment**: Enhances iptables rules with Docker context

## Example Enrichments

### Before Enrichment
```
✅ Allow
proto: TCP, to: 172.23.0.10, in: !br-48b7a6d85e30, out: br-48b7a6d85e30, dport: 5000
```

### After Enrichment
```
✅ Allow
proto: TCP, to: 🐳 lucidlink-mock, in: NOT 🐋 from-manou-20251001_checkmk-network, 
out: 🐋 from-manou-20251001_checkmk-network, dport: 5000
```

## Enrichment Symbols

- **🐳** Container (e.g., `🐳 my-app`)
- **🐋** Docker network (e.g., `🐋 bridge`, `🐋 my-network`)
- **🌉** Gateway (e.g., `🌉 Gateway (bridge)`)
- **🏠** Private IP range (e.g., `🏠 Private (10.x)`)
- **🔁** Loopback (e.g., `🔁 Loopback`)
- **🔌** Ethernet interface
- **📶** WiFi interface
- **🔒** VPN interface

## Understanding Docker Packet Flow

### Common Docker Rules

#### 1. Container-to-Internet
```
✅ Allow
from: 🐳 my-container, in: 🐋 bridge, out: NOT 🐋 bridge
```
Traffic from a container going to the internet (leaving Docker network).

#### 2. Internet-to-Container
```
✅ Allow
to: 🐳 my-container, in: NOT 🐋 bridge, out: 🐋 bridge, dport: 80 (HTTP)
```
Incoming traffic to a published container port.

#### 3. Container-to-Container (Same Network)
```
✅ Allow
in: 🐋 bridge, out: 🐋 bridge
```
Traffic between containers on the same Docker network.

#### 4. Container-to-Container (Different Networks)
```
✅ Allow
from: 🐳 app, to: 🐳 database, in: 🐋 app-network, out: 🐋 db-network
```
Traffic between containers on different networks (requires routing).

## Usage

### Web Interface
The enrichment is **automatic** when using the web interface:
1. Visit `http://your-server:17999/iptables`
2. Click "Load Local iptables Rules"
3. Docker information is automatically included

### Command Line
```bash
# Generate visualization with Docker enrichment (default)
sudo python3 iptables_visualizer.py

# Disable Docker enrichment
sudo python3 iptables_visualizer.py --no-docker-enrichment
```

### API
```bash
# GET endpoint includes Docker enrichment by default
curl http://localhost:17999/api/iptables/visualize

# POST endpoint for custom configs (no Docker enrichment)
curl -X POST http://localhost:17999/api/iptables/visualize/custom \
  -H "Content-Type: application/json" \
  -d '{"config": "..."}'
```

## Requirements

- **Docker installed**: The enrichment requires Docker to be installed
- **Docker access**: User must have permission to run `docker` commands
- **Running Docker daemon**: Docker service must be running

If Docker is not available, the visualizer still works but without enrichment.

## Troubleshooting

### No Docker Enrichment Showing

1. **Check Docker is running**:
   ```bash
   docker ps
   ```

2. **Check permissions**:
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   # Log out and back in
   ```

3. **Verify containers are running**:
   ```bash
   docker ps -a
   ```

### Partial Enrichment

- **Container IPs only show for running containers**: Stopped containers are discovered but may not have IPs
- **Network names may be truncated**: Very long network names are shown in full in tooltips
- **Custom networks**: Only networks created with `docker network create` are detected

## Technical Details

### Container Discovery
```python
# Containers are discovered via:
docker ps -a --format '{{json .}}'
docker inspect <container_id>
```

### Network Discovery
```python
# Networks are discovered via:
docker network ls --format '{{json .}}'
docker network inspect <network_id>
```

### IP-to-Container Mapping
- Reads `NetworkSettings.Networks` from container inspect
- Maps each IP address to container name and network
- Caches results for performance

### Interface Detection
- Pattern matching: `docker0`, `br-[a-f0-9]{12}`, `veth[a-f0-9]+`
- Network ID extraction from bridge names
- Fallback to "Docker" label if network name not found

## Performance

- **Initial load**: ~1-2 seconds to query Docker
- **Caching**: Results are cached for the duration of visualization
- **No impact on iptables**: Docker queries are separate from iptables parsing

## Privacy & Security

- **Local only**: Docker information is queried locally, never sent externally
- **Read-only**: Only reads Docker information, never modifies containers or networks
- **No credentials**: Uses existing Docker socket permissions
- **Optional**: Can be disabled with `--no-docker-enrichment` flag

## Examples

### Visualizing Docker Firewall Rules

```bash
# 1. Check your Docker containers
docker ps

# 2. Check iptables rules
sudo iptables -L -v -n | grep docker

# 3. Visualize with enrichment
sudo python3 iptables_visualizer.py -o docker-firewall.html

# 4. Open in browser
firefox docker-firewall.html
```

### Understanding Container Isolation

Look for rules like:
```
✅ Allow
in: 🐋 network-a, out: 🐋 network-a
```
This shows containers on `network-a` can communicate with each other.

```
❌ Block
from: 🐋 network-a, to: 🐋 network-b
```
This shows isolation between networks.

## Future Enhancements

Planned features:
- [ ] Kubernetes pod detection
- [ ] Docker Compose service grouping
- [ ] Container health status indicators
- [ ] Port mapping visualization
- [ ] Volume mount detection
- [ ] Network policy visualization
