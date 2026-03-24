# Running Abnemo as a Docker Container

> ⚠️ This has not been tested yet!

## Overview

**Yes, Abnemo can run as a Docker container to monitor the host's network traffic.** However, this requires special configuration because the container needs privileged access to the host's network stack and kernel features.

## Key Requirements

To monitor host network traffic from within a Docker container, Abnemo requires:

1. **Host network mode** (`--network host`) - Container shares the host's network namespace
2. **Privileged mode** (`--privileged`) - Required for:
   - Raw packet capture (Scapy)
   - eBPF program loading (BCC)
   - Access to `/proc` filesystem for process tracking
3. **Volume mounts** - For persistent logs and Docker socket access
4. **Kernel headers** - Must match the host kernel version

## Architecture Considerations

### What Works
- ✅ **Network packet capture** - Monitors all host network traffic
- ✅ **eBPF process tracking** - Identifies processes on the host
- ✅ **Docker container detection** - Can identify containers via Docker socket
- ✅ **Web interface** - Accessible from host or network
- ✅ **Persistent logs** - Stored on host filesystem

### Limitations
- ⚠️ **Kernel version dependency** - Container kernel headers must match host kernel
- ⚠️ **Security implications** - Requires privileged access (see Security section)
- ⚠️ **BCC installation** - Must be built for the specific host kernel
- ⚠️ **Process visibility** - Can only see host processes, not processes in other containers (unless using Docker socket)

## Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-scapy \
    python3-dnspython \
    python3-tabulate \
    python3-flask \
    python3-flask-wtf \
    python3-watchdog \
    python3-cryptography \
    python3-jwt \
    # eBPF/BCC dependencies
    python3-bpfcc \
    bpfcc-tools \
    linux-headers-generic \
    # Docker CLI for container detection
    docker.io \
    # Build tools for eBPF
    clang \
    llvm \
    # Utilities
    iproute2 \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY requirements.txt .
COPY src/ ./src/
COPY ebpf/ ./ebpf/
COPY templates/ ./templates/
COPY scripts/ ./scripts/
COPY port_mappings.txt .

# Install Python dependencies (in addition to system packages)
RUN pip3 install --no-cache-dir -r requirements.txt

# Create log directory
RUN mkdir -p /app/traffic_logs

# Make scripts executable
RUN chmod +x scripts/*.sh

# Expose web interface port
EXPOSE 5000

# Default command: run web server with monitoring
CMD ["python3", "src/abnemo.py", "monitor", "--web", "--web-port", "5000", "--summary-interval", "10"]
```

## Docker Compose Configuration

Create a `docker-compose.yml` for easier deployment:

```yaml
version: '3.8'

services:
  abnemo:
    build: .
    container_name: abnemo-monitor
    network_mode: host
    privileged: true
    volumes:
      # Persistent log storage
      - ./traffic_logs:/app/traffic_logs
      # Docker socket for container detection
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # Host /proc for process tracking
      - /proc:/host/proc:ro
      # Kernel headers (must match host kernel)
      - /usr/src:/usr/src:ro
      - /lib/modules:/lib/modules:ro
    environment:
      # Optional: IP-API pro key
      - IPAPI_KEY=${IPAPI_KEY:-}
      # Optional: OAuth configuration
      - ABSTRAUTH_CLIENT_ID=${ABSTRAUTH_CLIENT_ID:-}
      - ABSTRAUTH_CLIENT_SECRET=${ABSTRAUTH_CLIENT_SECRET:-}
      - ABSTRAUTH_AUTHORIZATION_ENDPOINT=${ABSTRAUTH_AUTHORIZATION_ENDPOINT:-}
      - ABSTRAUTH_TOKEN_ENDPOINT=${ABSTRAUTH_TOKEN_ENDPOINT:-}
      - ABSTRAUTH_REDIRECT_URI=${ABSTRAUTH_REDIRECT_URI:-}
      - ABSTRAUTH_WELLKNOWN_URI=${ABSTRAUTH_WELLKNOWN_URI:-}
      - ABSTRAUTH_REQUIRED_GROUPS=${ABSTRAUTH_REQUIRED_GROUPS:-}
      - ABSTRAUTH_COOKIE_SECURE=${ABSTRAUTH_COOKIE_SECURE:-false}
    restart: unless-stopped
    command: >
      python3 src/abnemo.py monitor
      --web
      --web-port 5000
      --summary-interval 10
      --continuous-log-interval 60
      --log-retention-days 7
      --top 20
```

## Building and Running

### Using Docker Compose (Recommended)

```bash
# Build the image
docker-compose build

# Start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### Using Docker CLI

```bash
# Build the image
docker build -t abnemo:latest .

# Run the container
docker run -d \
  --name abnemo-monitor \
  --network host \
  --privileged \
  -v $(pwd)/traffic_logs:/app/traffic_logs \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro \
  -v /usr/src:/usr/src:ro \
  -v /lib/modules:/lib/modules:ro \
  -e IPAPI_KEY="${IPAPI_KEY}" \
  abnemo:latest

# View logs
docker logs -f abnemo-monitor

# Stop the container
docker stop abnemo-monitor
docker rm abnemo-monitor
```

## Accessing the Web Interface

Once running, access the web interface at:

```
http://localhost:5000
```

Or from another machine on the network:

```
http://<host-ip>:5000
```

## Configuration Options

### Environment Variables

Pass these via `-e` flag or in `docker-compose.yml`:

| Variable | Description | Default |
|----------|-------------|---------|
| `IPAPI_KEY` | IP-API.com pro API key | None (uses free tier) |
| `ABSTRAUTH_CLIENT_ID` | OAuth client ID | None (no auth) |
| `ABSTRAUTH_CLIENT_SECRET` | OAuth client secret | None |
| `ABSTRAUTH_AUTHORIZATION_ENDPOINT` | OAuth authorization URL | None |
| `ABSTRAUTH_TOKEN_ENDPOINT` | OAuth token URL | None |
| `ABSTRAUTH_REDIRECT_URI` | OAuth callback URL | None |
| `ABSTRAUTH_WELLKNOWN_URI` | OAuth well-known configuration URL | None |
| `ABSTRAUTH_REQUIRED_GROUPS` | Required user groups | None |

### Command Line Arguments

Override the default command in `docker-compose.yml` or when running:

```bash
docker run ... abnemo:latest python3 src/abnemo.py monitor \
  --web \
  --web-port 5000 \
  --summary-interval 30 \
  --continuous-log-interval 120 \
  --log-retention-days 14 \
  --top 50 \
  --traffic-direction bidirectional
```

Available options:
- `--summary-interval N` - Print summary every N seconds
- `--continuous-log-interval N` - Save logs every N seconds (0=disabled)
- `--log-retention-days N` - Delete logs older than N days
- `--log-max-size-mb N` - Delete oldest logs if total exceeds N MB
- `--top N` - Show top N destinations in summaries
- `--traffic-direction MODE` - `outgoing`, `incoming`, `bidirectional`, or `all`
- `--log-level LEVEL` - `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

## Security Considerations

### Privileged Mode Risks

Running with `--privileged` grants the container extensive host access:

- ✅ **Necessary for**: Packet capture, eBPF, kernel module loading
- ⚠️ **Security risk**: Container can potentially compromise the host
- 🛡️ **Mitigation strategies**:
  1. Run on trusted, isolated monitoring hosts
  2. Use read-only mounts where possible
  3. Implement network segmentation
  4. Enable OAuth authentication for web interface
  5. Use firewall rules to restrict web interface access
  6. Regularly update the container image
  7. Monitor container logs for suspicious activity

### Recommended Security Hardening

```yaml
services:
  abnemo:
    # ... other config ...
    
    # Read-only root filesystem (if possible)
    read_only: true
    tmpfs:
      - /tmp
      - /app/traffic_logs  # Or use volume
    
    # Drop unnecessary capabilities (if not using --privileged)
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_ADMIN  # Required for eBPF
      - SYS_RESOURCE
    
    # Security options
    security_opt:
      - apparmor:unconfined  # Required for eBPF
      - seccomp:unconfined   # Required for eBPF
    
    # Limit resources
    mem_limit: 2g
    cpus: 2
```

**Note**: Some security restrictions are incompatible with eBPF. The `--privileged` flag is the most reliable approach.

### OAuth Authentication

For production deployments, enable OAuth:

```bash
# Set environment variables
export ABSTRAUTH_CLIENT_ID="abnemo-monitor"
export ABSTRAUTH_CLIENT_SECRET="<secret>"
export ABSTRAUTH_AUTHORIZATION_ENDPOINT="https://auth.example.com/oauth2/authorize"
export ABSTRAUTH_TOKEN_ENDPOINT="https://auth.example.com/oauth2/token"
export ABSTRAUTH_REDIRECT_URI="https://monitor.example.com/oauth/callback"
export ABSTRAUTH_WELLKNOWN_URI="https://auth.example.com/.well-known/oauth-authorization-server"
export ABSTRAUTH_REQUIRED_GROUPS="abnemo_admins,abnemo_viewers"
export ABSTRAUTH_COOKIE_SECURE=true

# Run with docker-compose
docker-compose up -d
```

## Troubleshooting

### eBPF Not Working

**Symptom**: Error loading eBPF program

**Solutions**:
1. Verify kernel headers match host kernel:
   ```bash
   # On host
   uname -r
   
   # In container
   docker exec abnemo-monitor uname -r
   ```

2. Install matching kernel headers:
   ```bash
   # On host
   sudo apt install linux-headers-$(uname -r)
   ```

3. Rebuild container with correct headers:
   ```dockerfile
   # In Dockerfile, use host kernel version
   RUN apt-get install -y linux-headers-$(uname -r)
   ```

### Permission Denied Errors

**Symptom**: Cannot capture packets or load eBPF

**Solution**: Ensure `--privileged` flag is set:
```bash
docker run --privileged ...
```

### Container Detection Not Working

**Symptom**: Cannot identify Docker containers in traffic

**Solution**: Mount Docker socket:
```bash
-v /var/run/docker.sock:/var/run/docker.sock:ro
```

### High Memory Usage

**Symptom**: Container consumes excessive memory

**Solutions**:
1. Reduce log retention:
   ```bash
   --log-retention-days 3 --log-max-size-mb 50
   ```

2. Limit container memory:
   ```yaml
   mem_limit: 1g
   ```

3. Increase log save interval:
   ```bash
   --continuous-log-interval 300  # 5 minutes
   ```

### Web Interface Not Accessible

**Symptom**: Cannot access http://localhost:5000

**Solutions**:
1. Verify container is running:
   ```bash
   docker ps | grep abnemo
   ```

2. Check logs:
   ```bash
   docker logs abnemo-monitor
   ```

3. Ensure host network mode:
   ```bash
   docker inspect abnemo-monitor | grep NetworkMode
   # Should show "host"
   ```

4. Check firewall rules:
   ```bash
   sudo ufw status
   sudo iptables -L -n | grep 5000
   ```

## Alternative: Docker-less Deployment

If Docker's privileged requirements are unacceptable, consider:

1. **Native installation** on the host (see main README.md)
2. **Systemd service** for automatic startup
3. **Dedicated monitoring VM** with Abnemo installed natively

## Production Deployment Checklist

- [ ] Enable OAuth authentication
- [ ] Set `ABSTRAUTH_COOKIE_SECURE=true` (requires HTTPS)
- [ ] Configure firewall to restrict web interface access
- [ ] Set appropriate log retention policies
- [ ] Configure resource limits (CPU, memory)
- [ ] Set up log rotation and monitoring
- [ ] Enable HTTPS with reverse proxy (nginx, Caddy)
- [ ] Implement backup strategy for traffic logs
- [ ] Document incident response procedures
- [ ] Schedule regular security updates
- [ ] Monitor container health and resource usage

## Example Production Setup with Nginx Reverse Proxy

```yaml
# docker-compose.yml
version: '3.8'

services:
  abnemo:
    build: .
    container_name: abnemo-monitor
    network_mode: host
    privileged: true
    volumes:
      - ./traffic_logs:/app/traffic_logs
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /proc:/host/proc:ro
      - /usr/src:/usr/src:ro
      - /lib/modules:/lib/modules:ro
    environment:
      - IPAPI_KEY=${IPAPI_KEY}
      - ABSTRAUTH_CLIENT_ID=${ABSTRAUTH_CLIENT_ID}
      - ABSTRAUTH_CLIENT_SECRET=${ABSTRAUTH_CLIENT_SECRET}
      - ABSTRAUTH_AUTHORIZATION_ENDPOINT=${ABSTRAUTH_AUTHORIZATION_ENDPOINT}
      - ABSTRAUTH_TOKEN_ENDPOINT=${ABSTRAUTH_TOKEN_ENDPOINT}
      - ABSTRAUTH_REDIRECT_URI=https://monitor.example.com/oauth/callback
      - ABSTRAUTH_WELLKNOWN_URI=https://auth.example.com/.well-known/oauth-authorization-server
      - ABSTRAUTH_REQUIRED_GROUPS=abnemo_admins
      - ABSTRAUTH_COOKIE_SECURE=true
    restart: unless-stopped
    command: >
      python3 src/abnemo.py monitor
      --web
      --web-port 5000
      --summary-interval 10
      --continuous-log-interval 60
      --log-retention-days 30
      --log-level INFO

  nginx:
    image: nginx:alpine
    container_name: abnemo-nginx
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - abnemo
    restart: unless-stopped
```

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream abnemo {
        server localhost:5000;
    }

    server {
        listen 80;
        server_name monitor.example.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name monitor.example.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            proxy_pass http://abnemo;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

## Conclusion

Abnemo can successfully run as a Docker container to monitor host network traffic, but requires:

1. **Privileged mode** for kernel-level access
2. **Host network mode** to see host traffic
3. **Proper volume mounts** for logs and Docker socket
4. **Matching kernel headers** for eBPF support

This approach is suitable for:
- ✅ Dedicated monitoring hosts
- ✅ Development/testing environments
- ✅ Isolated network segments
- ✅ Environments with strong container security policies

For maximum security, consider native installation on a dedicated monitoring host instead of containerization.
