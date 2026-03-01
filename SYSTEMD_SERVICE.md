# Installing Abnemo as a Systemd Service

This guide explains how to install and configure Abnemo as a systemd service that automatically starts on boot and restarts on failure.

## Prerequisites

- Root/sudo access
- Abnemo installed in `/opt/abnemo` (or adjust paths accordingly)
- Python 3 and all dependencies installed

## Installation Steps

### 1. Create Service User (Optional but Recommended)

Create a dedicated user for running the service:

```bash
sudo useradd -r -s /bin/false -d /opt/abnemo abnemo
```

### 2. Install Abnemo to System Location

```bash
# Create installation directory
sudo mkdir -p /opt/abnemo
sudo mkdir -p /var/log/abnemo
sudo mkdir -p /var/lib/abnemo/traffic_logs

# Copy files (run from the project root)
sudo cp -r * /opt/abnemo/

# Set ownership
sudo chown -R abnemo:abnemo /opt/abnemo
sudo chown -R abnemo:abnemo /var/log/abnemo
sudo chown -R abnemo:abnemo /var/lib/abnemo

# Make scripts executable
sudo chmod +x /opt/abnemo/abnemo.py
sudo chmod +x /opt/abnemo/abnemo.sh
```

### 3. Create Systemd Service File

Create `/etc/systemd/system/abnemo.service`:

```ini
[Unit]
Description=Abnemo Network Traffic Monitor
After=network.target
Documentation=https://github.com/yourusername/abnemo

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/abnemo

# Main command - adjust parameters as needed
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --web \
    --web-port 5000 \
    --isp-cache-ttl 72 \
    --enable-process-tracking \
    --continuous-log-interval 60 \
    --log-retention-days 30 \
    --log-max-size-mb 500

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Resource limits (optional)
MemoryLimit=512M
CPUQuota=50%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=abnemo

# Security hardening (optional - may need adjustment)
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/abnemo /var/log/abnemo /opt/abnemo

# Environment
Environment="PYTHONUNBUFFERED=1"
Environment="IPAPI_KEY="

[Install]
WantedBy=multi-user.target
```

**Note:** The service runs as `root` because packet capture requires root privileges. If using eBPF mode, this is mandatory.

### 4. Create Environment File (Optional)

For sensitive configuration like API keys, create `/etc/abnemo/abnemo.env`:

```bash
sudo mkdir -p /etc/abnemo
sudo nano /etc/abnemo/abnemo.env
```

Add:
```bash
IPAPI_KEY=your_api_key_here
```

Then update the service file to include:
```ini
EnvironmentFile=/etc/abnemo/abnemo.env
```

### 5. Enable and Start Service

```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable abnemo

# Start service now
sudo systemctl start abnemo

# Check status
sudo systemctl status abnemo
```

## Service Management Commands

```bash
# Start service
sudo systemctl start abnemo

# Stop service
sudo systemctl stop abnemo

# Restart service
sudo systemctl restart abnemo

# Check status
sudo systemctl status abnemo

# View logs (real-time)
sudo journalctl -u abnemo -f

# View logs (last 100 lines)
sudo journalctl -u abnemo -n 100

# View logs since boot
sudo journalctl -u abnemo -b

# Disable auto-start on boot
sudo systemctl disable abnemo
```

## Configuration Options

Edit `/etc/systemd/system/abnemo.service` and modify the `ExecStart` line:

### Basic Monitoring (No Web Interface)
```bash
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --continuous-log-interval 60
```

### With Web Interface
```bash
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --web \
    --web-port 5000 \
    --continuous-log-interval 60
```

### With eBPF (Zero-Overhead Process Tracking)
```bash
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --web \
    --web-port 5000 \
    --ebpf \
    --continuous-log-interval 60
```

### With ISP Lookup and Debug
```bash
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --web \
    --web-port 5000 \
    --enable-process-tracking \
    --isp-cache-ttl 72 \
    --isp-debug \
    --continuous-log-interval 60
```

After changing configuration:
```bash
sudo systemctl daemon-reload
sudo systemctl restart abnemo
```

## Automatic Restart Configuration

The service is configured to automatically restart on failure:

- **Restart=always**: Restart on any exit (success or failure)
- **RestartSec=10**: Wait 10 seconds before restarting
- **StartLimitInterval=200**: Track restart attempts over 200 seconds
- **StartLimitBurst=5**: Allow max 5 restarts in the interval

This means if the service crashes, it will:
1. Wait 10 seconds
2. Attempt to restart
3. If it crashes 5 times in 200 seconds, systemd will give up
4. You can manually restart it with `sudo systemctl restart abnemo`

To reset the restart counter:
```bash
sudo systemctl reset-failed abnemo
```

## Monitoring Service Health

### Check if service is running
```bash
sudo systemctl is-active abnemo
```

### Check if service is enabled
```bash
sudo systemctl is-enabled abnemo
```

### View service resource usage
```bash
sudo systemctl status abnemo
```

### View detailed logs with timestamps
```bash
sudo journalctl -u abnemo --since "1 hour ago" -o verbose
```

## Troubleshooting

### Service won't start
```bash
# Check logs for errors
sudo journalctl -u abnemo -n 50

# Check service file syntax
sudo systemd-analyze verify abnemo.service

# Test command manually
sudo /usr/bin/python3 /opt/abnemo/abnemo.py monitor --log-dir /var/lib/abnemo/traffic_logs --web
```

### Permission errors
```bash
# Ensure proper ownership
sudo chown -R abnemo:abnemo /var/lib/abnemo
sudo chown -R abnemo:abnemo /var/log/abnemo

# Or if running as root
sudo chown -R root:root /var/lib/abnemo
```

### Web interface not accessible
```bash
# Check if port is listening
sudo ss -tlnp | grep 5000

# Check firewall
sudo ufw status
sudo ufw allow 5000/tcp

# Check logs
sudo journalctl -u abnemo -f
```

### High memory usage
Adjust in service file:
```ini
MemoryLimit=1G
```

### Service keeps restarting
```bash
# View crash logs
sudo journalctl -u abnemo --since "10 minutes ago"

# Check system resources
free -h
df -h
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop abnemo
sudo systemctl disable abnemo

# Remove service file
sudo rm /etc/systemd/system/abnemo.service

# Reload systemd
sudo systemctl daemon-reload

# Remove installation (optional)
sudo rm -rf /opt/abnemo
sudo rm -rf /var/lib/abnemo
sudo rm -rf /var/log/abnemo
sudo rm -rf /etc/abnemo

# Remove user (optional)
sudo userdel abnemo
```

## Integration with Nginx (Optional)

To expose the web interface through Nginx with SSL:

Create `/etc/nginx/sites-available/abnemo`:

```nginx
server {
    listen 80;
    server_name abnemo.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and reload:
```bash
sudo ln -s /etc/nginx/sites-available/abnemo /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

For SSL with Let's Encrypt:
```bash
sudo certbot --nginx -d abnemo.yourdomain.com
```

## Best Practices

1. **Regular log rotation**: Systemd journal handles this automatically, but monitor disk usage
2. **Monitor service health**: Set up alerts for service failures
3. **Backup configuration**: Keep `/etc/systemd/system/abnemo.service` in version control
4. **Security**: Run with minimal required privileges, use firewall rules
5. **Resource limits**: Set appropriate memory/CPU limits for your system
6. **ISP cache**: Use longer TTL (72h) to reduce API calls
7. **Log retention**: Adjust `--log-retention-days` based on disk space

## Example: Production Setup

```bash
# Install
sudo cp -r . /opt/abnemo
sudo mkdir -p /var/lib/abnemo/traffic_logs

# Create service
sudo tee /etc/systemd/system/abnemo.service > /dev/null <<'EOF'
[Unit]
Description=Abnemo Network Traffic Monitor
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/abnemo
ExecStart=/usr/bin/python3 /opt/abnemo/abnemo.py monitor \
    --log-dir /var/lib/abnemo/traffic_logs \
    --web \
    --web-port 5000 \
    --ebpf \
    --isp-cache-ttl 72 \
    --continuous-log-interval 60 \
    --log-retention-days 30 \
    --log-max-size-mb 1000
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable abnemo
sudo systemctl start abnemo

# Verify
sudo systemctl status abnemo
```

Access web interface at `http://your-server-ip:5000`
