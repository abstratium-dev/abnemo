# Abnemo - Network Traffic Monitor & IPTables Rule Generator

A Linux-based network traffic monitoring and security tool that uses eBPF for kernel-level packet capture, tracks processes and containers, performs reverse DNS lookups, logs data usage by IP address, and provides comprehensive network visibility with iptables integration.

## Features

### Core Monitoring
- **eBPF-based packet capture** - Kernel-level monitoring with near-zero overhead (IPv4 and IPv6)
- **Process and container tracking** - Identifies which program/container sent each packet using eBPF hooks
- **Configurable traffic direction**: outgoing (default), incoming (unsolicited), bidirectional (with responses), or all traffic
- **Real-time statistics** - Track bytes, packets, and ports per destination IP
- **Periodic summaries** - Configurable interval reporting during monitoring
- **Continuous monitoring** - Automatic log rotation with retention policies

### Network Intelligence
- **Reverse DNS lookups** - Identify destination domains for all IPs
- **ISP identification** - Using ip-api.com (free tier or pro with API key)
- **IP classification** - Multicast, private, public, reserved (IPv4 and IPv6)
- **Port mapping** - Human-readable descriptions for common ports
- **Docker enrichment** - Container name and ID resolution

### Web Interface & Security
- **Live web dashboard** - Beautiful real-time traffic visualization with time-range filtering
- **OAuth 2.0 authentication** - Secure access with Abstrauth integration (BFF pattern)
- **Accept-list filters** - Hide known-good traffic from the interface
- **Warn-list filters** - Highlight suspicious traffic with email alerts
- **Role-based access control** - Group-based authorization for monitoring data

### IPTables Integration
- **iptables tree visualization** - View firewall configuration as hierarchical tree
- **Docker-aware filtering** - Show only Docker-related chains and rules
- **Rule generation** - Create block/unblock scripts from captured traffic
- **Interactive mode** - Manually select IPs to block
- **Automatic blocking** - Set thresholds to auto-block high-traffic destinations

### fail2ban Integration
- **Configuration visualization** - Parse and display fail2ban setup
- **Mermaid diagram generation** - Visual representation of jails and filters
- **Web endpoints** - API access to fail2ban status

### Additional Features
- **IP ban management** - Dedicated endpoints for managing blocked IPs
- **JSON logging** - Detailed traffic logs for later analysis
- **Log retention policies** - Automatic cleanup based on age and size
- **Full IPv6 support** - Alongside IPv4 throughout the stack

## Requirements

- Linux operating system
- Python 3.7+
- Root/sudo privileges (required for packet capture)
- iptables (for applying firewall rules)
- ufw (for baning / unbaning IP addresses)
- fail2ban (optional, if present, unbaning will also remove temporary fail2ban rules)

## Installation

### Automated Installation (Ubuntu)

For Ubuntu systems, you can use the automated installation script that sets up Abnemo as a systemd service:

```bash
# Download and run the installation script
wget https://raw.githubusercontent.com/abstratium-dev/abnemo/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

The script will:
- Install all system dependencies
- Clone the repository to `/opt/abnemo`
- Build the eBPF program
- Prompt for OAuth and SMTP configuration
- Create a systemd service that starts on boot
- Start the service immediately

After installation, the web interface will be available at `http://localhost:40002`

### Manual Installation (One-time setup)

BCC must be installed via system package manager (not available in conda). So if necessary, first disable conda:

```bash
# If using conda, deactivate first
conda deactivate
```

Next, install dependencies:

```bash
# 1. Install dependencies
# System packages (recommended if using system Python)
# Ubuntu/Debian
sudo apt install python3-scapy python3-dnspython python3-tabulate python3-bpfcc python3-flask python3-flaskext.wtf python3-watchdog python3-cryptography python3-jwt python3-debugpy python3-flask-limiter

# Fedora/RHEL
sudo dnf install python3-scapy python3-dns python3-tabulate python3-bcc python3-flask python3-flask-wtf python3-watchdog python3-cryptography python3-jwt python3-debugpy python3-flask-limiter

# 2. Build eBPF program
sudo ./scripts/build_ebpf.sh 

# 3. Make wrapper script executable
chmod +x abnemo.sh

# 4. Set up IP-API (pro) key for (unlimited) ISP lookups
export IPAPI_KEY=your_api_key_here
# Or add to ~/.bashrc for persistence
```

## Usage

### 1. Monitor Network Traffic

Production mode with web server for configuration and monitoring, max 30 day log retention / 100 MB:

```bash
sudo ./scripts/abnemo.sh monitor --web --web-port 40002 --log-level WARNING
```

Note that email notification and OAuth security are enabled using environment variables. See further below.

Development mode with web server:

```bash
sudo ./scripts/abnemo.sh monitor --summary-interval 10 --top 9999 --web --web-port 40002 --log-level DEBUG
```

### Debugging

To attach a Python debugger, use the `--debug-process` parameter with a port number (e.g., `sudo ./scripts/abnemo.sh --debug-process 5678 monitor`).

Capture outgoing network traffic as a command line interface:

```bash
# Using wrapper script (recommended)
sudo ./scripts/abnemo.sh monitor

# Monitor for 60 seconds
./scripts/abnemo.sh monitor --duration 60

# Monitor with periodic summaries every 10 seconds
./scripts/abnemo.sh monitor --summary-interval 10

# Monitor specific network interface with summaries
./scripts/abnemo.sh monitor --interface eth0 --summary-interval 10

# Show top 50 destinations in final summary
./scripts/abnemo.sh monitor --top 50

# Continuous monitoring with automatic log rotation
./scripts/abnemo.sh monitor --summary-interval 10 --continuous-log-interval 60

# Custom log retention (keep 7 days, max 50MB)
./scripts/abnemo.sh monitor --log-retention-days 7 --log-max-size-mb 50

# Monitor with live web interface for real-time visualization
./scripts/abnemo.sh monitor --summary-interval 10
```

#### Logging Levels

Abnemo uses Python's standard logging framework. You can control the verbosity of output using the `--log-level` flag:

```bash
# INFO (default) - Shows important events and progress
./scripts/abnemo.sh monitor --log-level INFO

# DEBUG - Shows detailed diagnostic information (ISP lookups, cache hits/misses, email sending, etc.)
./scripts/abnemo.sh monitor --log-level DEBUG

# WARNING - Shows only warnings and errors
./scripts/abnemo.sh monitor --log-level WARNING

# ERROR - Shows only errors
./scripts/abnemo.sh monitor --log-level ERROR

# CRITICAL - Shows only critical errors
./scripts/abnemo.sh monitor --log-level CRITICAL
```

#### Traffic Filtering System

Abnemo provides two types of filters for managing traffic visibility and alerts:

**Accept-List Filters** (Hide matching traffic):
- Hide known-good traffic from the web interface
- Useful for filtering out routine connections (local network, DNS, etc.)
- Prevents email notifications for accepted traffic

**Warn-List Filters** (Highlight and alert on matching traffic):
- Highlight suspicious or important traffic in the web interface
- Trigger email notifications when matches are detected
- **Important:** Email notifications are NOT sent if traffic also matches any accept-list filter

**Email Configuration:**
```bash
export ABNEMO_SMTP_HOST=smtp.example.com
export ABNEMO_SMTP_PORT=587
export ABNEMO_SMTP_USERNAME=your_username
export ABNEMO_SMTP_PASSWORD=your_password
export ABNEMO_SMTP_FROM=abnemo@example.com
export ABNEMO_SMTP_TO=admin@example.com
export ABNEMO_SMTP_TLS=true
```

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
./scripts/abnemo.sh monitor --continuous-log-interval 60

# Run with custom retention
./scripts/abnemo.sh monitor --log-retention-days 7 --log-max-size-mb 50

# Disable continuous logging (only save on exit)
./scripts/abnemo.sh monitor --continuous-log-interval 0
```

#### Process Tracking with eBPF

Abnemo uses **eBPF (Extended Berkeley Packet Filter)** for kernel-level process tracking with near-zero overhead.

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

### Why eBPF?

**Benefits:**
- ✅ **Catches ALL processes** - even short-lived ones (curl, wget, ping)
- ✅ **Near-zero overhead** - runs in kernel space (<0.1ms per connection)
- ✅ **Complete visibility** - detects rogue scripts, crypto miners, scanners
- ✅ **Docker tracking** - identifies containers without IP fallback
- ✅ **Real-time** - captures process info before packet is sent

**How it works:**
1. **Kernel hooks**: Attaches to `tcp_sendmsg()`, `udp_sendmsg()`, `tcp_connect()`
2. **Pre-capture**: Extracts PID, process name, cgroup **before** packet is sent
3. **No race condition**: Process info captured even if process exits in 1ms
4. **Zero overhead**: Runs in kernel space, minimal CPU usage
5. **Complete visibility**: Catches ALL network activity, even brief connections

---

## eBPF Setup

### Requirements

- Linux kernel 4.x or higher (5.x recommended)
- BCC (BPF Compiler Collection) installed
- Root privileges (required for packet capture)
- BPF enabled in kernel (usually default)

### Troubleshooting

**Error: "BCC not found"**
```bash
# Ubuntu/Debian
sudo apt install python3-bpfcc

# Fedora/RHEL
sudo dnf install python3-bcc
```

**Error: "Kernel too old"**
```bash
uname -r  # Check version (need 4.x+)
```

**Error: "Permission denied"**
```bash
# eBPF requires root
sudo python3 src/abnemo.py monitor --ebpf
```

## Securing the Web UI with Abstrauth (OAuth 2.0 BFF)

The live dashboard can require sign-in via Abstrauth (https://github.com/abstratium-dev/abstrauth) using the **Backend-For-Frontend (BFF)** pattern. When OAuth is configured, the backend negotiates Authorization Code + PKCE on behalf of the browser, stores tokens server-side, and issues only HTTP-only session cookies. Tokens, PKCE parameters, and client secrets never reach the frontend.

### Required Environment Variables

Set these before starting `./scripts/abnemo.sh monitor --web`. Authentication gates activate automatically once all required fields are present.

| Variable | Required | Description |
|----------|----------|-------------|
| `ABSTRAUTH_CLIENT_ID` | ✅ | OAuth confidential client ID registered in Abstrauth |
| `ABSTRAUTH_CLIENT_SECRET` | ✅ | Client secret paired with the client ID |
| `ABSTRAUTH_AUTHORIZATION_ENDPOINT` | ✅ | Full URL to Abstrauth's `/oauth2/authorize` endpoint |
| `ABSTRAUTH_TOKEN_ENDPOINT` | ✅ | Full URL to the `/oauth2/token` endpoint |
| `ABSTRAUTH_REDIRECT_URI` | ✅ | Callback handled by Abnemo (e.g., `https://monitor.example.com/oauth/callback`) |
| `ABSTRAUTH_WELLKNOWN_URI` | ✅ | Full URL to Abstrauth's well-known configuration endpoint (e.g., `https://auth.example.com/.well-known/oauth-authorization-server`) |
| `ABSTRAUTH_SCOPE` | ⛔ (defaults to `openid profile email`) | Space-delimited scopes requested during login |
| `ABSTRAUTH_SESSION_COOKIE` | ⛔ (`abnemo_session`) | Name of the HTTP-only session cookie (auto-prefixed with `__Host-` in production) |
| `ABSTRAUTH_COOKIE_SECURE` | ⛔ (`auto`) | Cookie security: `auto` (default, enables in production), `true`, or `false` |
| `ABSTRAUTH_SESSION_TTL` | ⛔ (`3600`) | Session lifetime in seconds |
| `ABSTRAUTH_REQUIRED_GROUP` | ⛔ | Name of a single Abstrauth group required to view monitoring data |
| `ABSTRAUTH_REQUIRED_GROUPS` | ⛔ | Comma-separated list of acceptable groups; user must belong to at least one |
| `FLASK_ENV` | ⛔ (`production`) | Flask environment: `production` or `development` (affects cookie security) |
| `ABNEMO_STATE_SECRET` | ⛔ | Secret used to encrypt OAuth state, generated with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `ABSTRAUTH_STATE_MAX_AGE` | ⛔ | How long the state should be valid for (time that the user has to sign in), in seconds, default 10 minutes |

> ⚠️ The redirect URI **must exactly match** what is registered on the Abstrauth client, including scheme/host/port/path.

### Role / Group Enforcement

If any group requirement is configured (`ABSTRAUTH_REQUIRED_GROUP` or `ABSTRAUTH_REQUIRED_GROUPS`), Abnemo checks the user's `groups` claim inside the ID/access token payload. Users must belong to **at least one** of the configured groups to access `/api/traffic`, `/api/process/<pid>`, etc. Missing groups result in `403` with `code=missing_required_group`, and the UI explains which role is required.

Example configuration:

```bash
export ABSTRAUTH_CLIENT_ID="abnemo-monitor"
export ABSTRAUTH_CLIENT_SECRET="<super-secret>"
export ABSTRAUTH_AUTHORIZATION_ENDPOINT="https://auth.example.com/oauth2/authorize"
export ABSTRAUTH_TOKEN_ENDPOINT="https://auth.example.com/oauth2/token"
export ABSTRAUTH_REDIRECT_URI="https://monitor.example.com/oauth/callback"
export ABSTRAUTH_WELLKNOWN_URI="https://auth.example.com/.well-known/oauth-authorization-server"
export ABSTRAUTH_REQUIRED_GROUPS="abnemo_admins"
export FLASK_ENV=production           # enables secure cookies automatically
export ABSTRAUTH_COOKIE_SECURE=auto   # auto-detects based on FLASK_ENV (recommended)
```

Then launch:

```bash
./scripts/abnemo.sh monitor --web --web-port 8443
```

If the Abstrauth variables are not set, the server stays open (no authentication required) so development and local testing remain frictionless.

### CSRF Protection

The web interface includes CSRF (Cross-Site Request Forgery) protection for all state-changing operations. A secret key is required for CSRF token generation:

```bash
# Generate a secure secret key (recommended for production)
export FLASK_SECRET_KEY=$(openssl rand -hex 32)

# Or add to ~/.bashrc for persistence
echo "export FLASK_SECRET_KEY=$(openssl rand -hex 32)" >> ~/.bashrc
```

If `FLASK_SECRET_KEY` is not set, a random key is generated on startup (suitable for development, but sessions won't persist across restarts).

### Token Encryption

OAuth tokens are encrypted in memory using Fernet (AES-128-CBC + HMAC-SHA256) to protect against memory dump attacks and process inspection. An encryption key is required:

```bash
# Generate a secure encryption key (recommended for production)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set the environment variable
export ABNEMO_TOKEN_ENCRYPTION_KEY="your-generated-key-here"

# Or add to ~/.bashrc for persistence
echo "export ABNEMO_TOKEN_ENCRYPTION_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" >> ~/.bashrc
```

**Important:**
- If `ABNEMO_TOKEN_ENCRYPTION_KEY` is not set, a random key is generated on each server start
- Tokens encrypted with the old key cannot be decrypted after restart
- Users will need to re-authenticate after server restart if the key changes
- For production deployments, use a persistent key stored in a secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)

**Security Note:** This encryption protects tokens stored in server memory. It does not replace HTTPS for protecting tokens in transit.

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
./scripts/abnemo.sh monitor --isp-api-key YOUR_API_KEY
```

2. **Environment variable**:
```bash
export IPAPI_KEY=YOUR_API_KEY
./scripts/abnemo.sh monitor
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
├── src/                           # Main source code directory
│   ├── abnemo.py                  # Main CLI interface
│   ├── packet_monitor.py          # Packet capture and monitoring logic
│   ├── ebpf_monitor.py            # eBPF-based network monitoring
│   ├── process_tracker.py         # Process tracking and enrichment
│   ├── isp_lookup.py              # ISP/organization lookup module
│   ├── docker_enrichment.py       # Docker container enrichment
│   ├── web_server.py              # Flask web server
│   ├── oauth.py                   # OAuth authentication
│   ├── filters.py                 # Traffic filtering system
│   ├── fail2ban_visualizer.py     # Fail2ban log visualization
│   ├── fail2ban_endpoints.py      # Fail2ban API endpoints
│   ├── ip_bans.py                 # IP ban management
│   ├── iptables_endpoints.py      # iptables API endpoints
│   └── iptables/                  # iptables parsing and modeling
│       ├── model.py               # Data model for iptables rules
│       ├── parser.py              # iptables rule parser
│       ├── tree.py                # Tree structure for rules
│       ├── DATA_MODEL.md          # Data model documentation
│       └── README.md              # iptables module documentation
├── ebpf/                          # eBPF programs and loader
│   ├── ebpf_loader.py             # eBPF program loader
│   └── network_monitor.c          # eBPF network monitor
├── templates/                     # Jinja2 HTML templates
│   ├── base.html                  # Base template with navigation
│   ├── index.html                 # Main dashboard
│   ├── traffic_viz.html           # Traffic visualization page
│   ├── fail2ban.html              # Fail2ban visualization page
│   ├── ip_bans.html               # IP bans management page
│   └── iptables.html              # iptables visualization page
├── web_static/                    # Static HTML files (standalone)
│   ├── index.html                 # Static dashboard
│   ├── fail2ban_page.html         # Static fail2ban page
│   ├── iptables_page.html         # Static iptables page
│   └── styles.css                 # CSS styles
├── scripts/                       # Utility scripts
│   ├── abnemo.sh                  # Wrapper script for easy execution
│   ├── build_ebpf.sh              # eBPF compilation script
│   └── export_docker_info.sh      # Docker info export utility
├── tests/                         # Test suite
│   ├── iptables/                  # iptables module tests
│   ├── fixtures/                  # Test fixtures
│   └── test_*.py                  # Various test modules
├── docs/                          # Documentation
│   ├── DESIGN.md                  # Architecture and design
│   ├── ADVANCED_FILTERING.md      # Filtering system guide
│   ├── DOCKER_DEPLOYMENT.md       # Docker deployment guide
│   ├── SYSTEMD_SERVICE.md         # systemd service setup
│   ├── VERIFICATION_GUIDE.md      # Testing and verification
│   └── ephemeral/                 # Development notes that are likely to be out of date
├── port_mappings.txt              # Port number to description mappings
├── requirements.txt               # Python dependencies
├── requirements-dev.txt           # Development dependencies
├── verification.py                # Verification and testing script
├── pytest.ini                     # pytest configuration
├── .coveragerc                    # Coverage configuration
├── .gitignore                     # Git ignore rules
├── README.md                      # This file
├── LICENSE                        # License file
└── SECURITY.md                    # Security policy
```

## SBOM & Compliance

This project maintains a **Software Bill of Materials (SBOM)** in compliance with:
- **EU Cyber Resilience Act (CRA)** - Effective 2026
- **Swiss Federal Act on Data Protection (nFADP)** - Art. 7 (Privacy by Design)

The SBOM is automatically generated and updated on every push to `main` using GitHub Actions. It includes:
- Complete dependency inventory with versions
- Vulnerability scanning (CRITICAL and HIGH severity)
- CycloneDX format (recognized by EU and Swiss authorities)

**Accessing the SBOM:**
- Download `sbom.json` from the repository root
- View the latest scan results in GitHub Actions

## Verification

To verify that Abnemo is correctly capturing network traffic, use the included verification tool:

```bash
sudo python3 verification.py
```

**What it does:**
1. Runs tcpdump as an independent reference monitor (60 seconds)
2. Runs abnemo in parallel to capture the same traffic (60 seconds)
3. Compares the results to verify abnemo is working correctly

**Requirements:**
- Root privileges (for packet capture)
- tcpdump installed
- Optional: scapy for detailed packet analysis

**Output:**
- Total bytes and packets captured by each tool
- Top 10 destination IPs from both monitors
- Match percentage (≥80% indicates correct operation)
- Verdict: ✅ Working correctly, ⚠️ Partially working, or ❌ Not working

**Note:** Minor discrepancies (80-99%) are normal because abnemo uses eBPF hooks on `tcp_sendmsg`/`tcp_recvmsg` to track actual data transmission, while tcpdump captures all packets including TCP control packets (ACKs, SYNs, FINs) that contain no payload data.

**Logs saved to:**
- `/tmp/verification_capture.pcap` - tcpdump packet capture
- `/tmp/verification_tcpdump_packets.log` - Detailed packet log
- `/tmp/verification_logs/*.json` - Abnemo traffic logs
- `/tmp/verification_abnemo_packets.log` - Abnemo packet log

For detailed verification instructions, see [docs/ephemeral/VERIFICATION_GUIDE.md](docs/ephemeral/VERIFICATION_GUIDE.md).

## Running Tests

Install test dependencies:

```bash
sudo apt install \
   python3-pytest \
   python3-pytest-cov \
   python3-pytest-mock \
   python3-flake8 \
   python3-mypy \
   python3-freezegun \
   python3-responses
```

Run the test suite with pytest:

```bash
# Run all tests with verbose output and coverage report
python3 -m pytest -v --cov=. --cov-report=term-missing

# Generate HTML coverage report
python3 -m pytest --cov=. --cov-report=html
# View report: xdg-open htmlcov/index.html
```

**Note:** `verification.py` is excluded from code coverage as it's a standalone verification tool, not part of the main application. The exclusion is configured in `.coveragerc`.

For detailed testing instructions, see [docs/ephemeral/DEVELOPMENT_AND_TESTING.md](docs/ephemeral/DEVELOPMENT_AND_TESTING.md).

## Further Documentation

- [Dark Mode Implementation](docs/DARK_MODE_IMPLEMENTATION.md)
- [Design](docs/DESIGN.md)
- [Systemd Service](docs/SYSTEMD_SERVICE.md)
- [TODO](docs/TODO.md)
- [iptables Explained](docs/iptables-explained.md)


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## Disclaimer

This tool is for legitimate network monitoring and security purposes only. Always ensure you have proper authorization before monitoring network traffic. Use responsibly and in accordance with your local laws and network policies.
