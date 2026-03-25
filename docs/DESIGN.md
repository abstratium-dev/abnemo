# Abnemo Design Document

Comprehensive architecture and design documentation for the Abnemo network traffic monitoring and security system.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [eBPF Monitoring System](#ebpf-monitoring-system)
6. [IPTables Integration](#iptables-integration)
7. [Web Server & API](#web-server--api)
8. [Security & Authentication](#security--authentication)
9. [Data Storage](#data-storage)
10. [Technology Stack](#technology-stack)

---

## System Overview

Abnemo is a Linux-based network traffic monitoring and security tool that provides:

- **Kernel-level packet capture** using eBPF for near-zero overhead monitoring
- **Process and container tracking** to identify which applications generate traffic
- **Real-time web dashboard** with OAuth 2.0 authentication
- **IPTables visualization and management** with Docker enrichment
- **Intelligent filtering** with accept-list and warn-list capabilities
- **fail2ban integration** for intrusion prevention visualization

### Key Features

- IPv4 and IPv6 support throughout the stack
- Configurable traffic direction monitoring (outgoing, incoming, bidirectional, all)
- ISP and reverse DNS lookups for network intelligence
- Docker container identification and enrichment
- Automated email alerts for suspicious traffic
- Log rotation with retention policies

---

## Architecture

### High-Level System Architecture

```mermaid
graph TB
    subgraph "Kernel Space"
        K[Linux Kernel]
        TCP[tcp_sendmsg/recvmsg]
        UDP[udp_sendmsg/recvmsg]
        EBPF[eBPF Program]
        PERF[Perf Ring Buffer]
    end
    
    subgraph "User Space"
        LOADER[eBPF Loader]
        MONITOR[EBPFMonitor]
        PACKET[PacketMonitor]
        ISP[ISP Lookup]
        DNS[DNS Resolver]
        DOCKER[Docker Enricher]
    end
    
    subgraph "Storage"
        LOGS[JSON Log Files]
        CACHE[ISP Cache]
        FILTERS[Filter Configs]
    end
    
    subgraph "Web Layer"
        FLASK[Flask Web Server]
        API[REST API]
        OAUTH[OAuth 2.0 BFF]
        TEMPLATES[Jinja2 Templates]
    end
    
    subgraph "External Services"
        IPAPI[ip-api.com]
        DNSSERV[DNS Servers]
        DOCKERD[Docker Daemon]
        SMTP[SMTP Server]
    end
    
    K --> TCP
    K --> UDP
    TCP --> EBPF
    UDP --> EBPF
    EBPF --> PERF
    PERF --> LOADER
    LOADER --> MONITOR
    MONITOR --> PACKET
    PACKET --> ISP
    PACKET --> DNS
    PACKET --> DOCKER
    PACKET --> LOGS
    ISP --> IPAPI
    ISP --> CACHE
    DNS --> DNSSERV
    DOCKER --> DOCKERD
    FLASK --> API
    FLASK --> OAUTH
    FLASK --> TEMPLATES
    API --> LOGS
    API --> FILTERS
    FILTERS --> SMTP
    
    style K fill:#e1f5ff
    style EBPF fill:#fff3cd
    style MONITOR fill:#d4edda
    style FLASK fill:#f8d7da
```

### Component Interaction Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as abnemo.py
    participant eBPF as eBPF Loader
    participant Kernel
    participant Monitor as EBPFMonitor
    participant Web as Flask Server
    participant Storage as Log Files
    
    User->>CLI: sudo abnemo.py monitor --web
    CLI->>eBPF: load(callback)
    eBPF->>Kernel: Attach kprobes
    Kernel-->>eBPF: Hooks attached
    CLI->>Monitor: start_monitoring_ebpf()
    CLI->>Web: start_web_server() [thread]
    
    loop Every packet
        Kernel->>eBPF: tcp_sendmsg/recvmsg event
        eBPF->>Monitor: _handle_ebpf_event()
        Monitor->>Monitor: Update statistics
    end
    
    loop Every interval
        Monitor->>Storage: save_statistics()
        Storage->>Storage: Analyze warn-list
    end
    
    User->>Web: GET /api/traffic
    Web->>Storage: Read log files
    Storage-->>Web: Traffic data
    Web-->>User: JSON response
```

---

## Core Components

### 1. Main CLI (`abnemo.py`)

**Purpose**: Command-line interface and application entry point

**Responsibilities**:
- Parse command-line arguments
- Configure logging levels
- Initialize monitoring components
- Start web server (optional)
- Handle graceful shutdown

**Key Commands**:
- `monitor` - Start network traffic monitoring
- `list-logs` - List captured traffic logs
- `iptables-tree` - Visualize iptables configuration
- `web` - Start standalone web server

### 2. eBPF Monitoring System

#### eBPF Loader (`ebpf/ebpf_loader.py`)

**Purpose**: Load and manage eBPF programs in the kernel

**Key Methods**:
- `load(callback)` - Compile C code to eBPF bytecode and attach to kernel
- `poll(timeout)` - Poll perf buffer for events
- `cleanup()` - Detach hooks and free resources

**Kernel Hooks**:
- `tcp_sendmsg` / `tcp_recvmsg` - TCP traffic
- `udp_sendmsg` / `udp_recvmsg` - UDP traffic

#### eBPF Monitor (`src/ebpf_monitor.py`)

**Purpose**: User-space component that receives and processes eBPF events

**Inheritance**: Extends `PacketMonitor` base class

**Key Features**:
- Process identification via PID and cgroup ID
- Container detection from cgroup paths
- Docker container name resolution
- Actual byte counting from kernel events

**Container Identification Methods**:
1. cgroup ID matching (primary)
2. PID-based cgroup parsing (fallback)
3. Docker inspect API calls (name resolution)

### 3. Packet Monitor (`src/packet_monitor.py`)

**Purpose**: Base class for network traffic monitoring and statistics

**Key Responsibilities**:
- Traffic statistics aggregation by IP
- Reverse DNS lookups with caching
- IP address classification (public, private, multicast, etc.)
- ISP information enrichment
- Traffic direction filtering
- Log rotation and retention

**Traffic Direction Modes**:
- `outgoing` - Only local → remote (default)
- `incoming` - Only unsolicited remote → local
- `bidirectional` - Responses to outgoing connections
- `all` - Everything including unsolicited incoming

**Statistics Tracked Per IP**:
- Bytes and packet counts
- Domain names (reverse DNS)
- Ports accessed
- IP type classification
- ISP information
- Associated processes/containers

### 4. ISP Lookup (`src/isp_lookup.py`)

**Purpose**: Retrieve ISP and geolocation data for IP addresses

**Features**:
- Persistent JSON cache with TTL
- Rate limiting (1.5s for free tier, 0.1s for pro)
- Multi-instance cache synchronization
- Automatic cache expiration

**API Integration**:
- Free tier: `http://ip-api.com/json/`
- Pro tier: `https://pro.ip-api.com/json/` (requires API key)

**Cached Data**:
- ISP name and organization
- AS number and name
- Country and country code
- Timestamp for TTL management

---

## Data Flow

### Packet Capture and Processing Flow

```mermaid
flowchart TD
    START([Network Packet]) --> KERNEL[Kernel Network Stack]
    KERNEL --> HOOK{eBPF Hook}
    HOOK -->|tcp_sendmsg| TCPSEND[TCP Send]
    HOOK -->|tcp_recvmsg| TCPRECV[TCP Receive]
    HOOK -->|udp_sendmsg| UDPSEND[UDP Send]
    HOOK -->|udp_recvmsg| UDPRECV[UDP Receive]
    
    TCPSEND --> EVENT[Create Event]
    TCPRECV --> EVENT
    UDPSEND --> EVENT
    UDPRECV --> EVENT
    
    EVENT --> PERF[Perf Ring Buffer]
    PERF --> USERSPACE[User Space Handler]
    
    USERSPACE --> EXTRACT[Extract Event Data]
    EXTRACT --> PID[PID & Process Name]
    EXTRACT --> ADDRS[Source/Dest IPs]
    EXTRACT --> PORTS[Source/Dest Ports]
    EXTRACT --> BYTES[Actual Byte Count]
    EXTRACT --> CGROUP[cgroup ID]
    
    PID --> IDENTIFY{Identify Process}
    CGROUP --> CONTAINER{Docker Container?}
    
    CONTAINER -->|Yes| DOCKERNAME[Get Container Name]
    CONTAINER -->|No| HOSTPROC[Host Process]
    
    IDENTIFY --> DIRECTION{Traffic Direction}
    DIRECTION -->|Outgoing| REMOTE1[Remote IP = Dest]
    DIRECTION -->|Incoming| REMOTE2[Remote IP = Source]
    
    REMOTE1 --> FILTER{Apply Filters}
    REMOTE2 --> FILTER
    
    FILTER -->|Pass| STATS[Update Statistics]
    FILTER -->|Drop| DISCARD[Discard]
    
    STATS --> DNS[Reverse DNS Lookup]
    DNS --> CLASSIFY[Classify IP Type]
    CLASSIFY --> AGGREGATE[Aggregate by IP]
    
    AGGREGATE --> SAVE{Save Interval?}
    SAVE -->|Yes| LOG[Write JSON Log]
    SAVE -->|No| CONTINUE[Continue Monitoring]
    
    LOG --> ANALYZE[Analyze Warn-list]
    ANALYZE --> EMAIL{Matches Found?}
    EMAIL -->|Yes| ALERT[Send Email Alert]
    EMAIL -->|No| DONE([Done])
    ALERT --> DONE
    CONTINUE --> START
    
    style KERNEL fill:#e1f5ff
    style HOOK fill:#fff3cd
    style EVENT fill:#d4edda
    style STATS fill:#d1ecf1
    style LOG fill:#f8d7da
```

### Web Request Flow

```mermaid
sequenceDiagram
    participant Browser
    participant Flask
    participant OAuth
    participant Session
    participant LogFiles
    participant Filters
    
    Browser->>Flask: GET /api/traffic?begin=...&end=...
    Flask->>OAuth: Check authentication
    OAuth->>Session: Get session cookie
    Session-->>OAuth: Session data
    
    alt Not authenticated
        OAuth-->>Flask: 401 Unauthorized
        Flask-->>Browser: Redirect to login
    else Authenticated
        OAuth-->>Flask: Continue
        Flask->>LogFiles: get_logs_in_range()
        
        loop For each log file
            LogFiles->>LogFiles: Check timestamp
            LogFiles->>LogFiles: Aggregate traffic
        end
        
        LogFiles-->>Flask: Aggregated data
        Flask->>Filters: Apply accept-list
        Filters-->>Flask: Filtered data
        Flask-->>Browser: JSON response
    end
```

---

## eBPF Monitoring System

### eBPF Program Architecture

```mermaid
graph LR
    subgraph "C Program (network_monitor.c)"
        STRUCT[Event Struct Definition]
        MAPS[BPF Hash Maps]
        TRACE_TCP[trace_tcp_sendmsg]
        TRACE_UDP[trace_udp_sendmsg]
        SUBMIT[Submit to Perf Buffer]
    end
    
    subgraph "BCC Compilation"
        BCC[BCC Compiler]
        LLVM[LLVM Backend]
        BYTECODE[eBPF Bytecode]
    end
    
    subgraph "Kernel"
        VERIFIER[eBPF Verifier]
        JIT[JIT Compiler]
        LOADED[Loaded Program]
    end
    
    STRUCT --> BCC
    MAPS --> BCC
    TRACE_TCP --> BCC
    TRACE_UDP --> BCC
    SUBMIT --> BCC
    
    BCC --> LLVM
    LLVM --> BYTECODE
    BYTECODE --> VERIFIER
    VERIFIER -->|Safe| JIT
    VERIFIER -->|Unsafe| REJECT[Reject]
    JIT --> LOADED
    
    style BYTECODE fill:#fff3cd
    style VERIFIER fill:#d4edda
    style LOADED fill:#d1ecf1
```

### Event Structure

The eBPF program captures the following data for each network event:

```c
struct traffic_event_t {
    u32 pid;              // Process ID
    char comm[16];        // Process name
    u32 saddr;            // Source IP (IPv4)
    u32 daddr;            // Destination IP (IPv4)
    u32 saddr_v6[4];      // Source IP (IPv6)
    u32 daddr_v6[4];      // Destination IP (IPv6)
    u16 sport;            // Source port
    u16 dport;            // Destination port
    u8 protocol;          // 6=TCP, 17=UDP
    u64 cgroup_id;        // Container cgroup ID
    u8 ip_version;        // 4 or 6
    u32 bytes;            // Actual bytes sent/received
};
```

### Container Identification Process

```mermaid
flowchart TD
    START([eBPF Event]) --> CGROUP{cgroup_id != 0?}
    CGROUP -->|Yes| METHOD1[Method 1: cgroup ID lookup]
    CGROUP -->|No| PID{PID available?}
    
    METHOD1 --> SEARCH1[Search /sys/fs/cgroup]
    SEARCH1 --> FOUND1{Found?}
    FOUND1 -->|Yes| CONTAINER[Container Info]
    FOUND1 -->|No| PID
    
    PID -->|Yes| METHOD2[Method 2: PID-based]
    PID -->|No| HOST[Host Process]
    
    METHOD2 --> READCGROUP[Read /proc/PID/cgroup]
    READCGROUP --> DOCKER{Contains 'docker'?}
    
    DOCKER -->|Yes| EXTRACT[Extract Container ID]
    DOCKER -->|No| K8S{Contains 'kubepods'?}
    
    K8S -->|Yes| K8SPOD[Kubernetes Pod]
    K8S -->|No| HOST
    
    EXTRACT --> INSPECT[docker inspect]
    INSPECT --> NAME[Get Container Name]
    NAME --> CONTAINER
    K8SPOD --> CONTAINER
    
    CONTAINER --> CACHE[Cache Result]
    HOST --> END([Done])
    CACHE --> END
    
    style CGROUP fill:#fff3cd
    style DOCKER fill:#d4edda
    style CONTAINER fill:#d1ecf1
```

---

## IPTables Integration

### IPTables Model Architecture

```mermaid
classDiagram
    class IptablesConfig {
        +Dict~str,Table~ tables
        +add_table(table)
        +get_table(name)
        +get_all_chains()
        +total_rules: int
    }
    
    class Table {
        +str name
        +Dict~str,Chain~ chains
        +add_chain(chain)
        +get_chain(name)
        +get_docker_chains()
        +total_rules: int
    }
    
    class Chain {
        +str name
        +Policy policy
        +int packet_count
        +int byte_count
        +List~Rule~ rules
        +is_builtin: bool
        +is_docker_chain: bool
        +docker_rules_count: int
        +add_rule(rule)
        +get_docker_rules()
    }
    
    class Rule {
        +int pkts
        +int bytes
        +str target
        +str prot
        +DockerEnrichedField in_interface
        +DockerEnrichedField out_interface
        +DockerEnrichedField source
        +DockerEnrichedField destination
        +str extra
        +is_docker_related: bool
        +is_chain_target: bool
        +get_flow_description()
    }
    
    class DockerEnrichedField {
        +str original
        +Dict docker_info
        +is_docker_related: bool
        +docker_name: str
        +docker_type: str
        +label: str
    }
    
    class DockerEnricher {
        +Dict containers
        +Dict networks
        +enrich_ip(ip)
        +enrich_interface(iface)
        +is_docker_interface(iface)
        +get_docker_flow_info(rule)
    }
    
    IptablesConfig "1" *-- "*" Table
    Table "1" *-- "*" Chain
    Chain "1" *-- "*" Rule
    Rule "1" *-- "4" DockerEnrichedField
    DockerEnrichedField ..> DockerEnricher : enriched by
```

### IPTables Parsing Flow

```mermaid
flowchart TD
    START([Parse Request]) --> SOURCE{Data Source}
    SOURCE -->|Command| SUDO[sudo iptables -t TABLE -L -v -n]
    SOURCE -->|File| READ[Read File]
    
    SUDO --> OUTPUT[Command Output]
    READ --> OUTPUT
    
    OUTPUT --> DOCKER[Load Docker Info]
    DOCKER --> ENRICHER[Create DockerEnricher]
    
    ENRICHER --> PARSE[Parse Output]
    PARSE --> LINE{For Each Line}
    
    LINE --> CHAIN_HEADER{Chain Header?}
    CHAIN_HEADER -->|Yes| CREATE_CHAIN[Create Chain Object]
    CHAIN_HEADER -->|No| RULE_LINE{Rule Line?}
    
    RULE_LINE -->|Yes| PARSE_RULE[Parse Rule Fields]
    RULE_LINE -->|No| LINE
    
    CREATE_CHAIN --> POLICY{Has Policy?}
    POLICY -->|Yes| BUILTIN[Built-in Chain]
    POLICY -->|No| CUSTOM[Custom Chain]
    
    BUILTIN --> ADD_CHAIN[Add to Table]
    CUSTOM --> ADD_CHAIN
    ADD_CHAIN --> LINE
    
    PARSE_RULE --> ENRICH_IP[Enrich Source/Dest IPs]
    ENRICH_IP --> ENRICH_IFACE[Enrich Interfaces]
    ENRICH_IFACE --> CREATE_RULE[Create Rule Object]
    CREATE_RULE --> ADD_RULE[Add to Current Chain]
    ADD_RULE --> LINE
    
    LINE -->|Done| MODEL[IptablesConfig Model]
    MODEL --> TREE{Tree View?}
    
    TREE -->|Yes| FORMATTER[IptablesTreeFormatter]
    TREE -->|No| RETURN[Return Model]
    
    FORMATTER --> COMPRESS{Compress Chains?}
    COMPRESS -->|Yes| OR_NODES[Create OR Nodes]
    COMPRESS -->|No| INLINE[Inline Expansion]
    
    OR_NODES --> OUTPUT_TREE[Tree Output]
    INLINE --> OUTPUT_TREE
    RETURN --> END([Done])
    OUTPUT_TREE --> END
    
    style ENRICHER fill:#fff3cd
    style MODEL fill:#d4edda
    style FORMATTER fill:#d1ecf1
```

---

## Web Server & API

### Flask Application Structure

```mermaid
graph TB
    subgraph "Flask App Factory"
        CREATE[create_app]
        CONFIG[OAuth Config]
        SESSION[Session Store]
    end
    
    subgraph "Middleware"
        BEFORE[before_request]
        AFTER[after_request]
        AUTH[Authentication Check]
    end
    
    subgraph "Route Modules"
        TRAFFIC[Traffic Routes]
        IPTABLES[IPTables Routes]
        FAIL2BAN[fail2ban Routes]
        FILTERS[Filter Routes]
        IPBAN[IP Ban Routes]
        OAUTH_ROUTES[OAuth Routes]
    end
    
    subgraph "Templates"
        INDEX[index.html]
        IPTABLES_PAGE[iptables.html]
        FAIL2BAN_PAGE[fail2ban.html]
        TRAFFIC_VIZ[traffic_viz.html]
        IP_BANS[ip_bans.html]
    end
    
    CREATE --> CONFIG
    CONFIG --> SESSION
    SESSION --> BEFORE
    BEFORE --> AUTH
    AUTH --> AFTER
    
    AFTER --> TRAFFIC
    AFTER --> IPTABLES
    AFTER --> FAIL2BAN
    AFTER --> FILTERS
    AFTER --> IPBAN
    AFTER --> OAUTH_ROUTES
    
    TRAFFIC --> INDEX
    IPTABLES --> IPTABLES_PAGE
    FAIL2BAN --> FAIL2BAN_PAGE
    TRAFFIC --> TRAFFIC_VIZ
    IPBAN --> IP_BANS
    
    style CONFIG fill:#fff3cd
    style AUTH fill:#f8d7da
    style TRAFFIC fill:#d4edda
```

### API Endpoints

#### Traffic Monitoring
- `GET /api/traffic` - Get aggregated traffic data for time range
- `GET /api/traffic-viz` - Get time series data with regex filtering
- `GET /api/process/<pid>` - Get process details via ps command

#### IPTables Management
- `GET /api/iptables/visualize` - Get iptables tree visualization
- `GET /api/iptables/tables` - List all iptables tables
- `GET /api/iptables/chains` - Get chains for a table

#### fail2ban Integration
- `GET /api/fail2ban/status` - Get fail2ban status
- `GET /api/fail2ban/visualize` - Get Mermaid diagram

#### Filter Management
- `GET /api/accept-list-filters` - List accept-list filters
- `POST /api/accept-list-filters` - Create accept-list filter
- `PUT /api/accept-list-filters/<id>` - Update filter
- `DELETE /api/accept-list-filters/<id>` - Delete filter
- `GET /api/warnlist-filters` - List warn-list filters
- `POST /api/warnlist-filters` - Create warn-list filter
- `PUT /api/warnlist-filters/<id>` - Update filter
- `DELETE /api/warnlist-filters/<id>` - Delete filter

#### IP Ban Management
- `GET /api/ip-bans` - List banned IPs
- `POST /api/ip-bans` - Ban an IP address
- `DELETE /api/ip-bans/<ip>` - Unban an IP address

#### OAuth & User
- `GET /api/user` - Get current user info
- `GET /api/oauth/status` - Get OAuth status
- `POST /api/logout` - Logout current user
- `GET /oauth/login` - Initiate OAuth login
- `GET /oauth/callback` - OAuth callback handler

---

## Security & Authentication

### OAuth 2.0 BFF Pattern

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant Flask as Flask BFF
    participant Session as Session Store
    participant OAuth as OAuth Provider
    
    User->>Browser: Access /
    Browser->>Flask: GET /
    Flask->>Session: Check session cookie
    Session-->>Flask: No session
    Flask-->>Browser: Redirect to /oauth/login
    
    Browser->>Flask: GET /oauth/login
    Flask->>Flask: Generate state & nonce
    Flask->>Session: Store state & nonce
    Flask-->>Browser: Redirect to OAuth provider
    
    Browser->>OAuth: Authorization request
    User->>OAuth: Enter credentials
    OAuth->>OAuth: Authenticate user
    OAuth-->>Browser: Redirect to /oauth/callback?code=...
    
    Browser->>Flask: GET /oauth/callback?code=...
    Flask->>Session: Verify state
    Flask->>OAuth: Exchange code for tokens
    OAuth-->>Flask: Access token + ID token
    
    Flask->>OAuth: Get user info
    OAuth-->>Flask: User profile
    
    Flask->>Flask: Verify groups (if required)
    Flask->>Session: Store user + tokens
    Flask-->>Browser: Set session cookie
    Flask-->>Browser: Redirect to /
    
    Browser->>Flask: GET / (with session)
    Flask->>Session: Validate session
    Session-->>Flask: User authenticated
    Flask-->>Browser: Serve application
```

### Filter System

```mermaid
flowchart TD
    START([New Traffic Log]) --> ASYNC[Async Analysis Thread]
    ASYNC --> LOAD[Load Traffic Data]
    LOAD --> WARNLIST[Load Warn-list Filters]
    WARNLIST --> ACCEPTLIST[Load Accept-list Filters]
    
    ACCEPTLIST --> LOOP{For Each IP}
    LOOP --> CHECK_WARN{Matches Warn-list?}
    
    CHECK_WARN -->|No| LOOP
    CHECK_WARN -->|Yes| CHECK_ACCEPT{Matches Accept-list?}
    
    CHECK_ACCEPT -->|Yes| SKIP[Skip - Accept-list Priority]
    CHECK_ACCEPT -->|No| MATCH[Add to Matches]
    
    SKIP --> LOOP
    MATCH --> LOOP
    
    LOOP -->|Done| MATCHES{Any Matches?}
    MATCHES -->|No| END([Done])
    MATCHES -->|Yes| EMAIL[Send Email Alert]
    
    EMAIL --> SMTP[SMTP Server]
    SMTP --> NOTIFY[Notify User]
    NOTIFY --> END
    
    style CHECK_WARN fill:#fff3cd
    style CHECK_ACCEPT fill:#d4edda
    style EMAIL fill:#f8d7da
```

---

## Data Storage

### Log File Structure

**Filename Format**: `traffic_log_YYYYMMDD_HHMMSS.json`

**JSON Structure**:
```json
{
  "timestamp": "2024-03-23T20:55:00.123456",
  "total_ips": 42,
  "total_bytes": 1234567890,
  "total_packets": 98765,
  "traffic_by_ip": {
    "8.8.8.8": {
      "bytes": 123456,
      "packets": 234,
      "domains": ["dns.google"],
      "ports": [53, 443],
      "ip_type": "public",
      "isp": {
        "org": "Google LLC",
        "country_code": "US",
        "as": "AS15169"
      },
      "processes": [
        {
          "name": "firefox",
          "pid": 1234,
          "container": {
            "name": "web-app",
            "id": "abc123def456"
          }
        }
      ]
    }
  }
}
```

---

## Technology Stack

### Core Technologies

| Component | Technology | Purpose |
|-----------|-----------|----------|
| **Kernel Monitoring** | eBPF/BCC | Kernel-level packet capture |
| **Language** | Python 3.7+ | Application logic |
| **Web Framework** | Flask | REST API and web server |
| **Templating** | Jinja2 | HTML template rendering |
| **Packet Processing** | Scapy | Alternative packet capture |
| **DNS** | dnspython | Reverse DNS lookups |
| **Container** | Docker API | Container identification |
| **Authentication** | OAuth 2.0 | User authentication |
| **Visualization** | Mermaid.js | Diagram generation |

### Python Dependencies

**Core**:
- `bcc` / `python3-bpfcc` - BPF Compiler Collection
- `scapy` - Packet manipulation library
- `dnspython` - DNS toolkit
- `flask` - Web framework
- `flask-wtf` - CSRF protection
- `flask-limiter` - Rate limiting
- `watchdog` - File system monitoring
- `cryptography` - Security utilities
- `tabulate` - Table formatting
- `debugpy` - Remote debugging

---

## Conclusion

Abnemo provides a comprehensive network monitoring solution that combines:

- **Low-overhead monitoring** via eBPF kernel hooks
- **Rich context** through process, container, and ISP identification
- **Flexible filtering** with accept-list and warn-list capabilities
- **Secure access** via OAuth 2.0 authentication
- **Visual insights** through iptables and fail2ban integration

The modular architecture allows for easy extension and customization while maintaining performance and security.
