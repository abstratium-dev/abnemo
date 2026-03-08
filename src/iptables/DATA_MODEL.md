# iptables Data Model

This document describes the data model for representing iptables configuration in memory.

## Entity Relationship Diagram

```mermaid
erDiagram
    IptablesConfig ||--o{ Table : contains
    Table ||--o{ Chain : contains
    Chain ||--o{ Rule : contains
    Chain ||--o{ Chain : references
    Rule ||--|| DockerEnrichedField : "has source"
    Rule ||--|| DockerEnrichedField : "has destination"
    Rule ||--|| DockerEnrichedField : "has in_interface"
    Rule ||--|| DockerEnrichedField : "has out_interface"
    
    IptablesConfig {
        dict tables "Keyed by table name"
        int total_rules "Computed property"
    }
    
    Table {
        string name "filter, nat, mangle, raw"
        dict chains "Keyed by chain name"
        int total_rules "Computed property"
    }
    
    Chain {
        string name "INPUT, OUTPUT, FORWARD, or custom"
        Policy policy "ACCEPT, DROP, REJECT, etc (optional)"
        int packet_count "Policy packet counter"
        int byte_count "Policy byte counter"
        list rules "List of Rule objects"
        bool is_builtin "Computed property"
        bool is_docker_chain "Computed property"
    }
    
    Rule {
        int pkts "Packet count"
        int bytes "Byte count"
        string target "ACCEPT, DROP, or chain name"
        string prot "Protocol: tcp, udp, icmp, all, etc"
        string opt "Options"
        DockerEnrichedField in_interface "Input interface"
        DockerEnrichedField out_interface "Output interface"
        DockerEnrichedField source "Source IP/network"
        DockerEnrichedField destination "Destination IP/network"
        string extra "Additional options"
        bool is_docker_related "Computed property"
        bool is_chain_target "Computed property"
    }
    
    DockerEnrichedField {
        string original "Original value from iptables"
        dict docker_info "Docker metadata (optional)"
        bool is_docker_related "Computed property"
        string docker_name "Container or network name"
        string docker_type "container, network, gateway, etc"
        string label "Human-readable label with emoji"
    }
```

## Class Hierarchy

```mermaid
classDiagram
    class IptablesConfig {
        +tables: Dict[str, Table]
        +add_table(table)
        +get_table(name) Table
        +get_all_chains() List[Chain]
        +get_all_docker_chains() List[Chain]
        +total_rules: int
    }
    
    class Table {
        +name: str
        +chains: Dict[str, Chain]
        +add_chain(chain)
        +get_chain(name) Chain
        +get_builtin_chains() List[Chain]
        +get_custom_chains() List[Chain]
        +get_docker_chains() List[Chain]
        +get_chains_referencing(chain_name) List[Chain]
        +get_chain_references() Dict[str, List[str]]
        +total_rules: int
    }
    
    class Chain {
        +name: str
        +policy: Policy
        +packet_count: int
        +byte_count: int
        +rules: List[Rule]
        +is_builtin: bool
        +is_docker_chain: bool
        +docker_rules_count: int
        +add_rule(rule)
        +get_rules_by_target(target) List[Rule]
        +get_docker_rules() List[Rule]
        +get_chain_target_rules() List[Rule]
        +get_referenced_chain_names() List[str]
    }
    
    class Rule {
        +pkts: int
        +bytes: int
        +target: str
        +prot: str
        +opt: str
        +in_interface: DockerEnrichedField
        +out_interface: DockerEnrichedField
        +source: DockerEnrichedField
        +destination: DockerEnrichedField
        +extra: str
        +is_docker_related: bool
        +is_chain_target: bool
        +bytes_human: str
        +get_flow_description() str
    }
    
    class DockerEnrichedField {
        +original: str
        +docker_info: Dict
        +is_docker_related: bool
        +docker_name: str
        +docker_type: str
        +label: str
    }
    
    class Policy {
        <<enumeration>>
        ACCEPT
        DROP
        REJECT
        RETURN
    }
    
    IptablesConfig "1" *-- "0..*" Table
    Table "1" *-- "0..*" Chain
    Chain "1" *-- "0..*" Rule
    Chain "0..*" --> "0..*" Chain : references via Rule.target
    Rule "1" *-- "4" DockerEnrichedField
    Chain --> Policy
```

## Chain References

Chains can reference other chains through rule targets. When a rule's target is not a terminal action (ACCEPT, DROP, REJECT, etc.), it references another chain.

```mermaid
graph TD
    INPUT[Chain: INPUT]
    FORWARD[Chain: FORWARD]
    UFW_BEFORE[Chain: ufw-before-input]
    UFW_AFTER[Chain: ufw-after-input]
    DOCKER_USER[Chain: DOCKER-USER]
    DOCKER_FORWARD[Chain: DOCKER-FORWARD]
    DOCKER[Chain: DOCKER]
    
    INPUT -->|rule target| UFW_BEFORE
    INPUT -->|rule target| UFW_AFTER
    FORWARD -->|rule target| DOCKER_USER
    FORWARD -->|rule target| DOCKER_FORWARD
    DOCKER_FORWARD -->|rule target| DOCKER
    
    style INPUT fill:#e1f5ff
    style FORWARD fill:#e1f5ff
    style DOCKER fill:#ffe1e1
    style DOCKER_USER fill:#ffe1e1
    style DOCKER_FORWARD fill:#ffe1e1
```

## Docker Enrichment Types

```mermaid
graph LR
    subgraph DockerEnrichedField Types
        A[container]
        B[docker_network]
        C[gateway]
        D[docker_interface]
        E[loopback]
        F[private]
    end
    
    subgraph Examples
        A --> A1["172.19.0.7 → maxant-victoriametrics"]
        B --> B1["172.18.0.0/16 → serverless network"]
        C --> C1["172.19.0.1 → maxant gateway"]
        D --> D1["br-134df6656aef → maxant"]
        E --> E1["127.0.0.1 → loopback"]
        F --> F1["192.168.1.0/24 → private"]
    end
    
    style A fill:#d4f1d4
    style B fill:#d4f1d4
    style C fill:#d4f1d4
    style D fill:#d4f1d4
```

## Data Flow

```mermaid
sequenceDiagram
    participant Parser
    participant DockerEnricher
    participant IptablesConfig
    participant Table
    participant Chain
    participant Rule
    
    Parser->>DockerEnricher: Load Docker metadata
    Parser->>Parser: Parse iptables output
    Parser->>IptablesConfig: Create config
    Parser->>Table: Create table
    Parser->>Chain: Create chain
    Parser->>DockerEnricher: Enrich interface
    Parser->>DockerEnricher: Enrich IP address
    Parser->>Rule: Create rule with enriched fields
    Parser->>Chain: Add rule
    Parser->>Table: Add chain
    Parser->>IptablesConfig: Add table
    IptablesConfig-->>Parser: Return config
```

## Key Concepts

### Chain References
- Rules can target other chains (not just terminal actions)
- `Rule.is_chain_target` identifies rules that reference chains
- `Chain.get_referenced_chain_names()` returns list of referenced chains
- `Table.get_chain_references()` builds dependency graph
- `Table.get_chains_referencing(name)` finds chains that reference a specific chain

### Docker Enrichment
- `DockerEnrichedField` wraps original values with Docker metadata
- Automatically populated by `DockerEnricher` during parsing
- Stores container names, network names, and human-readable labels
- Enables Docker-aware filtering and visualization

### Built-in vs Custom Chains
- Built-in chains: INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING
- Custom chains: Created by users or Docker
- Docker chains: Names starting with "DOCKER" or "docker"

### Terminal Actions
Terminal actions that end rule processing:
- ACCEPT
- DROP
- REJECT
- RETURN
- QUEUE
- LOG
- MASQUERADE
- SNAT
- DNAT

Non-terminal targets are chain references.
