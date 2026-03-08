# iptables Model and Parser

Python classes to model and parse Linux iptables configuration with Docker enrichment support.

## Overview

This package provides:

1. **Model classes** (`model.py`) - Object-oriented representation of iptables configuration
2. **Parser** (`parser.py`) - Parse `iptables -L -v -n` output and populate the model
3. **Docker enrichment** - Automatically enrich IP addresses and interfaces with Docker container/network information

## Quick Start

```python
from src.iptables import load_iptables_config

# Parse from iptables command (requires sudo)
config = load_iptables_config(table='filter', use_sudo=True)

# Or parse from a file
config = load_iptables_config(
    iptables_file='iptables_output.txt',
    enrichment_file='docker_enrichment.txt',
    table='filter'
)

# Access the configuration
filter_table = config.get_table('filter')
for chain_name, chain in filter_table.chains.items():
    print(f"{chain_name}: {len(chain.rules)} rules")
```

## Model Classes

### IptablesConfig

The top-level container for the entire iptables configuration.

```python
config = IptablesConfig()
config.add_table(table)

# Access tables
filter_table = config.get_table('filter')

# Get all chains across all tables
all_chains = config.get_all_chains()

# Get Docker-related chains
docker_chains = config.get_all_docker_chains()

# Total rules count
print(f"Total rules: {config.total_rules}")
```

### Table

Represents an iptables table (filter, nat, mangle, raw).

```python
table = Table(name='filter')
table.add_chain(chain)

# Access chains
input_chain = table.get_chain('INPUT')

# Get built-in vs custom chains
builtin_chains = table.get_builtin_chains()
custom_chains = table.get_custom_chains()

# Get Docker chains
docker_chains = table.get_docker_chains()
```

### Chain

Represents an iptables chain with its policy and rules.

```python
chain = Chain(
    name='INPUT',
    policy=Policy.DROP,
    packet_count=1000,
    byte_count=50000
)

chain.add_rule(rule)

# Properties
print(f"Is built-in: {chain.is_builtin}")
print(f"Is Docker chain: {chain.is_docker_chain}")
print(f"Docker rules: {chain.docker_rules_count}")

# Query rules
accept_rules = chain.get_rules_by_target('ACCEPT')
docker_rules = chain.get_docker_rules()
```

### Rule

Represents a single iptables rule with all its fields.

```python
rule = Rule(
    pkts=100,
    bytes=5000,
    target='ACCEPT',
    prot='tcp',
    opt='--',
    in_interface=DockerEnrichedField('docker0'),
    out_interface=DockerEnrichedField('*'),
    source=DockerEnrichedField('172.17.0.2'),
    destination=DockerEnrichedField('0.0.0.0/0')
)

# Properties
print(f"Is Docker-related: {rule.is_docker_related}")
print(f"Bytes (human): {rule.bytes_human}")  # e.g., "4.9K"
print(f"Flow: {rule.get_flow_description()}")
```

### DockerEnrichedField

A field that stores both the original value and Docker enrichment metadata.

```python
field = DockerEnrichedField(
    original='172.17.0.2',
    docker_info={
        'type': 'container',
        'container_name': 'my-app',
        'network': 'bridge',
        'label': '🐳 my-app'
    }
)

# Access original value
print(field.original)  # "172.17.0.2"
print(str(field))      # "172.17.0.2"

# Check Docker enrichment
if field.is_docker_related:
    print(f"Docker name: {field.docker_name}")    # "my-app"
    print(f"Docker type: {field.docker_type}")    # "container"
    print(f"Label: {field.label}")                # "🐳 my-app"
```

## Parser Usage

### Parse from iptables command

```python
from src.iptables import IptablesParser

parser = IptablesParser()

# Parse single table
config = parser.parse_from_command(table='filter', use_sudo=True)

# Parse all tables
config = parser.parse_all_tables(use_sudo=True)
```

### Parse from file

```python
# Parse iptables output from file
config = parser.parse_file('iptables_output.txt', table_name='filter')
```

### With Docker enrichment

```python
from docker_enrichment import DockerEnricher
from src.iptables import IptablesParser

# Create enricher with data from file
with open('docker_enrichment.txt', 'r') as f:
    enrichment_data = f.read()

enricher = DockerEnricher(enrichment_data=enrichment_data)

# Or let it query Docker directly
enricher = DockerEnricher()

# Create parser with enricher
parser = IptablesParser(docker_enricher=enricher)
config = parser.parse_from_command(table='filter')
```

## Docker Enrichment

The parser automatically enriches fields with Docker information:

### Container IPs

When a source or destination IP belongs to a Docker container:

```python
rule.destination.original        # "172.19.0.28"
rule.destination.docker_type     # "container"
rule.destination.docker_name     # "maxant-test-sre"
rule.destination.label           # "🐳 maxant-test-sre"
```

### Docker Networks

When an IP is in a Docker network subnet:

```python
rule.source.docker_type          # "docker_network"
rule.source.docker_name          # "serverless"
rule.source.label                # "🐋 Docker net: serverless"
```

### Docker Interfaces

When an interface is a Docker bridge:

```python
rule.out_interface.original      # "br-979cf8868fcd"
rule.out_interface.docker_type   # "docker_interface"
rule.out_interface.docker_name   # "maxant"
rule.out_interface.label         # "🐋 maxant"
```

## Field Reference

### Rule Fields

All fields from `iptables -L -v -n`:

- `pkts` (int) - Number of packets matched
- `bytes` (int) - Number of bytes matched
- `target` (str) - Target action (ACCEPT, DROP, chain name, etc.)
- `prot` (str) - Protocol (tcp, udp, icmp, all, etc.)
- `opt` (str) - Options (usually '--')
- `in_interface` (DockerEnrichedField) - Input interface
- `out_interface` (DockerEnrichedField) - Output interface
- `source` (DockerEnrichedField) - Source IP/network
- `destination` (DockerEnrichedField) - Destination IP/network
- `extra` (str) - Additional rule options (ports, state, etc.)

### Chain Structure

A chain consists of:
- **name** - Chain name (INPUT, OUTPUT, FORWARD, or custom)
- **policy** - Default policy (ACCEPT, DROP, etc.) - None for custom chains
- **packet_count** - Packet counter for the chain policy
- **byte_count** - Byte counter for the chain policy
- **rules** - List of Rule objects

## Examples

See `example_usage.py` for complete examples:

1. Parse from file with Docker enrichment
2. Query Docker-related rules
3. Parse from iptables command
4. Access Docker-enriched field details
5. Create model programmatically

## Command-Line Usage

The parser can also be used from the command line:

```bash
# Parse filter table
python3 -m src.iptables.parser --table filter

# Parse all tables
python3 -m src.iptables.parser --all-tables

# Parse from file
python3 -m src.iptables.parser --file iptables_output.txt

# With Docker enrichment
python3 -m src.iptables.parser --enrichment docker_data.txt --table filter
```

## Docker Enrichment Data Format

The enrichment data file format (from `export_docker_info.sh`):

```
=== DOCKER ENRICHMENT DATA ===

# Docker Containers
# Format: IP|ContainerName|NetworkName|Gateway
172.18.0.10|serverless-prometheus|serverless|172.18.0.1
172.18.0.11|serverless-proxyserver|serverless|172.18.0.1

# Docker Networks
# Format: NetworkName|Subnet|Gateway|Driver|InterfaceID
serverless|172.18.0.0/16|172.18.0.1|bridge|ef37f7b34afa
maxant|172.19.0.0/16|172.19.0.1|bridge|979cf8868fcd

=== END DOCKER ENRICHMENT DATA ===
```

## Integration with Existing Code

This model integrates with the existing `docker_enrichment.py` module:

```python
from docker_enrichment import DockerEnricher
from src.iptables import IptablesParser

# Use existing enricher
enricher = DockerEnricher()
parser = IptablesParser(docker_enricher=enricher)

# Parse and get enriched data
config = parser.parse_from_command(table='filter')

# All IP addresses and interfaces are automatically enriched
for chain in config.get_all_chains():
    for rule in chain.rules:
        if rule.is_docker_related:
            print(f"Docker rule: {rule.get_flow_description()}")
```
