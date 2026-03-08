#!/usr/bin/env python3
"""
iptables Model - Classes to represent iptables configuration in memory
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from enum import Enum


class Policy(Enum):
    """Chain policy values"""
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    RETURN = "RETURN"


@dataclass
class DockerEnrichedField:
    """
    A field that can be enriched with Docker information.
    Stores both the original value and Docker metadata.
    """
    original: str
    docker_info: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_docker_related(self) -> bool:
        """Check if this field has Docker enrichment data"""
        return bool(self.docker_info)
    
    @property
    def docker_name(self) -> Optional[str]:
        """Get the Docker name (container or network) if available"""
        if 'container_name' in self.docker_info:
            return self.docker_info['container_name']
        elif 'network' in self.docker_info:
            return self.docker_info['network']
        return None
    
    @property
    def docker_type(self) -> Optional[str]:
        """Get the type of Docker entity (container, network, gateway, etc.)"""
        return self.docker_info.get('type')
    
    @property
    def label(self) -> str:
        """Get a human-readable label (with emoji if Docker-related)"""
        return self.docker_info.get('label', self.original)
    
    def __str__(self) -> str:
        """String representation shows original value"""
        return self.original
    
    def __repr__(self) -> str:
        if self.is_docker_related:
            return f"DockerEnrichedField('{self.original}', docker={self.docker_type})"
        return f"DockerEnrichedField('{self.original}')"


@dataclass
class Rule:
    """
    Represents a single iptables rule.
    
    Fields correspond to the output of `iptables -L -v -n`:
    - pkts: Number of packets matched
    - bytes: Number of bytes matched
    - target: Target action (ACCEPT, DROP, chain name, etc.)
    - prot: Protocol (tcp, udp, icmp, all, etc.)
    - opt: Options (usually '--')
    - in_interface: Input interface
    - out_interface: Output interface
    - source: Source IP/network
    - destination: Destination IP/network
    """
    pkts: int
    bytes: int
    target: str
    prot: str
    opt: str
    in_interface: DockerEnrichedField
    out_interface: DockerEnrichedField
    source: DockerEnrichedField
    destination: DockerEnrichedField
    
    # Additional fields for extended information
    extra: str = ""  # Any additional rule options (e.g., port ranges, state matching)
    
    @property
    def is_docker_related(self) -> bool:
        """Check if this rule involves Docker containers or networks"""
        return (
            self.in_interface.is_docker_related or
            self.out_interface.is_docker_related or
            self.source.is_docker_related or
            self.destination.is_docker_related
        )
    
    @property
    def is_chain_target(self) -> bool:
        """Check if target is likely a chain reference (not a terminal action)"""
        terminal_actions = {'ACCEPT', 'DROP', 'REJECT', 'RETURN', 'QUEUE', 'LOG', 'MASQUERADE', 'SNAT', 'DNAT'}
        return self.target not in terminal_actions
    
    @property
    def bytes_human(self) -> str:
        """Human-readable byte count"""
        if self.bytes < 1024:
            return f"{self.bytes}B"
        elif self.bytes < 1024 * 1024:
            return f"{self.bytes / 1024:.1f}K"
        elif self.bytes < 1024 * 1024 * 1024:
            return f"{self.bytes / (1024 * 1024):.1f}M"
        else:
            return f"{self.bytes / (1024 * 1024 * 1024):.1f}G"
    
    def get_flow_description(self) -> str:
        """Get a human-readable description of the traffic flow"""
        parts = []
        
        if self.source.is_docker_related:
            parts.append(f"from {self.source.label}")
        elif self.source.original not in ['0.0.0.0/0', 'anywhere', '*']:
            parts.append(f"from {self.source.original}")
        
        if self.destination.is_docker_related:
            parts.append(f"to {self.destination.label}")
        elif self.destination.original not in ['0.0.0.0/0', 'anywhere', '*']:
            parts.append(f"to {self.destination.original}")
        
        # Handle in_interface - check for negation prefix
        in_iface = self.in_interface.original
        if in_iface not in ['*', 'any']:
            if self.in_interface.is_docker_related:
                # Use docker label, preserve negation prefix if present
                prefix = "!" if in_iface.startswith("!") else ""
                parts.append(f"in:{prefix}{self.in_interface.label}")
            else:
                parts.append(f"in:{in_iface}")
        
        # Handle out_interface - check for negation prefix
        out_iface = self.out_interface.original
        if out_iface not in ['*', 'any']:
            if self.out_interface.is_docker_related:
                # Use docker label, preserve negation prefix if present
                prefix = "!" if out_iface.startswith("!") else ""
                parts.append(f"out:{prefix}{self.out_interface.label}")
            else:
                parts.append(f"out:{out_iface}")
        
        return ' '.join(parts) if parts else "any → any"
    
    def __repr__(self) -> str:
        return (
            f"Rule(target={self.target}, prot={self.prot}, "
            f"src={self.source.original}, dst={self.destination.original}, "
            f"pkts={self.pkts}, bytes={self.bytes_human})"
        )


@dataclass
class Chain:
    """
    Represents an iptables chain.
    
    A chain contains:
    - name: Chain name (INPUT, OUTPUT, FORWARD, or custom chain)
    - policy: Default policy (ACCEPT, DROP, etc.) - None for custom chains
    - packet_count: Packet counter for the chain policy
    - byte_count: Byte counter for the chain policy
    - rules: List of rules in this chain
    """
    name: str
    policy: Optional[Policy] = None
    packet_count: int = 0
    byte_count: int = 0
    rules: List[Rule] = field(default_factory=list)
    
    @property
    def is_builtin(self) -> bool:
        """Check if this is a built-in chain"""
        return self.name in ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']
    
    @property
    def is_docker_chain(self) -> bool:
        """Check if this is a Docker-related chain"""
        docker_prefixes = ['DOCKER', 'docker']
        return any(self.name.startswith(prefix) for prefix in docker_prefixes)
    
    @property
    def docker_rules_count(self) -> int:
        """Count how many rules in this chain are Docker-related"""
        return sum(1 for rule in self.rules if rule.is_docker_related)
    
    @property
    def bytes_human(self) -> str:
        """Human-readable byte count for chain policy"""
        if self.byte_count < 1024:
            return f"{self.byte_count}B"
        elif self.byte_count < 1024 * 1024:
            return f"{self.byte_count / 1024:.1f}K"
        elif self.byte_count < 1024 * 1024 * 1024:
            return f"{self.byte_count / (1024 * 1024):.1f}M"
        else:
            return f"{self.byte_count / (1024 * 1024 * 1024):.1f}G"
    
    def add_rule(self, rule: Rule):
        """Add a rule to this chain"""
        self.rules.append(rule)
    
    def get_rules_by_target(self, target: str) -> List[Rule]:
        """Get all rules with a specific target"""
        return [rule for rule in self.rules if rule.target == target]
    
    def get_docker_rules(self) -> List[Rule]:
        """Get all Docker-related rules"""
        return [rule for rule in self.rules if rule.is_docker_related]
    
    def get_chain_target_rules(self) -> List[Rule]:
        """Get all rules that target other chains (not terminal actions)"""
        return [rule for rule in self.rules if rule.is_chain_target]
    
    def get_referenced_chain_names(self) -> List[str]:
        """Get names of all chains referenced by rules in this chain"""
        return list(set(rule.target for rule in self.rules if rule.is_chain_target))
    
    def __repr__(self) -> str:
        policy_str = f", policy={self.policy.value}" if self.policy else ""
        return (
            f"Chain(name={self.name}{policy_str}, "
            f"rules={len(self.rules)}, "
            f"pkts={self.packet_count}, bytes={self.bytes_human})"
        )


@dataclass
class Table:
    """
    Represents an iptables table (filter, nat, mangle, raw).
    
    A table contains multiple chains.
    """
    name: str
    chains: Dict[str, Chain] = field(default_factory=dict)
    
    def add_chain(self, chain: Chain):
        """Add a chain to this table"""
        self.chains[chain.name] = chain
    
    def get_chain(self, name: str) -> Optional[Chain]:
        """Get a chain by name"""
        return self.chains.get(name)
    
    def get_builtin_chains(self) -> List[Chain]:
        """Get all built-in chains"""
        return [chain for chain in self.chains.values() if chain.is_builtin]
    
    def get_custom_chains(self) -> List[Chain]:
        """Get all custom chains"""
        return [chain for chain in self.chains.values() if not chain.is_builtin]
    
    def get_docker_chains(self) -> List[Chain]:
        """Get all Docker-related chains"""
        return [chain for chain in self.chains.values() if chain.is_docker_chain]
    
    def get_chains_referencing(self, chain_name: str) -> List[Chain]:
        """Get all chains that have rules targeting the specified chain"""
        return [
            chain for chain in self.chains.values()
            if chain_name in chain.get_referenced_chain_names()
        ]
    
    def get_chain_references(self) -> Dict[str, List[str]]:
        """
        Get a mapping of chain names to the chains they reference.
        Returns dict where key is chain name and value is list of referenced chain names.
        """
        return {
            chain.name: chain.get_referenced_chain_names()
            for chain in self.chains.values()
        }
    
    @property
    def total_rules(self) -> int:
        """Total number of rules across all chains"""
        return sum(len(chain.rules) for chain in self.chains.values())
    
    def __repr__(self) -> str:
        return (
            f"Table(name={self.name}, "
            f"chains={len(self.chains)}, "
            f"total_rules={self.total_rules})"
        )


@dataclass
class IptablesConfig:
    """
    Complete iptables configuration.
    
    Contains all tables (filter, nat, mangle, raw).
    """
    tables: Dict[str, Table] = field(default_factory=dict)
    
    def add_table(self, table: Table):
        """Add a table to the configuration"""
        self.tables[table.name] = table
    
    def get_table(self, name: str) -> Optional[Table]:
        """Get a table by name"""
        return self.tables.get(name)
    
    def get_all_chains(self) -> List[Chain]:
        """Get all chains from all tables"""
        chains = []
        for table in self.tables.values():
            chains.extend(table.chains.values())
        return chains
    
    def get_all_docker_chains(self) -> List[Chain]:
        """Get all Docker-related chains from all tables"""
        chains = []
        for table in self.tables.values():
            chains.extend(table.get_docker_chains())
        return chains
    
    @property
    def total_rules(self) -> int:
        """Total number of rules across all tables"""
        return sum(table.total_rules for table in self.tables.values())
    
    def __repr__(self) -> str:
        return (
            f"IptablesConfig(tables={len(self.tables)}, "
            f"total_rules={self.total_rules})"
        )
