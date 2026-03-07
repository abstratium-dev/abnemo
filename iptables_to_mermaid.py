#!/usr/bin/env python3
"""
Convert iptables rules with Docker enrichment data into a Mermaid activity diagram.
Shows how incoming packets are routed through the firewall.
"""

import re
import sys
from typing import Dict, List, Tuple, Set
from collections import defaultdict


class DockerEnrichment:
    """Parse and store Docker enrichment data."""
    
    def __init__(self):
        self.containers: Dict[str, Tuple[str, str]] = {}  # IP -> (container_name, network_name)
        self.networks: Dict[str, Tuple[str, str]] = {}  # interface_id -> (network_name, subnet)
        self.interface_to_network: Dict[str, str] = {}  # interface_id -> network_name
        
    def add_container(self, ip: str, container: str, network: str, gateway: str):
        """Add container mapping."""
        self.containers[ip] = (container, network)
        
    def add_network(self, network: str, subnet: str, gateway: str, driver: str, interface_id: str):
        """Add network mapping."""
        self.networks[interface_id] = (network, subnet)
        self.interface_to_network[interface_id] = network
        
    def get_container_name(self, ip: str) -> str:
        """Get container name for IP, or return IP if not found."""
        if ip in self.containers:
            container, network = self.containers[ip]
            return f"{container} ({ip})"
        return ip
        
    def get_network_name(self, interface: str) -> str:
        """Get network name for interface, or return interface if not found."""
        # Handle both full interface names and short IDs
        for iface_id, (network, subnet) in self.networks.items():
            if iface_id in interface or interface in iface_id:
                return f"{network} ({interface[:12]})"
        return interface


class IptablesParser:
    """Parse iptables rules and generate Mermaid diagram."""
    
    def __init__(self, enrichment: DockerEnrichment):
        self.enrichment = enrichment
        self.chains: Dict[str, List[Dict]] = defaultdict(list)
        self.chain_policies: Dict[str, str] = {}
        
    @staticmethod
    def sanitize_label(text: str, max_length: int = 50) -> str:
        """Sanitize text for Mermaid labels - escape special chars and truncate."""
        # Truncate long network names first
        if len(text) > max_length:
            text = text[:max_length] + "..."
        
        # Replace ALL problematic Mermaid characters with safe alternatives
        # Parentheses, brackets, and braces are all Mermaid syntax
        text = text.replace('(', '‹')  # Use angle brackets instead
        text = text.replace(')', '›')
        text = text.replace('[', '‹')
        text = text.replace(']', '›')
        text = text.replace('{', '‹')
        text = text.replace('}', '›')
        text = text.replace('"', "'")
        
        return text
        
    def parse_chain_header(self, line: str) -> Tuple[str, str]:
        """Parse chain header line."""
        # Chain INPUT (policy DROP 2852 packets, 143K bytes)
        match = re.match(r'Chain (\S+) \(policy (\S+)', line)
        if match:
            return match.group(1), match.group(2)
        # Chain DOCKER (9 references)
        match = re.match(r'Chain (\S+)', line)
        if match:
            return match.group(1), "NONE"
        return None, None
        
    def parse_rule(self, line: str) -> Dict:
        """Parse a single iptables rule."""
        parts = line.split()
        if len(parts) < 4:
            return None
            
        rule = {
            'pkts': parts[0],
            'bytes': parts[1],
            'target': parts[2],
            'prot': parts[3],
            'opt': parts[4] if len(parts) > 4 else '',
            'in': parts[5] if len(parts) > 5 else '*',
            'out': parts[6] if len(parts) > 6 else '*',
            'source': parts[7] if len(parts) > 7 else '0.0.0.0/0',
            'destination': parts[8] if len(parts) > 8 else '0.0.0.0/0',
            'extra': ' '.join(parts[9:]) if len(parts) > 9 else ''
        }
        return rule
        
    def parse_file(self, filepath: str):
        """Parse the iptables file."""
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        current_chain = None
        in_docker_section = False
        in_iptables_section = False
        
        for line in lines:
            line = line.strip()
            
            # Skip Docker enrichment section
            if line.startswith('=== DOCKER ENRICHMENT DATA ==='):
                in_docker_section = True
                continue
            elif line.startswith('=== END DOCKER ENRICHMENT DATA ==='):
                in_docker_section = False
                in_iptables_section = True
                continue
                
            if in_docker_section:
                # Parse Docker data
                if line.startswith('#') or not line:
                    continue
                parts = line.split('|')
                if len(parts) == 4:
                    # Container line
                    self.enrichment.add_container(parts[0], parts[1], parts[2], parts[3])
                elif len(parts) == 5:
                    # Network line
                    self.enrichment.add_network(parts[0], parts[1], parts[2], parts[3], parts[4])
                continue
                
            if not in_iptables_section:
                continue
                
            # Parse chain headers
            if line.startswith('Chain '):
                chain_name, policy = self.parse_chain_header(line)
                if chain_name:
                    current_chain = chain_name
                    self.chain_policies[chain_name] = policy
                continue
                
            # Skip header lines
            if 'pkts bytes target' in line:
                continue
                
            # Parse rules
            if current_chain and line and not line.startswith('Chain'):
                rule = self.parse_rule(line)
                if rule:
                    self.chains[current_chain].append(rule)
                    
    def generate_mermaid(self) -> str:
        """Generate Mermaid activity diagram."""
        lines = []
        lines.append("flowchart TD")
        lines.append("    %% Packet Flow Through Firewall")
        lines.append("")
        
        # Start node
        lines.append("    Start([Incoming Packet]) --> InputChain")
        lines.append("")
        
        # INPUT chain
        lines.append("    %% INPUT Chain")
        lines.append(f"    InputChain{{INPUT Chain<br/>Policy: {self.chain_policies.get('INPUT', 'ACCEPT')}}}")
        
        if 'INPUT' in self.chains:
            for idx, rule in enumerate(self.chains['INPUT'][:10]):  # Limit to first 10 rules
                node_id = f"Input{idx}"
                target = rule['target']
                
                # Enrich with Docker info
                in_iface = rule['in']
                if in_iface != '*':
                    in_iface = self.enrichment.get_network_name(in_iface)
                    
                dest = rule['destination']
                if dest != '0.0.0.0/0':
                    dest = self.enrichment.get_container_name(dest)
                
                label = f"{target}"
                if rule['prot'] != '0':
                    label += f"<br/>proto: {rule['prot']}"
                if in_iface != '*':
                    label += f"<br/>in: {self.sanitize_label(in_iface, 40)}"
                if dest != '0.0.0.0/0':
                    label += f"<br/>dst: {self.sanitize_label(dest, 35)}"
                    
                lines.append(f"    InputChain --> {node_id}[{self.sanitize_label(label, 100)}]")
                
                # If target is another chain, link to it
                if target in self.chains and target.startswith('ufw-'):
                    lines.append(f"    {node_id} --> {target.replace('-', '_')}Chain")
                    
        lines.append("")
        
        # FORWARD chain
        lines.append("    %% FORWARD Chain")
        lines.append(f"    ForwardChain{{FORWARD Chain<br/>Policy: {self.chain_policies.get('FORWARD', 'ACCEPT')}}}")
        lines.append("    Start --> ForwardChain")
        
        if 'FORWARD' in self.chains:
            for idx, rule in enumerate(self.chains['FORWARD'][:10]):
                node_id = f"Forward{idx}"
                target = rule['target']
                
                # Enrich with Docker info
                in_iface = rule['in']
                out_iface = rule['out']
                if in_iface != '*':
                    in_iface = self.enrichment.get_network_name(in_iface)
                if out_iface != '*':
                    out_iface = self.enrichment.get_network_name(out_iface)
                    
                label = f"{target}"
                if in_iface != '*':
                    label += f"<br/>in: {self.sanitize_label(in_iface, 40)}"
                if out_iface != '*':
                    label += f"<br/>out: {self.sanitize_label(out_iface, 40)}"
                    
                lines.append(f"    ForwardChain --> {node_id}[{self.sanitize_label(label, 100)}]")
                
                # Link to Docker chains
                if target in ['DOCKER-USER', 'DOCKER-FORWARD', 'DOCKER']:
                    lines.append(f"    {node_id} --> {target.replace('-', '_')}Chain")
                    
        lines.append("")
        
        # DOCKER-USER chain
        if 'DOCKER-USER' in self.chains:
            lines.append("    %% DOCKER-USER Chain")
            lines.append("    DOCKER_USERChain{DOCKER-USER Chain}")
            lines.append("    DOCKER_USERChain --> DOCKER_FORWARDChain")
            lines.append("")
            
        # DOCKER-FORWARD chain
        if 'DOCKER-FORWARD' in self.chains:
            lines.append("    %% DOCKER-FORWARD Chain")
            lines.append("    DOCKER_FORWARDChain{DOCKER-FORWARD Chain}")
            
            for idx, rule in enumerate(self.chains['DOCKER-FORWARD'][:8]):
                node_id = f"DockerForward{idx}"
                target = rule['target']
                in_iface = rule['in']
                out_iface = rule['out']
                
                if in_iface != '*':
                    in_iface = self.enrichment.get_network_name(in_iface)
                if out_iface != '*':
                    out_iface = self.enrichment.get_network_name(out_iface)
                    
                label = f"{target}"
                if in_iface != '*':
                    label += f"<br/>in: {self.sanitize_label(in_iface, 40)}"
                if out_iface != '*':
                    label += f"<br/>out: {self.sanitize_label(out_iface, 40)}"
                    
                lines.append(f"    DOCKER_FORWARDChain --> {node_id}[{self.sanitize_label(label, 100)}]")
                
                if target == 'DOCKER-CT':
                    lines.append(f"    {node_id} --> DOCKER_CTChain")
                elif target == 'DOCKER-BRIDGE':
                    lines.append(f"    {node_id} --> DOCKER_BRIDGEChain")
                elif target == 'ACCEPT':
                    lines.append(f"    {node_id} --> Accept([ACCEPT])")
                    
            lines.append("")
            
        # DOCKER chain with enriched IPs
        if 'DOCKER' in self.chains:
            lines.append("    %% DOCKER Chain (sample rules)")
            lines.append("    DOCKERChain{DOCKER Chain}")
            
            # Show first 5 ACCEPT rules with container info
            accept_rules = [r for r in self.chains['DOCKER'] if r['target'] == 'ACCEPT'][:5]
            for idx, rule in enumerate(accept_rules):
                node_id = f"Docker{idx}"
                dest = rule['destination']
                dest_enriched = self.enrichment.get_container_name(dest)
                in_iface = rule['in']
                out_iface = rule['out']
                
                if out_iface != '*':
                    out_iface = self.enrichment.get_network_name(out_iface)
                    
                label = f"ACCEPT"
                if rule['prot'] != '0':
                    label += f"<br/>proto: {rule['prot']}"
                if dest_enriched != dest:
                    label += f"<br/>to: {self.sanitize_label(dest_enriched, 35)}"
                else:
                    label += f"<br/>to: {dest}"
                if 'dpt:' in rule['extra']:
                    port = re.search(r'dpt:(\d+)', rule['extra'])
                    if port:
                        label += f"<br/>port: {port.group(1)}"
                if out_iface != '*':
                    label += f"<br/>net: {self.sanitize_label(out_iface, 35)}"
                    
                lines.append(f"    DOCKERChain --> {node_id}[{self.sanitize_label(label, 120)}]")
                lines.append(f"    {node_id} --> Accept")
                
            # Show DROP rules
            drop_rules = [r for r in self.chains['DOCKER'] if r['target'] == 'DROP'][:3]
            for idx, rule in enumerate(drop_rules):
                node_id = f"DockerDrop{idx}"
                out_iface = rule['out']
                if out_iface != '*':
                    out_iface = self.enrichment.get_network_name(out_iface)
                    
                label = f"DROP<br/>net: {self.sanitize_label(out_iface, 40)}"
                lines.append(f"    DOCKERChain --> {node_id}[{self.sanitize_label(label, 100)}]")
                lines.append(f"    {node_id} --> Drop([DROP])")
                
            lines.append("")
            
        # DOCKER-CT chain
        if 'DOCKER-CT' in self.chains:
            lines.append("    %% DOCKER-CT Chain (Connection Tracking)")
            lines.append("    DOCKER_CTChain{DOCKER-CT Chain}")
            
            for idx, rule in enumerate(self.chains['DOCKER-CT'][:5]):
                node_id = f"DockerCT{idx}"
                out_iface = rule['out']
                if out_iface != '*':
                    out_iface = self.enrichment.get_network_name(out_iface)
                    
                label = f"ACCEPT<br/>ESTABLISHED"
                if out_iface != '*':
                    label += f"<br/>net: {self.sanitize_label(out_iface, 40)}"
                    
                lines.append(f"    DOCKER_CTChain --> {node_id}[{self.sanitize_label(label, 100)}]")
                lines.append(f"    {node_id} --> Accept")
                
            lines.append("")
            
        # DOCKER-BRIDGE chain
        if 'DOCKER-BRIDGE' in self.chains:
            lines.append("    %% DOCKER-BRIDGE Chain")
            lines.append("    DOCKER_BRIDGEChain{DOCKER-BRIDGE Chain}")
            
            for idx, rule in enumerate(self.chains['DOCKER-BRIDGE'][:5]):
                node_id = f"DockerBridge{idx}"
                out_iface = rule['out']
                if out_iface != '*':
                    out_iface = self.enrichment.get_network_name(out_iface)
                    
                label = f"DOCKER"
                if out_iface != '*':
                    label += f"<br/>net: {self.sanitize_label(out_iface, 40)}"
                    
                lines.append(f"    DOCKER_BRIDGEChain --> {node_id}[{self.sanitize_label(label, 100)}]")
                lines.append(f"    {node_id} --> DOCKERChain")
                
            lines.append("")
            
        # UFW chains (simplified)
        lines.append("    %% UFW Chains (simplified)")
        lines.append("    ufw_before_inputChain{ufw-before-input}")
        lines.append("    Input0 --> ufw_before_inputChain")
        lines.append("    ufw_before_inputChain --> ufwAccept([ACCEPT<br/>Established/Related])")
        lines.append("    ufw_before_inputChain --> ufwUser{ufw-user-input}")
        lines.append("    ufwUser --> ufwAcceptPorts([ACCEPT<br/>Allowed Ports])")
        lines.append("    ufwUser --> ufwDrop([DROP<br/>Policy])")
        lines.append("")
        
        # Final nodes
        lines.append("    %% Final Decisions")
        lines.append("    Accept:::acceptStyle")
        lines.append("    Drop:::dropStyle")
        lines.append("    ufwAccept:::acceptStyle")
        lines.append("    ufwAcceptPorts:::acceptStyle")
        lines.append("    ufwDrop:::dropStyle")
        lines.append("")
        
        # Styling
        lines.append("    %% Styling")
        lines.append("    classDef acceptStyle fill:#90EE90,stroke:#006400,stroke-width:2px")
        lines.append("    classDef dropStyle fill:#FFB6C6,stroke:#8B0000,stroke-width:2px")
        
        return '\n'.join(lines)


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python iptables_to_mermaid.py <iptables_file>")
        sys.exit(1)
        
    filepath = sys.argv[1]
    
    # Create enrichment and parser
    enrichment = DockerEnrichment()
    parser = IptablesParser(enrichment)
    
    # Parse the file
    parser.parse_file(filepath)
    
    # Generate Mermaid diagram
    mermaid = parser.generate_mermaid()
    
    # Output
    print(mermaid)
    
    # Also save to file
    output_file = filepath.replace('.txt', '_diagram.mmd')
    with open(output_file, 'w') as f:
        f.write(mermaid)
    print(f"\n\n# Diagram saved to: {output_file}", file=sys.stderr)


if __name__ == '__main__':
    main()
