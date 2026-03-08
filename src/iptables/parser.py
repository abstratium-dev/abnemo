#!/usr/bin/env python3
"""
iptables Parser - Parse iptables output and populate the model
"""

import subprocess
import re
from typing import Optional, List, Tuple
import sys
import os

# Add parent directory to path to import docker_enrichment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from docker_enrichment import DockerEnricher
from src.iptables.model import (
    IptablesConfig, Table, Chain, Rule, 
    DockerEnrichedField, Policy
)


class IptablesParser:
    """
    Parse iptables output and create an in-memory model.
    
    Supports:
    - Parsing output from `iptables -L -v -n`
    - Docker enrichment for interfaces and IP addresses
    - Multiple tables (filter, nat, mangle, raw)
    """
    
    def __init__(self, docker_enricher: Optional[DockerEnricher] = None):
        """
        Initialize the parser.
        
        Args:
            docker_enricher: Optional DockerEnricher instance for enriching
                           Docker-related fields. If None, creates a new one.
        """
        self.docker_enricher = docker_enricher or DockerEnricher()
        self.config = IptablesConfig()
    
    def parse_from_command(self, table: str = 'filter', use_sudo: bool = True) -> IptablesConfig:
        """
        Run iptables command and parse the output.
        
        Args:
            table: Table name (filter, nat, mangle, raw)
            use_sudo: Whether to use sudo (required for iptables)
        
        Returns:
            IptablesConfig object with parsed data
        """
        cmd = ['iptables', '-t', table, '-L', '-v', '-n']
        if use_sudo:
            cmd = ['sudo'] + cmd
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"iptables command failed: {result.stderr}")
            
            return self.parse_output(result.stdout, table)
        
        except subprocess.TimeoutExpired:
            raise RuntimeError("iptables command timed out")
        except FileNotFoundError:
            raise RuntimeError("iptables command not found")
    
    def parse_output(self, output: str, table_name: str = 'filter') -> IptablesConfig:
        """
        Parse iptables output text.
        
        Args:
            output: Output from `iptables -L -v -n`
            table_name: Name of the table being parsed
        
        Returns:
            IptablesConfig object with parsed data
        """
        table = Table(name=table_name)
        lines = output.strip().split('\n')
        
        current_chain: Optional[Chain] = None
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines
            if not line:
                i += 1
                continue
            
            # Parse chain header: "Chain INPUT (policy DROP 2852 packets, 143K bytes)"
            chain_match = re.match(
                r'Chain\s+(\S+)\s+\(policy\s+(\S+)\s+(\S+)\s+packets?,\s+(\S+)\s+bytes?\)',
                line
            )
            if chain_match:
                chain_name = chain_match.group(1)
                policy_str = chain_match.group(2)
                packet_count = self._parse_count(chain_match.group(3))
                byte_count = self._parse_byte_count(chain_match.group(4))
                
                try:
                    policy = Policy(policy_str)
                except ValueError:
                    policy = None
                
                current_chain = Chain(
                    name=chain_name,
                    policy=policy,
                    packet_count=packet_count,
                    byte_count=byte_count
                )
                table.add_chain(current_chain)
                i += 1
                continue
            
            # Parse chain header without policy (custom chains): "Chain DOCKER (1 references)"
            chain_no_policy_match = re.match(r'Chain\s+(\S+)\s+\((\d+)\s+references?\)', line)
            if chain_no_policy_match:
                chain_name = chain_no_policy_match.group(1)
                current_chain = Chain(name=chain_name)
                table.add_chain(current_chain)
                i += 1
                continue
            
            # Skip column headers
            if line.startswith('pkts') or line.startswith('num'):
                i += 1
                continue
            
            # Parse rule line
            if current_chain is not None:
                rule = self._parse_rule_line(line)
                if rule:
                    current_chain.add_rule(rule)
            
            i += 1
        
        self.config.add_table(table)
        return self.config
    
    def parse_all_tables(self, use_sudo: bool = True) -> IptablesConfig:
        """
        Parse all iptables tables (filter, nat, mangle, raw).
        
        Args:
            use_sudo: Whether to use sudo
        
        Returns:
            IptablesConfig with all tables
        """
        tables = ['filter', 'nat', 'mangle', 'raw']
        
        for table_name in tables:
            try:
                self.parse_from_command(table=table_name, use_sudo=use_sudo)
            except RuntimeError as e:
                # Some tables might not be available
                print(f"Warning: Could not parse table {table_name}: {e}", file=sys.stderr)
        
        return self.config
    
    def parse_file(self, filepath: str, table_name: str = 'filter') -> IptablesConfig:
        """
        Parse iptables output from a file.
        
        Args:
            filepath: Path to file containing iptables output
            table_name: Name of the table
        
        Returns:
            IptablesConfig object
        """
        with open(filepath, 'r') as f:
            content = f.read()
        
        return self.parse_output(content, table_name)
    
    def _parse_rule_line(self, line: str) -> Optional[Rule]:
        """
        Parse a single rule line.
        
        Format: pkts bytes target prot opt in out source destination [extra]
        Example: "515K  363M ufw-before-logging-input  0    --  *      *       0.0.0.0/0            0.0.0.0/0"
        """
        # Split by whitespace, but be careful with alignment
        parts = line.split()
        
        if len(parts) < 9:
            return None
        
        try:
            # Parse packet and byte counts
            pkts = self._parse_count(parts[0])
            bytes_count = self._parse_byte_count(parts[1])
            
            # Parse other fields
            target = parts[2]
            prot = parts[3]
            opt = parts[4]
            in_iface = parts[5]
            out_iface = parts[6]
            source = parts[7]
            destination = parts[8]
            
            # Any remaining parts are extra options
            extra = ' '.join(parts[9:]) if len(parts) > 9 else ""
            
            # Create Docker-enriched fields
            in_interface = self._create_enriched_interface(in_iface)
            out_interface = self._create_enriched_interface(out_iface)
            source_field = self._create_enriched_ip(source)
            destination_field = self._create_enriched_ip(destination)
            
            return Rule(
                pkts=pkts,
                bytes=bytes_count,
                target=target,
                prot=prot,
                opt=opt,
                in_interface=in_interface,
                out_interface=out_interface,
                source=source_field,
                destination=destination_field,
                extra=extra
            )
        
        except (ValueError, IndexError) as e:
            # Skip malformed lines
            return None
    
    def _create_enriched_interface(self, interface: str) -> DockerEnrichedField:
        """Create a DockerEnrichedField for an interface"""
        enrichment = self.docker_enricher.enrich_interface(interface)
        return DockerEnrichedField(original=interface, docker_info=enrichment)
    
    def _create_enriched_ip(self, ip_address: str) -> DockerEnrichedField:
        """Create a DockerEnrichedField for an IP address"""
        enrichment = self.docker_enricher.enrich_ip(ip_address)
        return DockerEnrichedField(original=ip_address, docker_info=enrichment)
    
    def _parse_count(self, count_str: str) -> int:
        """
        Parse packet/byte count with K/M/G suffixes.
        
        Examples: "515K" -> 515000, "363M" -> 363000000
        """
        count_str = count_str.strip().upper()
        
        if count_str == '0' or count_str == '--':
            return 0
        
        multipliers = {
            'K': 1000,
            'M': 1000000,
            'G': 1000000000,
            'T': 1000000000000,
        }
        
        for suffix, multiplier in multipliers.items():
            if count_str.endswith(suffix):
                try:
                    value = float(count_str[:-1])
                    return int(value * multiplier)
                except ValueError:
                    return 0
        
        try:
            return int(count_str)
        except ValueError:
            return 0
    
    def _parse_byte_count(self, byte_str: str) -> int:
        """Parse byte count (same as _parse_count but kept separate for clarity)"""
        return self._parse_count(byte_str)


def load_iptables_config(
    enrichment_file: Optional[str] = None,
    iptables_file: Optional[str] = None,
    table: str = 'filter',
    use_sudo: bool = True
) -> IptablesConfig:
    """
    Convenience function to load iptables configuration.
    
    Args:
        enrichment_file: Optional path to Docker enrichment data file
        iptables_file: Optional path to iptables output file (if None, runs command)
        table: Table name to parse (if parsing from command)
        use_sudo: Whether to use sudo when running iptables command
    
    Returns:
        IptablesConfig object
    """
    # Load Docker enrichment data
    enricher = None
    if enrichment_file:
        with open(enrichment_file, 'r') as f:
            enrichment_data = f.read()
        enricher = DockerEnricher(enrichment_data=enrichment_data)
    else:
        enricher = DockerEnricher()
    
    # Create parser
    parser = IptablesParser(docker_enricher=enricher)
    
    # Parse iptables
    if iptables_file:
        return parser.parse_file(iptables_file, table_name=table)
    else:
        return parser.parse_from_command(table=table, use_sudo=use_sudo)


def main():
    """Example usage"""
    import argparse
    
    arg_parser = argparse.ArgumentParser(description='Parse iptables configuration')
    arg_parser.add_argument(
        '--file', '-f',
        help='Path to iptables output file (if not provided, runs iptables command)'
    )
    arg_parser.add_argument(
        '--enrichment', '-e',
        help='Path to Docker enrichment data file'
    )
    arg_parser.add_argument(
        '--table', '-t',
        default='filter',
        choices=['filter', 'nat', 'mangle', 'raw'],
        help='Table to parse (default: filter)'
    )
    arg_parser.add_argument(
        '--all-tables', '-a',
        action='store_true',
        help='Parse all tables'
    )
    arg_parser.add_argument(
        '--no-sudo',
        action='store_true',
        help='Do not use sudo (will likely fail unless running as root)'
    )
    
    args = arg_parser.parse_args()
    
    # Load configuration
    enricher = None
    if args.enrichment:
        with open(args.enrichment, 'r') as f:
            enrichment_data = f.read()
        enricher = DockerEnricher(enrichment_data=enrichment_data)
    else:
        enricher = DockerEnricher()
    
    parser = IptablesParser(docker_enricher=enricher)
    
    try:
        if args.file:
            config = parser.parse_file(args.file, table_name=args.table)
        elif args.all_tables:
            config = parser.parse_all_tables(use_sudo=not args.no_sudo)
        else:
            config = parser.parse_from_command(table=args.table, use_sudo=not args.no_sudo)
        
        # Print summary
        print(f"\n{config}")
        print(f"\nTables: {len(config.tables)}")
        
        for table_name, table in config.tables.items():
            print(f"\n{'='*60}")
            print(f"Table: {table_name}")
            print(f"{'='*60}")
            
            for chain_name, chain in table.chains.items():
                print(f"\n{chain}")
                
                if chain.rules:
                    print(f"  Docker-related rules: {chain.docker_rules_count}/{len(chain.rules)}")
                    
                    # Show first few rules
                    for i, rule in enumerate(chain.rules[:5]):
                        flow = rule.get_flow_description()
                        docker_marker = "🐳 " if rule.is_docker_related else "   "
                        print(f"  {docker_marker}[{i+1}] {rule.target:20s} {flow}")
                    
                    if len(chain.rules) > 5:
                        print(f"  ... and {len(chain.rules) - 5} more rules")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
