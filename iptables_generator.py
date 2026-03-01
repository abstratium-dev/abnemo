#!/usr/bin/env python3
"""
IPTables Rule Generator - Creates iptables rules to block specific IP addresses
"""

import json
import os
from datetime import datetime


class IPTablesGenerator:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_domains = set()
    
    def add_ip_to_blocklist(self, ip_address):
        """Add an IP address to the block list"""
        self.blocked_ips.add(ip_address)
    
    def add_domain_to_blocklist(self, domain):
        """Add a domain to the block list"""
        self.blocked_domains.add(domain)
    
    def load_from_traffic_log(self, log_file, min_bytes=None, min_packets=None, 
                              specific_ips=None, specific_domains=None):
        """
        Load IPs to block from a traffic log file based on criteria
        
        Args:
            log_file: Path to traffic log JSON file
            min_bytes: Minimum bytes threshold to auto-block
            min_packets: Minimum packets threshold to auto-block
            specific_ips: List of specific IPs to block
            specific_domains: List of specific domains to block
        """
        with open(log_file, 'r') as f:
            data = json.load(f)
        
        traffic_data = data.get('traffic_by_ip', {})
        
        for ip, stats in traffic_data.items():
            # Check if IP meets threshold criteria
            if min_bytes and stats['bytes'] >= min_bytes:
                self.blocked_ips.add(ip)
                continue
            
            if min_packets and stats['packets'] >= min_packets:
                self.blocked_ips.add(ip)
                continue
            
            # Check if IP is in specific list
            if specific_ips and ip in specific_ips:
                self.blocked_ips.add(ip)
            
            # Check if any domain matches
            if specific_domains:
                for domain in stats.get('domains', []):
                    if any(blocked_domain in domain for blocked_domain in specific_domains):
                        self.blocked_ips.add(ip)
                        self.blocked_domains.add(domain)
    
    def generate_iptables_rules(self, chain="OUTPUT", action="DROP"):
        """
        Generate iptables rules to block the collected IPs
        
        Args:
            chain: IPTables chain (OUTPUT for outgoing, FORWARD for forwarding)
            action: Action to take (DROP, REJECT)
        
        Returns:
            List of iptables command strings
        """
        rules = []
        
        # Add header comments
        rules.append("#!/bin/bash")
        rules.append("#")
        rules.append(f"# IPTables rules generated on {datetime.now().isoformat()}")
        rules.append(f"# Total IPs to block: {len(self.blocked_ips)}")
        rules.append("#")
        rules.append("")
        
        # Add rules for each IP
        for ip in sorted(self.blocked_ips):
            rule = f"iptables -A {chain} -d {ip} -j {action}"
            rules.append(rule)
        
        return rules
    
    def generate_iptables_restore_format(self, chain="OUTPUT", action="DROP"):
        """
        Generate iptables-restore format rules (more efficient for bulk operations)
        
        Args:
            chain: IPTables chain (OUTPUT for outgoing, FORWARD for forwarding)
            action: Action to take (DROP, REJECT)
        
        Returns:
            String in iptables-restore format
        """
        lines = []
        lines.append("*filter")
        lines.append(f":{chain} ACCEPT [0:0]")
        
        for ip in sorted(self.blocked_ips):
            lines.append(f"-A {chain} -d {ip} -j {action}")
        
        lines.append("COMMIT")
        
        return "\n".join(lines)
    
    def save_rules(self, output_file, format="script", chain="OUTPUT", action="DROP"):
        """
        Save iptables rules to a file
        
        Args:
            output_file: Path to output file
            format: 'script' for bash script or 'restore' for iptables-restore format
            chain: IPTables chain
            action: Action to take
        """
        if format == "script":
            rules = self.generate_iptables_rules(chain, action)
            content = "\n".join(rules)
        elif format == "restore":
            content = self.generate_iptables_restore_format(chain, action)
        else:
            raise ValueError(f"Unknown format: {format}")
        
        with open(output_file, 'w') as f:
            f.write(content)
        
        # Make script executable if it's a bash script
        if format == "script":
            os.chmod(output_file, 0o755)
        
        print(f"[+] IPTables rules saved to: {output_file}")
        print(f"[+] Total IPs to block: {len(self.blocked_ips)}")
        
        return output_file
    
    def generate_unblock_script(self, output_file, chain="OUTPUT", action="DROP"):
        """
        Generate a script to remove/unblock the rules
        
        Args:
            output_file: Path to output file
            chain: IPTables chain
            action: Action to take
        """
        rules = []
        rules.append("#!/bin/bash")
        rules.append("#")
        rules.append(f"# IPTables unblock script generated on {datetime.now().isoformat()}")
        rules.append(f"# Removes {len(self.blocked_ips)} blocking rules")
        rules.append("#")
        rules.append("")
        
        # Use -D to delete rules instead of -A to add
        for ip in sorted(self.blocked_ips):
            rule = f"iptables -D {chain} -d {ip} -j {action}"
            rules.append(rule)
        
        content = "\n".join(rules)
        
        with open(output_file, 'w') as f:
            f.write(content)
        
        os.chmod(output_file, 0o755)
        
        print(f"[+] Unblock script saved to: {output_file}")
        
        return output_file
    
    def print_summary(self):
        """Print summary of what will be blocked"""
        print("\n" + "="*80)
        print(f"{'IPTABLES BLOCK SUMMARY':^80}")
        print("="*80)
        print(f"Total IPs to block: {len(self.blocked_ips)}")
        
        if self.blocked_domains:
            print(f"Domains identified: {len(self.blocked_domains)}")
            print("\nDomains to block:")
            for domain in sorted(self.blocked_domains):
                print(f"  - {domain}")
        
        print("\nIPs to block:")
        for ip in sorted(list(self.blocked_ips)[:20]):
            print(f"  - {ip}")
        
        if len(self.blocked_ips) > 20:
            print(f"  ... and {len(self.blocked_ips) - 20} more")
        
        print("="*80 + "\n")
