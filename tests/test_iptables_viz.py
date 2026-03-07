#!/usr/bin/env python3
"""Test script to demonstrate improved iptables visualization"""

from iptables_visualizer import IptablesParser, MermaidGenerator

# Sample iptables output with various rule types
sample_output = """Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0           
  123  4567 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 ctstate NEW,ESTABLISHED
  456 78901 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80
  789 12345 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
   12   345 DROP       all  --  *      *       192.168.1.100        0.0.0.0/0           
   34   567 REJECT     tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:23 reject-with icmp-port-unreachable

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 DOCKER     all  --  *      docker0 0.0.0.0/0            0.0.0.0/0           
    0     0 ACCEPT     all  --  *      docker0 0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           
"""

# Parse the output
parser = IptablesParser()
chains = parser.parse_output(sample_output)

# Generate Mermaid diagram
generator = MermaidGenerator(chains)
mermaid_code = generator.generate(simplified=True, max_rules_per_type=10)

print("Generated Mermaid Diagram:")
print("=" * 80)
print(mermaid_code)
print("=" * 80)
print("\nThe diagram now shows detailed information for each rule including:")
print("- Protocol (TCP, UDP, ICMP)")
print("- Source and destination IPs (when not 0.0.0.0/0)")
print("- Network interfaces (in/out)")
print("- Destination and source ports")
print("- Connection states (NEW, ESTABLISHED, RELATED)")
print("- All in smaller, more readable font sizes (11px for rules)")
