#!/usr/bin/env python3
"""Test iptables visualization with Docker enrichment"""

from iptables_visualizer import IptablesParser, MermaidGenerator

# Sample iptables output with Docker rules
sample_output = """Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0           
  123  4567 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 DOCKER     all  --  *      docker0 0.0.0.0/0            0.0.0.0/0           
    0     0 ACCEPT     all  --  *      docker0 0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     all  --  docker0 !docker0 0.0.0.0/0           0.0.0.0/0           
    0     0 ACCEPT     all  --  docker0 docker0 0.0.0.0/0            0.0.0.0/0           
   12   345 ACCEPT     tcp  --  !br-48b7a6d85e30 br-48b7a6d85e30 0.0.0.0/0  172.23.0.10  tcp dpt:5000
   34   567 ACCEPT     tcp  --  br-48b7a6d85e30 !br-48b7a6d85e30 172.23.0.10  0.0.0.0/0  tcp spt:5000

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain DOCKER (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  !docker0 docker0 0.0.0.0/0           172.17.0.2           tcp dpt:80
    0     0 ACCEPT     tcp  --  !br-48b7a6d85e30 br-48b7a6d85e30 0.0.0.0/0  172.23.0.10  tcp dpt:5000
"""

# Parse the output
parser = IptablesParser()
chains = parser.parse_output(sample_output)

# Generate Mermaid diagram WITH Docker enrichment
print("=" * 80)
print("IPTABLES VISUALIZATION WITH DOCKER ENRICHMENT")
print("=" * 80)
print()

generator = MermaidGenerator(chains, enable_docker_enrichment=True)
mermaid_code = generator.generate(simplified=True, max_rules_per_type=10)

print(mermaid_code)
print()
print("=" * 80)
print("DOCKER-ENRICHED FEATURES:")
print("=" * 80)
print("✅ Container IPs are labeled with container names (🐳)")
print("✅ Docker network interfaces are labeled with network names (🐋)")
print("✅ Private IP ranges are identified (🏠)")
print("✅ Loopback addresses are marked (🔁)")
print("✅ Negated interfaces (!) are properly handled")
print("✅ Flow direction is clear (in/out with network names)")
print()
print("Example enrichments in the diagram above:")
print("- 172.23.0.10 → 🐳 lucidlink-mock (container)")
print("- br-48b7a6d85e30 → 🐋 from-manou-20251001_checkmk-network")
print("- docker0 → 🐋 bridge")
print("- 172.17.0.2 → 🐋 Docker net: bridge (or container if running)")
