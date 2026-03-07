#!/usr/bin/env python3
"""Test Docker enrichment functionality"""

from docker_enrichment import DockerEnricher

# Create enricher
enricher = DockerEnricher()

print("Docker Enrichment Test")
print("=" * 80)
print(f"Docker available: {enricher.docker_available}")
print(f"Containers found: {len(enricher.containers)}")
print(f"Networks found: {len(enricher.networks)}")
print()

# Test container IPs
print("Container Information:")
print("-" * 80)
for ip, info in enricher.containers.items():
    print(f"  {ip}: {info['name']} (network: {info['network']})")
print()

# Test network information
print("Network Information:")
print("-" * 80)
for subnet, info in enricher.networks.items():
    print(f"  {subnet}: {info['name']} (driver: {info['driver']}, gateway: {info['gateway']})")
print()

# Test IP enrichment
test_ips = [
    '172.23.0.10',
    '172.17.0.2',
    '10.0.0.5',
    '192.168.1.100',
    '127.0.0.1',
    '8.8.8.8'
]

print("IP Enrichment Tests:")
print("-" * 80)
for ip in test_ips:
    enrichment = enricher.enrich_ip(ip)
    if enrichment:
        print(f"  {ip}: {enrichment.get('label', 'No label')} (type: {enrichment.get('type', 'unknown')})")
    else:
        print(f"  {ip}: No enrichment")
print()

# Test interface enrichment
test_interfaces = [
    'docker0',
    'br-48b7a6d85e30',
    'veth1234567',
    'eth0',
    'wlan0',
    'lo'
]

print("Interface Enrichment Tests:")
print("-" * 80)
for iface in test_interfaces:
    is_docker, network_name = enricher.is_docker_interface(iface)
    enrichment = enricher.enrich_interface(iface)
    print(f"  {iface}: Docker={is_docker}, Network={network_name}, Label={enrichment.get('label', 'None')}")
print()

# Test flow information
print("Flow Information Test:")
print("-" * 80)
test_rule = {
    'source': '172.23.0.10',
    'destination': '0.0.0.0/0',
    'in': '!br-48b7a6d85e30',
    'out': 'br-48b7a6d85e30',
    'prot': '6',
    'extra': 'dpt:5000'
}

flow_info = enricher.get_docker_flow_info(test_rule)
print(f"  Is Docker-related: {flow_info['is_docker_related']}")
print(f"  Source: {flow_info['source']}")
print(f"  Destination: {flow_info['destination']}")
print(f"  In Interface: {flow_info['in_interface']}")
print(f"  Out Interface: {flow_info['out_interface']}")
print(f"  Flow Description: {flow_info['flow_description']}")
