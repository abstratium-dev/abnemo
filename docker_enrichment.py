#!/usr/bin/env python3
"""
Docker Enrichment - Enrich iptables rules with Docker container and network information
"""

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple
import ipaddress


class DockerEnricher:
    """Enrich IP addresses and interfaces with Docker information"""
    
    def __init__(self, enrichment_data: Optional[str] = None):
        self.containers = {}
        self.networks = {}
        self.interface_to_network = {}  # Map interface IDs to network names
        self.docker_available = False
        
        # If enrichment data is provided, parse it; otherwise load from Docker
        if enrichment_data:
            self._parse_enrichment_data(enrichment_data)
        else:
            self._load_docker_info()
    
    def _load_docker_info(self):
        """Load Docker container and network information"""
        try:
            # Get all containers with their network information
            result = subprocess.run(
                ['docker', 'ps', '-a', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self.docker_available = True
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            container = json.loads(line)
                            container_id = container.get('ID', '')
                            if container_id:
                                # Get detailed network info for this container
                                self._load_container_networks(container_id, container.get('Names', ''))
                        except json.JSONDecodeError:
                            continue
                
                # Get network information
                self._load_networks()
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            self.docker_available = False
    
    def _load_container_networks(self, container_id: str, container_name: str):
        """Load network information for a specific container"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', container_id],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data:
                    networks = data[0].get('NetworkSettings', {}).get('Networks', {})
                    for network_name, network_info in networks.items():
                        ip_address = network_info.get('IPAddress', '')
                        if ip_address:
                            self.containers[ip_address] = {
                                'name': container_name,
                                'id': container_id[:12],
                                'network': network_name,
                                'gateway': network_info.get('Gateway', ''),
                                'mac': network_info.get('MacAddress', '')
                            }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, subprocess.SubprocessError):
            pass
    
    def _parse_enrichment_data(self, data: str):
        """Parse custom Docker enrichment data format from export_docker_info.sh"""
        lines = data.strip().split('\n')
        in_docker_section = False
        in_containers = False
        in_networks = False
        
        for line in lines:
            line = line.strip()
            
            # Check for section markers
            if '=== DOCKER ENRICHMENT DATA ===' in line:
                in_docker_section = True
                continue
            elif '=== END DOCKER ENRICHMENT DATA ===' in line:
                in_docker_section = False
                break
            
            if not in_docker_section:
                continue
            
            # Check for subsection headers
            if line.startswith('# Docker Containers'):
                in_containers = True
                in_networks = False
                continue
            elif line.startswith('# Docker Networks'):
                in_containers = False
                in_networks = True
                continue
            elif line.startswith('#') or not line:
                continue
            
            # Parse container data: IP|ContainerName|NetworkName|Gateway
            if in_containers and '|' in line:
                parts = line.split('|')
                if len(parts) >= 4:
                    ip, name, network, gateway = parts[0], parts[1], parts[2], parts[3]
                    if ip:
                        self.containers[ip] = {
                            'name': name,
                            'network': network,
                            'gateway': gateway
                        }
                        self.docker_available = True
            
            # Parse network data: NetworkName|Subnet|Gateway|Driver|InterfaceID
            elif in_networks and '|' in line:
                parts = line.split('|')
                if len(parts) >= 5:
                    name, subnet, gateway, driver, interface_id = parts[0], parts[1], parts[2], parts[3], parts[4]
                    if subnet:
                        self.networks[subnet] = {
                            'name': name,
                            'id': interface_id,
                            'gateway': gateway,
                            'driver': driver
                        }
                        # Map interface ID to network name (e.g., ef37f7b34afa -> serverless)
                        if interface_id:
                            self.interface_to_network[interface_id] = name
                            # Also map with br- prefix
                            self.interface_to_network[f'br-{interface_id}'] = name
                        self.docker_available = True
    
    def _load_networks(self):
        """Load Docker network information"""
        try:
            result = subprocess.run(
                ['docker', 'network', 'ls', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            network = json.loads(line)
                            network_id = network.get('ID', '')
                            network_name = network.get('Name', '')
                            
                            if network_id:
                                # Get detailed network info
                                detail_result = subprocess.run(
                                    ['docker', 'network', 'inspect', network_id],
                                    capture_output=True,
                                    text=True,
                                    timeout=5
                                )
                                
                                if detail_result.returncode == 0:
                                    detail_data = json.loads(detail_result.stdout)
                                    if detail_data:
                                        ipam = detail_data[0].get('IPAM', {})
                                        config = ipam.get('Config', []) or []
                                        driver = detail_data[0].get('Driver', '')
                                        interface_id = network_id[:12]
                                        
                                        # Map interface ID to network name
                                        self.interface_to_network[interface_id] = network_name
                                        self.interface_to_network[f'br-{interface_id}'] = network_name
                                        
                                        for cfg in config:
                                            subnet = cfg.get('Subnet', '')
                                            gateway = cfg.get('Gateway', '')
                                            
                                            if subnet:
                                                self.networks[subnet] = {
                                                    'name': network_name,
                                                    'id': interface_id,
                                                    'gateway': gateway,
                                                    'driver': driver
                                                }
                        except (json.JSONDecodeError, subprocess.SubprocessError):
                            continue
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
    
    def is_docker_interface(self, interface: str) -> Tuple[bool, Optional[str]]:
        """Check if an interface is a Docker network interface"""
        if not interface or interface == '*':
            return False, None
        
        # Common Docker interface patterns
        docker_patterns = [
            r'^docker\d+$',  # docker0, docker1, etc.
            r'^br-[a-f0-9]{12}$',  # bridge networks (br-48b7a6d85e30)
            r'^veth[a-f0-9]+$',  # veth pairs
        ]
        
        for pattern in docker_patterns:
            if re.match(pattern, interface):
                # Try to find the network name
                network_name = self._get_network_name_by_interface(interface)
                return True, network_name
        
        return False, None
    
    def _get_network_name_by_interface(self, interface: str) -> Optional[str]:
        """Get Docker network name from interface name"""
        # Check direct mapping first (most efficient)
        if interface in self.interface_to_network:
            return self.interface_to_network[interface]
        
        # For br-* interfaces, the suffix is part of the network ID
        if interface.startswith('br-'):
            network_id_part = interface[3:]  # Remove 'br-'
            # Check if we have this interface ID mapped
            if network_id_part in self.interface_to_network:
                return self.interface_to_network[network_id_part]
            # Fallback to searching through networks
            for subnet, network_info in self.networks.items():
                if network_info['id'] == network_id_part or network_info['id'].startswith(network_id_part):
                    return network_info['name']
        
        # For docker0, it's usually the default bridge
        if interface == 'docker0':
            return 'bridge'
        
        return None
    
    def enrich_ip(self, ip_address: str) -> Dict[str, str]:
        """Enrich an IP address with Docker information"""
        if not ip_address or ip_address in ['0.0.0.0/0', 'anywhere']:
            return {}
        
        # Remove CIDR notation if present
        ip_clean = ip_address.split('/')[0]
        
        enrichment = {}
        
        # Check if it's a container IP
        if ip_clean in self.containers:
            container = self.containers[ip_clean]
            enrichment['type'] = 'container'
            enrichment['container_name'] = container['name']
            enrichment['container_id'] = container['id']
            enrichment['network'] = container['network']
            enrichment['label'] = f"🐳 {container['name']}"
            return enrichment
        
        # Check if it's in a Docker network subnet
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            for subnet, network_info in self.networks.items():
                try:
                    network_obj = ipaddress.ip_network(subnet, strict=False)
                    if ip_obj in network_obj:
                        # Check if it's the gateway
                        if ip_clean == network_info['gateway']:
                            enrichment['type'] = 'gateway'
                            enrichment['network'] = network_info['name']
                            enrichment['label'] = f"🌉 Gateway ({network_info['name']})"
                        else:
                            enrichment['type'] = 'docker_network'
                            enrichment['network'] = network_info['name']
                            enrichment['label'] = f"🐋 Docker net: {network_info['name']}"
                        return enrichment
                except ValueError:
                    continue
        except ValueError:
            pass
        
        # Check for special IP ranges
        enrichment.update(self._check_special_ranges(ip_clean))
        
        return enrichment
    
    def _check_special_ranges(self, ip_address: str) -> Dict[str, str]:
        """Check if IP is in special ranges (private, loopback, etc.)"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            if ip_obj.is_loopback:
                return {'type': 'loopback', 'label': '🔁 Loopback'}
            elif ip_obj.is_private:
                # Determine which private range
                if ip_address.startswith('10.'):
                    return {'type': 'private', 'range': '10.0.0.0/8', 'label': '🏠 Private (10.x)'}
                elif ip_address.startswith('172.'):
                    octet2 = int(ip_address.split('.')[1])
                    if 16 <= octet2 <= 31:
                        return {'type': 'private', 'range': '172.16.0.0/12', 'label': '🏠 Private (172.16-31.x)'}
                elif ip_address.startswith('192.168.'):
                    return {'type': 'private', 'range': '192.168.0.0/16', 'label': '🏠 Private (192.168.x)'}
            elif ip_obj.is_link_local:
                return {'type': 'link_local', 'label': '🔗 Link-local'}
            elif ip_obj.is_multicast:
                return {'type': 'multicast', 'label': '📡 Multicast'}
        except ValueError:
            pass
        
        return {}
    
    def enrich_interface(self, interface: str) -> Dict[str, str]:
        """Enrich an interface name with Docker information"""
        if not interface or interface == '*':
            return {}
        
        is_docker, network_name = self.is_docker_interface(interface)
        
        if is_docker:
            enrichment = {'type': 'docker_interface'}
            if network_name:
                enrichment['network'] = network_name
                enrichment['label'] = f"🐋 {network_name}"
            else:
                enrichment['label'] = f"🐋 Docker"
            return enrichment
        
        # Check for common interface types
        if interface.startswith('eth'):
            return {'type': 'ethernet', 'label': '🔌 Ethernet'}
        elif interface.startswith('wlan') or interface.startswith('wlp'):
            return {'type': 'wireless', 'label': '📶 WiFi'}
        elif interface == 'lo':
            return {'type': 'loopback', 'label': '🔁 Loopback'}
        elif interface.startswith('tun') or interface.startswith('tap'):
            return {'type': 'vpn', 'label': '🔒 VPN'}
        
        return {}
    
    def get_docker_flow_info(self, rule: Dict) -> Dict[str, any]:
        """Get comprehensive Docker flow information for a rule"""
        flow_info = {
            'is_docker_related': False,
            'source': {},
            'destination': {},
            'in_interface': {},
            'out_interface': {},
            'flow_description': ''
        }
        
        # Enrich source
        if rule.get('source'):
            flow_info['source'] = self.enrich_ip(rule['source'])
        
        # Enrich destination
        if rule.get('destination'):
            flow_info['destination'] = self.enrich_ip(rule['destination'])
        
        # Enrich interfaces
        if rule.get('in'):
            flow_info['in_interface'] = self.enrich_interface(rule['in'])
        
        if rule.get('out'):
            flow_info['out_interface'] = self.enrich_interface(rule['out'])
        
        # Determine if Docker-related
        if (flow_info['source'].get('type') in ['container', 'docker_network', 'gateway'] or
            flow_info['destination'].get('type') in ['container', 'docker_network', 'gateway'] or
            flow_info['in_interface'].get('type') == 'docker_interface' or
            flow_info['out_interface'].get('type') == 'docker_interface'):
            flow_info['is_docker_related'] = True
        
        # Build flow description
        flow_parts = []
        
        if flow_info['source'].get('label'):
            flow_parts.append(f"from {flow_info['source']['label']}")
        
        if flow_info['destination'].get('label'):
            flow_parts.append(f"to {flow_info['destination']['label']}")
        
        if flow_info['in_interface'].get('label'):
            flow_parts.append(f"via {flow_info['in_interface']['label']}")
        
        if flow_info['out_interface'].get('label'):
            flow_parts.append(f"out {flow_info['out_interface']['label']}")
        
        flow_info['flow_description'] = ' '.join(flow_parts)
        
        return flow_info
