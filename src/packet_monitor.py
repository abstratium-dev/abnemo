#!/usr/bin/env python3
"""
Network Packet Monitor - Captures and logs outgoing network traffic
"""

import socket
import dns.resolver
import dns.reversename
from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import defaultdict
from datetime import datetime
import threading
import time
import json
import os
from src.isp_lookup import ISPLookup


class PacketMonitor:
    def __init__(self, log_dir="traffic_logs", port_mappings_file="port_mappings.txt", 
                 enable_isp_lookup=True, isp_api_key=None,
                 log_retention_days=30, log_max_size_mb=100, 
                 continuous_log_interval=60, enable_process_tracking=False,
                 top_n=20, isp_cache_ttl_hours=72, isp_debug=False,
                 traffic_direction="outgoing"):
        self.traffic_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "domains": set(), "ports": set(), "ip_type": None, "isp": None, "processes": {}})
        self.dns_cache = {}
        self.log_dir = log_dir
        self.running = False
        self.stop_event = threading.Event()  # For immediate thread shutdown
        self.lock = threading.Lock()
        self.port_mappings = {}
        self.last_summary_time = None
        self.last_log_time = None
        self.enable_isp_lookup = enable_isp_lookup
        self.isp_lookup = ISPLookup(
            api_key=isp_api_key, 
            cache_ttl_hours=isp_cache_ttl_hours,
            debug=isp_debug
        ) if enable_isp_lookup else None
        self.total_packets_seen = 0
        self.total_packets_filtered = 0
        
        # Traffic direction mode:
        # - "outgoing": Only track outgoing traffic (local -> remote)
        # - "incoming": Only track unsolicited incoming traffic (remote -> local, not responses)
        # - "bidirectional": Track responses to outgoing connections (local <-> remote for established connections)
        # - "all": Track all traffic including unsolicited incoming (e.g., SSH servers, web servers)
        if traffic_direction not in ["outgoing", "incoming", "bidirectional", "all"]:
            raise ValueError(f"Invalid traffic_direction: {traffic_direction}. Must be 'outgoing', 'incoming', 'bidirectional', or 'all'")
        self.traffic_direction = traffic_direction
        
        # Track outgoing connections for bidirectional/incoming filtering
        self.outgoing_connections = set()  # Set of remote IPs we've initiated connections to
        
        # Process tracking (optional, zero overhead when disabled)
        self.enable_process_tracking = enable_process_tracking
        self.process_tracker = None
        if enable_process_tracking:
            from src.process_tracker import ProcessTracker
            self.process_tracker = ProcessTracker()
        
        # Log rotation settings
        self.log_retention_days = log_retention_days
        self.log_max_size_mb = log_max_size_mb
        self.continuous_log_interval = continuous_log_interval
        
        # Display settings
        self.top_n = top_n  # seconds
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Load port mappings
        self.load_port_mappings(port_mappings_file)
    
    def load_port_mappings(self, filename):
        """Load port number to description mappings from file"""
        if not os.path.exists(filename):
            return
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line:
                        port_str, description = line.split('=', 1)
                        try:
                            port = int(port_str.strip())
                            self.port_mappings[port] = description.strip()
                        except ValueError:
                            continue
        except Exception as e:
            print(f"[!] Warning: Could not load port mappings: {e}")
    
    def get_port_description(self, port):
        """Get human-readable description for a port number"""
        return self.port_mappings.get(port, str(port))
    
    def classify_ip_address(self, ip):
        """Classify IP address type (multicast, reserved, etc.) - IPv4 and IPv6"""
        try:
            # Check if IPv6
            if ':' in ip:
                ip_lower = ip.lower()
                if ip_lower.startswith('::1'):
                    return "loopback (IPv6)"
                if ip_lower.startswith('fe80:'):
                    return "link-local (IPv6)"
                if ip_lower.startswith('fc00:') or ip_lower.startswith('fd00:'):
                    return "unique local (IPv6)"
                if ip_lower.startswith('ff'):
                    return "multicast (IPv6)"
                if ip_lower.startswith('2001:db8:'):
                    return "documentation (IPv6)"
                return "public (IPv6)"
            
            # IPv4 classification
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return "invalid"
            
            first = parts[0]
            second = parts[1]
            
            # Multicast (224.0.0.0 to 239.255.255.255)
            if 224 <= first <= 239:
                return "multicast"
            
            # Private/Local addresses
            if first == 10:
                return "private (Class A)"
            if first == 172 and 16 <= second <= 31:
                return "private (Class B)"
            if first == 192 and second == 168:
                return "private (Class C)"
            
            # Loopback (127.0.0.0/8)
            if first == 127:
                return "loopback"
            
            # Link-local (169.254.0.0/16)
            if first == 169 and second == 254:
                return "link-local"
            
            # Broadcast
            if ip == "255.255.255.255":
                return "broadcast"
            
            # Reserved/Special ranges
            if first == 0:
                return "reserved (current network)"
            if first == 192 and second == 0 and parts[2] == 0:
                return "reserved (IETF protocol)"
            if first == 192 and second == 0 and parts[2] == 2:
                return "reserved (TEST-NET-1)"
            if first == 198 and second == 51 and parts[2] == 100:
                return "reserved (TEST-NET-2)"
            if first == 203 and second == 0 and parts[2] == 113:
                return "reserved (TEST-NET-3)"
            if first == 192 and second == 88 and parts[2] == 99:
                return "reserved (IPv6 to IPv4 relay)"
            if first == 198 and 18 <= second <= 19:
                return "reserved (benchmark testing)"
            if 240 <= first <= 255:
                return "reserved (future use)"
            
            # Public/Internet routable
            return "public"
            
        except:
            return "unknown"
        
    def reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup with caching"""
        if ip_address in self.dns_cache:
            return self.dns_cache[ip_address]
        
        try:
            # Try reverse DNS lookup
            rev_name = dns.reversename.from_address(ip_address)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            answers = resolver.resolve(rev_name, "PTR")
            domain = str(answers[0]).rstrip('.')
            self.dns_cache[ip_address] = domain
            return domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            # If reverse DNS fails, cache as unknown
            self.dns_cache[ip_address] = "unknown"
            return "unknown"
    
    def packet_callback(self, packet):
        """Callback function to process each captured packet"""
        self.total_packets_seen += 1
        
        # Handle both IPv4 and IPv6
        dst_ip = None
        src_ip = None
        
        if IP in packet:
            dst_ip = packet[IP].dst
            src_ip = packet[IP].src
        elif IPv6 in packet:
            dst_ip = packet[IPv6].dst
            src_ip = packet[IPv6].src
        else:
            return  # Not IP or IPv6
        
        # Determine which IP is the remote (non-local) one
        remote_ip = None
        local_ip = None
        is_outgoing = False
        
        if self.is_local_ip(src_ip) and not self.is_local_ip(dst_ip):
            # Outgoing: local -> remote
            remote_ip = dst_ip
            local_ip = src_ip
            is_outgoing = True
        elif self.is_local_ip(dst_ip) and not self.is_local_ip(src_ip):
            # Incoming: remote -> local
            remote_ip = src_ip
            local_ip = dst_ip
            is_outgoing = False
        else:
            # Both local or both remote - skip
            self.total_packets_filtered += 1
            return
        
        # Apply traffic direction filter
        if self.traffic_direction == "outgoing":
            if not is_outgoing:
                # Only track outgoing traffic
                self.total_packets_filtered += 1
                return
            # Track this as an outgoing connection
            with self.lock:
                self.outgoing_connections.add(remote_ip)
                
        elif self.traffic_direction == "incoming":
            if is_outgoing:
                # Track outgoing connections but don't count them
                with self.lock:
                    self.outgoing_connections.add(remote_ip)
                self.total_packets_filtered += 1
                return
            else:
                # Only count incoming if it's NOT a response to our outgoing connection
                with self.lock:
                    if remote_ip in self.outgoing_connections:
                        # This is a response to our connection - skip it
                        self.total_packets_filtered += 1
                        return
                # This is unsolicited incoming - count it
                
        elif self.traffic_direction == "bidirectional":
            if is_outgoing:
                # Track outgoing connections
                with self.lock:
                    self.outgoing_connections.add(remote_ip)
            else:
                # For bidirectional mode, only count incoming if it's a response to an established connection
                with self.lock:
                    if remote_ip not in self.outgoing_connections:
                        # No outgoing connection to this IP yet - skip incoming
                        self.total_packets_filtered += 1
                        return
        # "all" mode: no filtering, track everything
        
        packet_size = len(packet)
        
        # Get source and destination ports if available
        src_port = None
        dst_port = None
        remote_port = None
        local_port = None
        protocol = None
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'tcp'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'udp'
        
        # Determine which port is the remote one
        if is_outgoing:
            remote_port = dst_port
            local_port = src_port
        else:
            remote_port = src_port
            local_port = dst_port
        
        # Update statistics for the remote IP
        with self.lock:
            self.traffic_stats[remote_ip]["bytes"] += packet_size
            self.traffic_stats[remote_ip]["packets"] += 1
            
            if remote_port:
                self.traffic_stats[remote_ip]["ports"].add(remote_port)
            
            # Classify IP type if not already done
            if self.traffic_stats[remote_ip]["ip_type"] is None:
                self.traffic_stats[remote_ip]["ip_type"] = self.classify_ip_address(remote_ip)
            
            # Perform reverse DNS lookup if not already done
            if not self.traffic_stats[remote_ip]["domains"]:
                domain = self.reverse_dns_lookup(remote_ip)
                if domain != "unknown":
                    self.traffic_stats[remote_ip]["domains"].add(domain)
            
            # Process tracking (only if enabled and we have local port for outgoing)
            # For incoming traffic, we can't reliably identify the process
            if self.enable_process_tracking and is_outgoing and local_port and protocol:
                # Track all processes that access this IP (not just first one)
                process_key = f"{local_ip}:{local_port}:{protocol}"
                if process_key not in self.traffic_stats[remote_ip]["processes"]:
                    process_info = self.process_tracker.identify_process(local_ip, local_port, protocol)
                    
                    if process_info:
                        self.traffic_stats[remote_ip]["processes"][process_key] = process_info
                    else:
                        # Fallback: Try to identify Docker container by local IP
                        # This handles short-lived processes in containers
                        container_info = self.process_tracker.identify_container_by_ip(local_ip)
                        if container_info:
                            # Create a pseudo-process entry for the container
                            self.traffic_stats[remote_ip]["processes"][process_key] = {
                                'name': 'docker-container',
                                'pid': 'N/A',
                                'container': {
                                    'name': container_info['name'],
                                    'image': container_info.get('image', 'unknown'),
                                    'id': container_info.get('id', 'unknown')
                                }
                            }
                            # Debug: Uncomment to see when container is detected
                            # print(f"[DEBUG] Container detected: {container_info['name']} (local_ip: {local_ip} -> remote_ip: {remote_ip})")
            
            # Note: ISP lookup is deferred to avoid blocking packet capture
            # It will be performed when generating summaries or saving stats
            # Traffic direction is now bidirectional - both incoming and outgoing counted
    
    def is_local_ip(self, ip):
        """Check if IP is local/private (IPv4 or IPv6)"""
        try:
            # Check if IPv6
            if ':' in ip:
                # IPv6 local addresses
                ip_lower = ip.lower()
                if ip_lower.startswith('::1'):  # Loopback
                    return True
                if ip_lower.startswith('fe80:'):  # Link-local
                    return True
                if ip_lower.startswith('fc00:') or ip_lower.startswith('fd00:'):  # Unique local
                    return True
                if ip_lower.startswith('::ffff:'):  # IPv4-mapped IPv6
                    # Extract IPv4 and check it
                    ipv4 = ip_lower.split('::ffff:')[1]
                    return self.is_local_ip(ipv4)
                return False  # Public IPv6
            
            # IPv4 check
            parts = ip.split('.')
            if len(parts) != 4:
                return True
            
            # Check for private IP ranges
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            if first_octet == 10:
                return True
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
            if first_octet == 192 and second_octet == 168:
                return True
            if first_octet == 127:  # Loopback
                return True
            if first_octet == 169 and second_octet == 254:  # Link-local
                return True
            
            return False
        except:
            return True
    
    def start_monitoring(self, interface=None, duration=None, summary_interval=None, top_n=None):
        """Start packet capture with optional periodic summaries"""
        self.running = True
        self.last_summary_time = time.time()
        self.last_log_time = time.time()
        
        # Override top_n if specified
        if top_n is not None:
            self.top_n = top_n
        
        print(f"[*] Starting packet capture on interface: {interface or 'all'}")
        if summary_interval:
            print(f"[*] Periodic summaries every {summary_interval} seconds (showing top {self.top_n})")
        if duration is None and self.continuous_log_interval:
            print(f"[*] Continuous mode: saving logs every {self.continuous_log_interval} seconds")
        print("[*] Press Ctrl+C to stop monitoring\n")
        
        # Start periodic summary thread if requested
        summary_thread = None
        if summary_interval:
            summary_thread = threading.Thread(
                target=self._periodic_summary_worker,
                args=(summary_interval,),
                daemon=True
            )
            summary_thread.start()
        
        # Start continuous logging thread if no duration specified
        log_thread = None
        if duration is None and self.continuous_log_interval:
            log_thread = threading.Thread(
                target=self._continuous_log_worker,
                daemon=True
            )
            log_thread.start()
        
        try:
            # Capture both IPv4 and IPv6 packets
            sniff(
                iface=interface,
                prn=self.packet_callback,
                filter="ip or ip6",  # Capture both IPv4 and IPv6
                store=False,
                timeout=duration,
                stop_filter=lambda x: not self.running  # Stop when running=False
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping packet capture...")
            self.running = False
            self.stop_event.set()  # Wake up threads immediately
        finally:
            self.running = False
            self.stop_event.set()  # Ensure threads wake up
            
            # Wait for threads to finish (should be instant now)
            try:
                if summary_thread and summary_thread.is_alive():
                    summary_thread.join(timeout=0.1)  # Reduced from 0.5s
                if log_thread and log_thread.is_alive():
                    log_thread.join(timeout=0.1)
            except KeyboardInterrupt:
                pass  # User is impatient, skip thread cleanup
            
            # Save final statistics
            try:
                print("[*] Saving final statistics...")
                stats = self.get_statistics()
                if stats:
                    self.save_statistics()
                else:
                    print("[*] No traffic captured")
            except KeyboardInterrupt:
                print("[!] Interrupted during save - data may be incomplete")
            
            print("[*] Monitoring stopped")
    
    def _periodic_summary_worker(self, interval):
        """Worker thread for periodic summaries"""
        while self.running:
            # Use wait() instead of sleep() for instant shutdown
            if self.stop_event.wait(timeout=interval):
                break  # stop_event was set, exit immediately
            if self.running:
                self.print_periodic_summary()
    
    def _continuous_log_worker(self):
        """Worker thread for continuous logging"""
        while self.running:
            # Use wait() instead of sleep() for instant shutdown
            if self.stop_event.wait(timeout=self.continuous_log_interval):
                break  # stop_event was set, exit immediately
            if self.running:
                current_time = time.time()
                elapsed = current_time - self.last_log_time
                
                # Only save if we have captured some traffic
                stats = self.get_statistics(include_isp=False)  # Skip ISP for speed
                if stats:
                    self.save_statistics()
                    self.last_log_time = current_time
                    print(f"[*] Continuous log saved ({len(stats)} IPs, {elapsed:.0f}s elapsed)")
    
    def print_periodic_summary(self):
        """Print a brief periodic summary"""
        stats = self.get_statistics()
        
        if not stats:
            return
        
        current_time = time.time()
        elapsed = current_time - self.last_summary_time
        
        total_bytes = sum(s['bytes'] for s in stats.values())
        total_packets = sum(s['packets'] for s in stats.values())
        
        print(f"\n{'='*80}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Periodic Summary (last {elapsed:.0f}s)")
        print(f"{'='*80}")
        print(f"IPs: {len(stats)} | Bytes: {total_bytes:,} | Packets: {total_packets:,}")
        print(f"Total packets seen: {self.total_packets_seen:,} | Filtered (local): {self.total_packets_filtered:,}")
        
        # Show top N by bytes
        sorted_stats = sorted(stats.items(), key=lambda x: x[1]['bytes'], reverse=True)
        print(f"\nTop {min(self.top_n, len(sorted_stats))} destinations:")
        print("-" * 80)
        
        for idx, (ip, data) in enumerate(sorted_stats[:self.top_n], 1):
            ip_type = data.get('ip_type', 'unknown')
            
            # Get domain and ISP separately
            domain = data['domains'][0] if data['domains'] else None
            isp_info = data.get('isp')
            
            # Format domain line
            if domain and domain != 'unknown':
                domain_str = domain
            else:
                domain_str = "no domain name known"
            
            # Format ISP line
            if isp_info:
                isp_str = isp_info.get('org') or isp_info.get('isp', 'Unknown ISP')
                if isp_info.get('country_code'):
                    isp_str = f"{isp_str} ({isp_info['country_code']})"
            else:
                isp_str = "ISP lookup pending..."
            
            # Format ports with descriptions
            if data['ports']:
                port_list = sorted(data['ports'])
                ports_str = ", ".join(f"{p} ({self.get_port_description(p)})" for p in port_list)
            else:
                ports_str = "none"
            
            # Format process info (if available) - show all processes
            processes = data.get('processes', {})
            process_strs = []
            if processes:
                # Handle both dict (from traffic_stats) and list (from get_statistics)
                process_list = processes.values() if isinstance(processes, dict) else processes
                
                # Deduplicate: collect unique process names and containers
                unique_processes = {}
                for process_info in process_list:
                    process_name = process_info.get('name', 'unknown')
                    pid = process_info.get('pid', '')
                    container = process_info.get('container')
                    
                    # Create unique key based on name and container
                    if container:
                        key = f"{process_name}:container:{container['name']}"
                        container_name = container['name']
                        container_image = container.get('image', '')
                        
                        # Show process name with container info
                        if pid:
                            base = f"{process_name} (PID: {pid})"
                        else:
                            base = process_name
                        
                        if container_image and container_image != 'unknown':
                            display = f"{base} in container: {container_name} (image: {container_image})"
                        else:
                            display = f"{base} in container: {container_name}"
                    else:
                        key = process_name
                        if pid:
                            display = f"{process_name} (PID: {pid})"
                        else:
                            display = process_name
                    
                    unique_processes[key] = display
                
                process_strs = list(unique_processes.values())
            
            # Print entry
            print(f"\n{idx}. IP: {ip} [{ip_type}]")
            print(f"   Domain: {domain_str}")
            print(f"   ISP: {isp_str}")
            if process_strs:
                if len(process_strs) == 1:
                    print(f"   Process: {process_strs[0]}")
                else:
                    print(f"   Processes:")
                    for proc_str in process_strs:
                        print(f"     - {proc_str}")
            print(f"   Ports: {ports_str}")
            print(f"   Traffic: {data['bytes']:,} bytes, {data['packets']} packets")
        
        print("\n" + "="*80 + "\n")
    
    def enrich_with_isp_data(self, ips_to_lookup=None):
        """Perform ISP lookups for IPs that don't have domain names"""
        if not self.enable_isp_lookup or not self.isp_lookup:
            return
        
        with self.lock:
            if ips_to_lookup is None:
                ips_to_lookup = list(self.traffic_stats.keys())
            
            for ip in ips_to_lookup:
                if ip not in self.traffic_stats:
                    continue
                
                # Always lookup ISP if we haven't looked it up yet
                if self.traffic_stats[ip]["isp"] is None:
                    isp_info = self.isp_lookup.lookup_isp(ip)
                    if isp_info:
                        self.traffic_stats[ip]["isp"] = isp_info
    
    def get_statistics(self, include_isp=True):
        """Get current traffic statistics"""
        # Perform ISP lookups for IPs without domain names
        if include_isp:
            self.enrich_with_isp_data()
        
        with self.lock:
            stats = {}
            for ip, data in self.traffic_stats.items():
                stats[ip] = {
                    "bytes": data["bytes"],
                    "packets": data["packets"],
                    "domains": list(data["domains"]),
                    "ports": list(data["ports"]),
                    "ip_type": data.get("ip_type", "unknown"),
                    "isp": data.get("isp"),
                    "processes": list(data.get("processes", {}).values())
                }
            return stats
    
    def cleanup_old_logs(self):
        """Remove old log files based on retention policy"""
        try:
            log_files = []
            total_size = 0
            
            # Get all log files with their stats
            for filename in os.listdir(self.log_dir):
                if filename.startswith("traffic_log_") and filename.endswith(".json"):
                    filepath = os.path.join(self.log_dir, filename)
                    stat = os.stat(filepath)
                    log_files.append({
                        'path': filepath,
                        'mtime': stat.st_mtime,
                        'size': stat.st_size
                    })
                    total_size += stat.st_size
            
            # Sort by modification time (oldest first)
            log_files.sort(key=lambda x: x['mtime'])
            
            current_time = time.time()
            max_age_seconds = self.log_retention_days * 24 * 3600
            max_size_bytes = self.log_max_size_mb * 1024 * 1024
            
            files_deleted = 0
            
            # Delete files older than retention period
            for log_file in log_files[:]:
                age_seconds = current_time - log_file['mtime']
                if age_seconds > max_age_seconds:
                    os.remove(log_file['path'])
                    total_size -= log_file['size']
                    log_files.remove(log_file)
                    files_deleted += 1
                    print(f"[*] Deleted old log: {os.path.basename(log_file['path'])} (age: {age_seconds/86400:.1f} days)")
            
            # Delete oldest files if total size exceeds limit
            while total_size > max_size_bytes and log_files:
                oldest = log_files.pop(0)
                os.remove(oldest['path'])
                total_size -= oldest['size']
                files_deleted += 1
                print(f"[*] Deleted log to reduce size: {os.path.basename(oldest['path'])} (total size: {total_size/1024/1024:.1f} MB)")
            
            if files_deleted > 0:
                print(f"[*] Log cleanup: {files_deleted} file(s) deleted, {len(log_files)} remaining ({total_size/1024/1024:.1f} MB)")
        
        except Exception as e:
            print(f"[!] Warning: Log cleanup failed: {e}")
    
    def save_statistics(self, filename=None):
        """Save statistics to JSON file"""
        # Clean up old logs before saving new one
        self.cleanup_old_logs()
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.log_dir, f"traffic_log_{timestamp}.json")
        
        stats = self.get_statistics()
        
        # Add metadata
        output = {
            "timestamp": datetime.now().isoformat(),
            "total_ips": len(stats),
            "total_bytes": sum(s["bytes"] for s in stats.values()),
            "total_packets": sum(s["packets"] for s in stats.values()),
            "traffic_by_ip": stats
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Statistics saved to: {filename}")
        return filename
    
    def print_summary(self, top_n=20):
        """Print a summary of traffic statistics"""
        stats = self.get_statistics()
        
        if not stats:
            print("[!] No traffic data captured")
            return
        
        # Sort by bytes transferred
        sorted_stats = sorted(stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
        
        print("\n" + "="*100)
        print(f"{'TRAFFIC SUMMARY':^100}")
        print("="*100)
        print(f"Total IPs contacted: {len(stats)}")
        print(f"Total bytes transferred: {sum(s['bytes'] for s in stats.values()):,} bytes")
        print(f"Total packets: {sum(s['packets'] for s in stats.values()):,}")
        print("="*100)
        print(f"\nTop {top_n} destinations by data volume:\n")
        print("-"*100)
        
        for idx, (ip, data) in enumerate(sorted_stats[:top_n], 1):
            ip_type = data.get('ip_type', 'unknown')
            
            # Get domain and ISP separately
            domain = data['domains'][0] if data['domains'] else None
            isp_info = data.get('isp')
            
            # Format domain line
            if domain and domain != 'unknown':
                domain_str = domain
            else:
                domain_str = "no domain name known"
            
            # Format ISP line
            if isp_info:
                isp_str = isp_info.get('org') or isp_info.get('isp', 'Unknown ISP')
                if isp_info.get('country_code'):
                    isp_str = f"{isp_str} ({isp_info['country_code']})"
            else:
                isp_str = "ISP information not available"
            
            # Format ports with descriptions
            if data['ports']:
                port_list = sorted(data['ports'])
                ports_str = ", ".join(f"{p} ({self.get_port_description(p)})" for p in port_list)
            else:
                ports_str = "none"
            
            # Format process info (if available) - show all processes
            processes = data.get('processes', {})
            process_strs = []
            if processes:
                # Handle both dict (from traffic_stats) and list (from get_statistics)
                process_list = processes.values() if isinstance(processes, dict) else processes
                
                # Deduplicate: collect unique process names and containers
                unique_processes = {}
                for process_info in process_list:
                    process_name = process_info.get('name', 'unknown')
                    pid = process_info.get('pid', '')
                    container = process_info.get('container')
                    
                    # Create unique key based on name and container
                    if container:
                        key = f"{process_name}:container:{container['name']}"
                        container_name = container['name']
                        container_image = container.get('image', '')
                        
                        # Show process name with container info
                        if pid:
                            base = f"{process_name} (PID: {pid})"
                        else:
                            base = process_name
                        
                        if container_image and container_image != 'unknown':
                            display = f"{base} in container: {container_name} (image: {container_image})"
                        else:
                            display = f"{base} in container: {container_name}"
                    else:
                        key = process_name
                        if pid:
                            display = f"{process_name} (PID: {pid})"
                        else:
                            display = process_name
                    
                    unique_processes[key] = display
                
                process_strs = list(unique_processes.values())
            
            # Print entry
            print(f"\n{idx}. IP: {ip} [{ip_type}]")
            print(f"   Domain: {domain_str}")
            print(f"   ISP: {isp_str}")
            if process_strs:
                if len(process_strs) == 1:
                    print(f"   Process: {process_strs[0]}")
                else:
                    print(f"   Processes:")
                    for proc_str in process_strs:
                        print(f"     - {proc_str}")
            print(f"   Ports: {ports_str}")
            print(f"   Traffic: {data['bytes']:,} bytes, {data['packets']} packets")
        
        print("\n" + "="*100 + "\n")
