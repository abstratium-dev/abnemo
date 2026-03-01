#!/usr/bin/env python3
"""
eBPF-based Network Monitor
Uses kernel-level hooks to track all network connections with zero race conditions
"""

import time
import signal
import threading
import subprocess
import os
from collections import defaultdict
from datetime import datetime
from packet_monitor import PacketMonitor
from ebpf.ebpf_loader import EBPFLoader


class EBPFMonitor(PacketMonitor):
    """Network monitor using eBPF for process tracking"""
    
    def __init__(self, *args, **kwargs):
        # Force process tracking off - we use eBPF instead
        kwargs['enable_process_tracking'] = False
        super().__init__(*args, **kwargs)
        
        self.ebpf_loader = None
        self.ebpf_stats = defaultdict(lambda: {
            "bytes": 0, 
            "packets": 0, 
            "process": None,
            "cgroup_id": None
        })
        
        # Cache for cgroup_id -> container name mapping
        self.cgroup_container_cache = {}
        # Cache for pid -> container name mapping
        self.pid_container_cache = {}
        
    def start_monitoring_ebpf(self, interface=None, duration=None, summary_interval=None, top_n=None):
        """Start eBPF-based monitoring"""
        self.running = True
        self.last_summary_time = time.time()
        self.last_log_time = time.time()
        
        # Override top_n if specified
        if top_n is not None:
            self.top_n = top_n
        
        print(f"[*] Starting eBPF network monitor")
        print(f"[*] Mode: eBPF kernel hooks (no race conditions!)")
        if summary_interval:
            print(f"[*] Periodic summaries every {summary_interval} seconds (showing top {self.top_n})")
        if duration is None and self.continuous_log_interval:
            print(f"[*] Continuous mode: saving logs every {self.continuous_log_interval} seconds")
        print("[*] Press Ctrl+C to stop monitoring\n")
        
        # Load eBPF program
        try:
            self.ebpf_loader = EBPFLoader()
            self.ebpf_loader.load(self._handle_ebpf_event)
        except Exception as e:
            print(f"[!] Failed to load eBPF: {e}")
            print("[!] Make sure you have:")
            print("    1. Root privileges (sudo)")
            print("    2. BCC installed: apt install python3-bpfcc")
            print("    3. Kernel 4.x+ with BPF support")
            return
        
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
        
        # Main event loop
        start_time = time.time()
        try:
            print("[*] eBPF monitoring active...")
            while self.running:
                # Poll for events (100ms timeout)
                self.ebpf_loader.poll(timeout=0.1)
                
                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    print(f"\n[*] Duration of {duration}s reached")
                    break
                    
        except KeyboardInterrupt:
            print("\n[*] Stopping eBPF monitor...")
            self.running = False
            self.stop_event.set()
        finally:
            self.running = False
            self.stop_event.set()
            
            # Cleanup eBPF
            if self.ebpf_loader:
                self.ebpf_loader.cleanup()
            
            # Wait for threads to finish (should be instant)
            try:
                if summary_thread and summary_thread.is_alive():
                    summary_thread.join(timeout=0.1)
                if log_thread and log_thread.is_alive():
                    log_thread.join(timeout=0.1)
            except KeyboardInterrupt:
                pass
            
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
            
            print("[*] eBPF monitoring stopped")
    
    def _handle_ebpf_event(self, event):
        """Handle connection event from eBPF"""
        # Extract info
        dst_ip = event['daddr']
        src_ip = event['saddr']
        dst_port = event['dport']
        src_port = event['sport']
        protocol = event['protocol']
        pid = event['pid']
        comm = event['comm']
        cgroup_id = event['cgroup_id']
        
        # Determine which IP is the remote (non-local) one
        remote_ip = None
        local_ip = None
        remote_port = None
        local_port = None
        is_outgoing = False
        
        if self.is_local_ip(src_ip) and not self.is_local_ip(dst_ip):
            # Outgoing: local -> remote
            remote_ip = dst_ip
            local_ip = src_ip
            remote_port = dst_port
            local_port = src_port
            is_outgoing = True
        elif self.is_local_ip(dst_ip) and not self.is_local_ip(src_ip):
            # Incoming: remote -> local
            remote_ip = src_ip
            local_ip = dst_ip
            remote_port = src_port
            local_port = dst_port
            is_outgoing = False
        else:
            # Both local or both remote - skip
            self.total_packets_filtered += 1
            return
        
        # Apply traffic direction filter
        if self.traffic_direction == "outgoing":
            if not is_outgoing:
                self.total_packets_filtered += 1
                return
            with self.lock:
                self.outgoing_connections.add(remote_ip)
                
        elif self.traffic_direction == "incoming":
            if is_outgoing:
                with self.lock:
                    self.outgoing_connections.add(remote_ip)
                self.total_packets_filtered += 1
                return
            else:
                with self.lock:
                    if remote_ip in self.outgoing_connections:
                        self.total_packets_filtered += 1
                        return
                        
        elif self.traffic_direction == "bidirectional":
            if is_outgoing:
                with self.lock:
                    self.outgoing_connections.add(remote_ip)
            else:
                with self.lock:
                    if remote_ip not in self.outgoing_connections:
                        self.total_packets_filtered += 1
                        return
        # "all" mode: no filtering, track everything
        
        self.total_packets_seen += 1
        
        # Update traffic stats for the remote IP
        with self.lock:
            # We don't have packet size from eBPF, so estimate
            # (eBPF tracks connections, not individual packets)
            estimated_size = 64  # Minimum packet size
            
            self.traffic_stats[remote_ip]["bytes"] += estimated_size
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
            
            # Store process info from eBPF (only for outgoing, no race condition!)
            # For incoming traffic, we can't reliably identify the process
            if is_outgoing:
                process_key = f"{local_ip}:{local_port}:{protocol}"
                if process_key not in self.traffic_stats[remote_ip]["processes"]:
                    process_info = {
                        'name': comm,
                        'pid': pid,
                        'cgroup_id': cgroup_id
                    }
                    
                    # Try to identify container from cgroup or PID
                    container_info = None
                    if cgroup_id != 0:
                        container_info = self._identify_container_from_cgroup(cgroup_id)
                    
                    # Fallback: try to identify from PID
                    if not container_info and pid:
                        container_info = self._identify_container_from_pid(pid)
                    
                    if container_info:
                        process_info['container'] = container_info
                    
                    self.traffic_stats[remote_ip]["processes"][process_key] = process_info
    
    def _identify_container_from_cgroup(self, cgroup_id):
        """Identify Docker container from cgroup ID"""
        # Check cache first
        if cgroup_id in self.cgroup_container_cache:
            return self.cgroup_container_cache[cgroup_id]
        
        try:
            # Method 1: Search through /proc for matching cgroup_id
            # This is more reliable than parsing cgroup paths
            container_info = self._find_container_by_cgroup_id(cgroup_id)
            
            if container_info:
                self.cgroup_container_cache[cgroup_id] = container_info
                return container_info
            
            # Cache negative result to avoid repeated lookups
            self.cgroup_container_cache[cgroup_id] = None
            return None
        except Exception as e:
            return None
    
    def _find_container_by_cgroup_id(self, cgroup_id):
        """Find Docker container by searching /sys/fs/cgroup"""
        # NOTE: This method is not reliable because cgroup_id alone doesn't
        # uniquely identify a container without additional context.
        # We rely on PID-based lookup instead.
        # Returning None to force fallback to PID-based method.
        return None
    
    def _get_docker_container_name(self, container_id):
        """Get Docker container name from container ID"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format={{.Name}}', container_id],
                capture_output=True,
                text=True,
                timeout=1
            )
            if result.returncode == 0:
                name = result.stdout.strip()
                # Remove leading slash from container name
                return name.lstrip('/')
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None
    
    def _identify_container_from_pid(self, pid):
        """Identify Docker container from process PID by reading /proc/<pid>/cgroup"""
        # Check cache first
        if pid in self.pid_container_cache:
            return self.pid_container_cache[pid]
        
        try:
            cgroup_file = f"/proc/{pid}/cgroup"
            if not os.path.exists(cgroup_file):
                # Cache negative result
                self.pid_container_cache[pid] = None
                return None
            
            with open(cgroup_file, 'r') as f:
                cgroup_content = f.read()
                
                # Only proceed if we find docker-specific paths
                # Must have either "docker-" or "/docker/" to be a container
                if 'docker-' not in cgroup_content and '/docker/' not in cgroup_content:
                    # Not a Docker container
                    self.pid_container_cache[pid] = None
                    return None
                
                for line in cgroup_content.splitlines():
                    # Look for docker in cgroup path
                    # Format: 0::/system.slice/docker-<container_id>.scope
                    # Or: 0::/docker/<container_id>
                    if 'docker' in line:
                        # Extract container ID
                        if 'docker-' in line and '.scope' in line:
                            # systemd format: docker-<64-char-hex>.scope
                            parts = line.split('docker-')
                            if len(parts) > 1:
                                container_id = parts[1].split('.scope')[0]
                                if len(container_id) >= 12:
                                    short_id = container_id[:12]
                                    container_name = self._get_docker_container_name(short_id)
                                    if container_name:
                                        result = {
                                            'name': container_name,
                                            'id': short_id
                                        }
                                        # Cache the result
                                        self.pid_container_cache[pid] = result
                                        return result
                        elif '/docker/' in line:
                            # cgroupfs format: /docker/<64-char-hex>
                            parts = line.split('/docker/')
                            if len(parts) > 1:
                                container_id = parts[1].strip().rstrip('/')
                                if len(container_id) >= 12:
                                    short_id = container_id[:12]
                                    container_name = self._get_docker_container_name(short_id)
                                    if container_name:
                                        result = {
                                            'name': container_name,
                                            'id': short_id
                                        }
                                        # Cache the result
                                        self.pid_container_cache[pid] = result
                                        return result
            
            # Cache negative result
            self.pid_container_cache[pid] = None
            return None
        except Exception:
            # Cache negative result
            self.pid_container_cache[pid] = None
            return None
