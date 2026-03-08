#!/usr/bin/env python3
"""
Process Tracker Module - Identifies which process/container sent a packet
Uses /proc/net socket tracking and cgroup parsing
"""

import os
import re
from collections import defaultdict


class ProcessTracker:
    def __init__(self, proc_root='/proc'):
        self.socket_cache = {}  # Cache socket -> process mappings
        self.process_cache = {}  # Cache PID -> process info
        self.proc_root = proc_root
        
    def identify_process(self, src_ip, src_port, protocol='tcp'):
        """
        Identify which process owns a socket
        
        Args:
            src_ip: Source IP address (local machine IP)
            src_port: Source port number
            protocol: 'tcp' or 'udp'
            
        Returns:
            dict with process info or None
        """
        cache_key = f"{src_ip}:{src_port}:{protocol}"
        
        # Check cache first
        if cache_key in self.socket_cache:
            return self.socket_cache[cache_key]
        
        # Look up socket in /proc/net
        process_info = self._lookup_proc_net(src_ip, src_port, protocol)
        
        if process_info:
            # Check if it's a Docker container
            container_info = self._get_container_from_pid(process_info['pid'])
            if container_info:
                process_info['container'] = container_info
            
            # Cache the result
            self.socket_cache[cache_key] = process_info
            return process_info
        
        return None
    
    def _lookup_proc_net(self, local_ip, local_port, protocol='tcp'):
        """Look up socket owner in /proc/net/tcp or /proc/net/udp"""
        try:
            # Convert IP to hex format used in /proc/net
            # Format: little-endian hex (reversed octets)
            ip_parts = local_ip.split('.')
            if len(ip_parts) != 4:
                return None
            
            ip_hex = ''.join(['%02X' % int(x) for x in reversed(ip_parts)])
            port_hex = '%04X' % local_port
            socket_id = f"{ip_hex}:{port_hex}"
            
            # Read /proc/net file
            proc_file = os.path.join(self.proc_root, 'net', protocol)
            if not os.path.exists(proc_file):
                return None
            
            with open(proc_file, 'r') as f:
                lines = f.readlines()[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                # Check if this is our socket
                if parts[1] == socket_id:
                    inode = parts[9]
                    
                    # Find process with this inode
                    process_info = self._find_process_by_inode(inode)
                    if process_info:
                        return process_info
        
        except Exception as e:
            # Silently fail - process tracking is optional
            pass
        
        return None
    
    def _find_process_by_inode(self, inode):
        """Find which process owns a socket inode"""
        try:
            # Search through all processes
            for pid in os.listdir(self.proc_root):
                if not pid.isdigit():
                    continue
                
                # Check cache first
                if pid in self.process_cache:
                    cached = self.process_cache[pid]
                    if cached.get('inode') == inode:
                        return cached
                
                fd_dir = os.path.join(self.proc_root, pid, 'fd')
                if not os.path.exists(fd_dir):
                    continue
                
                try:
                    for fd in os.listdir(fd_dir):
                        link_path = f"{fd_dir}/{fd}"
                        try:
                            link = os.readlink(link_path)
                            if f"socket:[{inode}]" in link:
                                # Found the process!
                                return self._get_process_info(pid, inode)
                        except (OSError, FileNotFoundError):
                            continue
                except (PermissionError, FileNotFoundError):
                    continue
        
        except Exception as e:
            pass
        
        return None
    
    def _get_process_info(self, pid, inode=None):
        """Get detailed information about a process"""
        try:
            # Read command line
            cmdline_path = os.path.join(self.proc_root, pid, 'cmdline')
            if os.path.exists(cmdline_path):
                with open(cmdline_path, 'r') as f:
                    cmdline = f.read().replace('\x00', ' ').strip()
                    if not cmdline:
                        cmdline = f"[PID {pid}]"
            else:
                cmdline = f"[PID {pid}]"
            
            # Read process name from status
            process_name = None
            status_path = os.path.join(self.proc_root, pid, 'status')
            if os.path.exists(status_path):
                with open(status_path, 'r') as f:
                    for line in f:
                        if line.startswith('Name:'):
                            process_name = line.split(':', 1)[1].strip()
                            break
            
            if not process_name:
                process_name = cmdline.split()[0] if cmdline else f"PID-{pid}"
            
            # Get user ID
            uid = None
            try:
                stat_info = os.stat(os.path.join(self.proc_root, pid))
                uid = stat_info.st_uid
            except:
                pass
            
            info = {
                'pid': pid,
                'name': process_name,
                'cmdline': cmdline,
                'uid': uid,
                'inode': inode
            }
            
            # Cache it
            self.process_cache[pid] = info
            return info
        
        except Exception as e:
            return None
    
    def _get_container_from_pid(self, pid):
        """Check if process is running in a Docker container"""
        try:
            cgroup_path = os.path.join(self.proc_root, pid, 'cgroup')
            if not os.path.exists(cgroup_path):
                return None
            
            with open(cgroup_path, 'r') as f:
                for line in f:
                    # Look for docker in cgroup path
                    if 'docker' in line.lower():
                        # Extract container ID from cgroup path
                        # Format examples:
                        # 12:pids:/docker/abc123def456...
                        # 0::/docker/abc123def456...
                        parts = line.strip().split('/')
                        
                        for i, part in enumerate(parts):
                            if 'docker' in part.lower():
                                if i + 1 < len(parts):
                                    container_id = parts[i + 1]
                                    # Clean up container ID (may have .scope suffix)
                                    container_id = container_id.replace('.scope', '')
                                    
                                    # Get short ID (first 12 chars)
                                    short_id = container_id[:12]
                                    
                                    # Try to get container name from Docker
                                    container_name = self._get_container_name(short_id)
                                    
                                    return {
                                        'id': short_id,
                                        'full_id': container_id,
                                        'name': container_name or short_id
                                    }
                    
                    # Also check for containerd/k8s
                    if 'containerd' in line or 'kubepods' in line:
                        # Kubernetes pod
                        return {
                            'id': 'k8s-pod',
                            'name': 'Kubernetes Pod',
                            'type': 'kubernetes'
                        }
        
        except Exception as e:
            pass
        
        return None
    
    def _get_container_name(self, container_id):
        """Try to get container name from Docker (if available)"""
        # Method 1: Try docker inspect command
        try:
            import subprocess
            result = subprocess.run(
                ['docker', 'inspect', '--format', '{{.Name}}', container_id],
                capture_output=True,
                text=True,
                timeout=1
            )
            if result.returncode == 0:
                name = result.stdout.strip()
                # Remove leading slash
                return name.lstrip('/')
        except:
            pass
        
        # Method 2: Search Docker config files on host
        # Docker stores container config in /var/lib/docker/containers/
        try:
            import json
            import glob
            
            # Try to find container config by matching container ID prefix
            config_pattern = f"/var/lib/docker/containers/{container_id}*/config.v2.json"
            config_files = glob.glob(config_pattern)
            
            if not config_files:
                # Try with full ID if we have it
                config_pattern = f"/var/lib/docker/containers/*/config.v2.json"
                config_files = glob.glob(config_pattern)
                # Filter by container ID
                config_files = [f for f in config_files if container_id in f]
            
            for config_file in config_files:
                try:
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                        name = config.get('Name', '')
                        if name:
                            # Remove leading slash
                            return name.lstrip('/')
                except (PermissionError, FileNotFoundError, json.JSONDecodeError):
                    continue
        except:
            pass
        
        # Method 3: Try alternative Docker paths
        try:
            import json
            
            # Some systems use different paths
            alt_paths = [
                f"/run/docker/containerd/{container_id}/config.json",
                f"/var/run/docker/containers/{container_id}/config.v2.json"
            ]
            
            for config_file in alt_paths:
                if os.path.exists(config_file):
                    try:
                        with open(config_file, 'r') as f:
                            config = json.load(f)
                            name = config.get('Name', '')
                            if name:
                                return name.lstrip('/')
                    except (PermissionError, json.JSONDecodeError):
                        continue
        except:
            pass
        
        return None
    
    def clear_cache(self):
        """Clear all caches"""
        self.socket_cache.clear()
        self.process_cache.clear()
    
    def get_cache_size(self):
        """Get current cache sizes"""
        return {
            'sockets': len(self.socket_cache),
            'processes': len(self.process_cache)
        }
    
    def identify_container_by_ip(self, ip_address):
        """
        Identify Docker container by its IP address
        Useful when process lookup fails due to short-lived connections
        """
        try:
            import subprocess
            import json
            
            # Method 1: Use docker inspect to find container by IP
            result = subprocess.run(
                ['docker', 'ps', '-q'],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode != 0:
                return None
            
            container_ids = result.stdout.strip().split('\n')
            
            for container_id in container_ids:
                if not container_id:
                    continue
                
                # Get container network info
                inspect_result = subprocess.run(
                    ['docker', 'inspect', container_id],
                    capture_output=True,
                    text=True,
                    timeout=1
                )
                
                if inspect_result.returncode == 0:
                    data = json.loads(inspect_result.stdout)[0]
                    networks = data.get('NetworkSettings', {}).get('Networks', {})
                    
                    # Check all networks for matching IP
                    for network_name, network_info in networks.items():
                        if network_info.get('IPAddress') == ip_address:
                            # Found the container!
                            container_name = data.get('Name', '').lstrip('/')
                            container_image = data.get('Config', {}).get('Image', 'unknown')
                            
                            return {
                                'id': container_id[:12],
                                'name': container_name or container_id[:12],
                                'image': container_image,
                                'ip': ip_address,
                                'network': network_name
                            }
        
        except Exception as e:
            # Silently fail - this is a fallback method
            pass
        
        return None
