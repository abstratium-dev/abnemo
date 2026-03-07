#!/usr/bin/env python3
"""
Test script to debug process tracking
Run this to see what processes are currently using network connections
"""

import os
import subprocess

def test_proc_net():
    """Show current TCP connections from /proc/net/tcp"""
    print("=== Current TCP Connections ===\n")
    
    try:
        with open('/proc/net/tcp', 'r') as f:
            lines = f.readlines()
            print(f"Header: {lines[0].strip()}")
            print(f"\nTotal connections: {len(lines) - 1}\n")
            
            # Show first 10 connections
            for i, line in enumerate(lines[1:11], 1):
                parts = line.split()
                if len(parts) >= 10:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]
                    inode = parts[9]
                    
                    # Convert hex to IP:port
                    local_ip_hex, local_port_hex = local_addr.split(':')
                    remote_ip_hex, remote_port_hex = remote_addr.split(':')
                    
                    # Convert to decimal
                    local_port = int(local_port_hex, 16)
                    remote_port = int(remote_port_hex, 16)
                    
                    print(f"{i}. Local port: {local_port}, Remote port: {remote_port}, State: {state}, Inode: {inode}")
    
    except Exception as e:
        print(f"Error reading /proc/net/tcp: {e}")

def test_ss_command():
    """Show connections using ss command"""
    print("\n\n=== Connections via 'ss' command ===\n")
    
    try:
        result = subprocess.run(
            ['ss', '-tnp'],
            capture_output=True,
            text=True
        )
        
        lines = result.stdout.split('\n')
        print(f"Total lines: {len(lines)}\n")
        
        # Show connections with process info
        for line in lines[:20]:
            if 'users:' in line:
                print(line)
    
    except Exception as e:
        print(f"Error running ss: {e}")

def test_docker_containers():
    """Show running Docker containers"""
    print("\n\n=== Docker Containers ===\n")
    
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', 'table {{.ID}}\t{{.Names}}\t{{.Image}}'],
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except Exception as e:
        print(f"Error: {e}")

def find_process_for_port(port):
    """Find which process is using a specific port"""
    print(f"\n\n=== Finding process for port {port} ===\n")
    
    try:
        # Convert port to hex
        port_hex = f"{port:04X}"
        
        with open('/proc/net/tcp', 'r') as f:
            for line in f:
                if f":{port_hex}" in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        inode = parts[9]
                        print(f"Found socket with inode: {inode}")
                        
                        # Search for process
                        for pid in os.listdir('/proc'):
                            if not pid.isdigit():
                                continue
                            
                            fd_dir = f"/proc/{pid}/fd"
                            try:
                                for fd in os.listdir(fd_dir):
                                    try:
                                        link = os.readlink(f"{fd_dir}/{fd}")
                                        if f"socket:[{inode}]" in link:
                                            # Found it!
                                            with open(f"/proc/{pid}/cmdline", 'r') as cmd:
                                                cmdline = cmd.read().replace('\x00', ' ')
                                            print(f"Process: PID {pid}, Command: {cmdline}")
                                            
                                            # Check cgroup for Docker
                                            with open(f"/proc/{pid}/cgroup", 'r') as cg:
                                                cgroup = cg.read()
                                                if 'docker' in cgroup.lower():
                                                    print(f"Docker container detected!")
                                                    print(f"Cgroup info:\n{cgroup[:200]}")
                                            return
                                    except:
                                        pass
                            except:
                                pass
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("Process Tracking Debug Tool")
    print("=" * 60)
    
    test_proc_net()
    test_ss_command()
    test_docker_containers()
    
    # Test specific port if provided
    import sys
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
        find_process_for_port(port)
    
    print("\n\nTo test a specific port: sudo python3 test_process_lookup.py <port>")
