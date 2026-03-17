#!/usr/bin/env python3
"""
Abnemo Verification Tool

This program independently monitors outgoing network traffic for 1 minute
and compares the results with abnemo's output to verify that abnemo is
working correctly.

Usage:
    sudo python3 verification.py

Requirements:
    - Root privileges (for packet capture)
    - tcpdump installed
    - abnemo dependencies installed
"""

import subprocess
import sys
import os
import time
import json
import signal
import re
from datetime import datetime
from pathlib import Path


class TrafficMonitor:
    """Independent traffic monitor using tcpdump"""
    
    def __init__(self):
        self.process = None
        self.pcap_file = "/tmp/verification_capture.pcap"
        self.stats = {
            'total_bytes': 0,
            'total_packets': 0,
            'ips': {}
        }
    
    def start(self):
        """Start tcpdump capture"""
        # Remove old pcap file if it exists
        if os.path.exists(self.pcap_file):
            os.remove(self.pcap_file)
        
        # Start tcpdump to capture ALL traffic
        # We'll filter in the analysis phase to match abnemo's behavior
        cmd = [
            'tcpdump',
            '-i', 'any',
            '-w', self.pcap_file,
            '-n',  # Don't resolve hostnames
            '-s', '0'  # Capture full packets
        ]
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            print(f"✓ Started tcpdump (PID: {self.process.pid})")
            return True
        except FileNotFoundError:
            print("✗ Error: tcpdump not found. Please install it:")
            print("  Ubuntu/Debian: sudo apt-get install tcpdump")
            print("  CentOS/RHEL: sudo yum install tcpdump")
            return False
        except Exception as e:
            print(f"✗ Error starting tcpdump: {e}")
            return False
    
    def stop(self):
        """Stop tcpdump and analyze capture"""
        if self.process:
            try:
                # Send SIGTERM to the process group
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
            except Exception as e:
                print(f"Warning: Error stopping tcpdump: {e}")
        
        # Wait a moment for file to be written
        time.sleep(1)
        
        # Analyze the capture
        self._analyze_capture()
    
    def _analyze_capture(self):
        """Analyze pcap file to extract statistics using scapy for accurate parsing"""
        if not os.path.exists(self.pcap_file):
            print("✗ Warning: Capture file not found")
            return
        
        try:
            # Try using scapy for accurate packet parsing
            try:
                from scapy.all import rdpcap, IP
                
                packets = rdpcap(self.pcap_file)
                
                # Helper function to check if IP is local/private
                def is_local_ip(ip):
                    if ip in ['127.0.0.1', '0.0.0.0', '255.255.255.255']:
                        return True
                    if ip.startswith('224.') or ip.startswith('239.'):  # Multicast
                        return True
                    if ip.startswith('127.'):  # Loopback range (127.0.0.0/8)
                        return True
                    if (ip.startswith('10.') or 
                        ip.startswith('192.168.') or
                        ip.startswith('172.16.') or
                        ip.startswith('172.17.') or
                        ip.startswith('172.18.') or
                        ip.startswith('172.19.') or
                        ip.startswith('172.20.') or
                        ip.startswith('172.21.') or
                        ip.startswith('172.22.') or
                        ip.startswith('172.23.') or
                        ip.startswith('172.24.') or
                        ip.startswith('172.25.') or
                        ip.startswith('172.26.') or
                        ip.startswith('172.27.') or
                        ip.startswith('172.28.') or
                        ip.startswith('172.29.') or
                        ip.startswith('172.30.') or
                        ip.startswith('172.31.')):
                        return True
                    return False
                
                total_bytes = 0
                ip_bytes = {}
                packet_count = 0
                total_packets_read = len(packets)
                ip_packets = 0
                filtered_packets = 0
                outgoing_packets = 0
                incoming_packets = 0
                local_to_local = 0
                
                # Create detailed log file
                log_file = "/tmp/verification_tcpdump_packets.log"
                with open(log_file, 'w') as log:
                    log.write("TCPDUMP PACKET LOG\n")
                    log.write("=" * 80 + "\n\n")
                    
                    for pkt in packets:
                        # Only process IP packets
                        if IP not in pkt:
                            continue
                        
                        ip_packets += 1
                        
                        # Get packet length (entire frame)
                        pkt_len = len(pkt)
                        
                        # Get source and destination IPs
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        
                        # OUTGOING TRAFFIC ONLY: local source -> remote destination
                        # This matches abnemo's "outgoing" mode
                        src_is_local = is_local_ip(src_ip)
                        dst_is_local = is_local_ip(dst_ip)
                        
                        # Determine direction
                        if src_is_local and dst_is_local:
                            direction = "LOCAL→LOCAL"
                            local_to_local += 1
                        elif src_is_local and not dst_is_local:
                            direction = "OUTGOING"
                            outgoing_packets += 1
                        elif not src_is_local and dst_is_local:
                            direction = "INCOMING"
                            incoming_packets += 1
                        else:
                            direction = "TRANSIT"
                        
                        # Log every packet
                        log.write(f"Packet #{ip_packets}: {src_ip:15} → {dst_ip:15} | {pkt_len:5} bytes | {direction}\n")
                        
                        # Only count packets from local to remote (outgoing)
                        if src_is_local and not dst_is_local:
                            packet_count += 1
                            total_bytes += pkt_len
                            ip_bytes[dst_ip] = ip_bytes.get(dst_ip, 0) + pkt_len
                            log.write(f"         ✓ COUNTED (outgoing to remote)\n")
                        else:
                            filtered_packets += 1
                            log.write(f"         ✗ FILTERED ({direction.lower()})\n")
                
                print(f"  Debug: Read {total_packets_read} total packets, {ip_packets} IP packets")
                print(f"         Outgoing (local→remote): {outgoing_packets}, Incoming (remote→local): {incoming_packets}, Local→Local: {local_to_local}")
                print(f"         Counted: {packet_count} outgoing packets")
                
                self.stats['total_packets'] = packet_count
                self.stats['total_bytes'] = total_bytes
                self.stats['ips'] = ip_bytes
                return
                
            except ImportError:
                # Scapy not available, fall back to tcpdump parsing
                pass
            
            # Fallback: Use tcpdump with detailed output
            result = subprocess.run(
                ['tcpdump', '-r', self.pcap_file, '-nn', '-tt', '-v'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            total_bytes = 0
            ip_bytes = {}
            packet_count = 0
            
            # Helper function to check if IP is local/private
            def is_local_ip(ip):
                if ip in ['127.0.0.1', '0.0.0.0', '255.255.255.255']:
                    return True
                if ip.startswith('224.') or ip.startswith('239.') or ip.startswith('127.'):
                    return True
                if (ip.startswith('10.') or ip.startswith('192.168.') or
                    ip.startswith('172.16.') or ip.startswith('172.17.') or
                    ip.startswith('172.18.') or ip.startswith('172.19.') or
                    ip.startswith('172.20.') or ip.startswith('172.21.') or
                    ip.startswith('172.22.') or ip.startswith('172.23.') or
                    ip.startswith('172.24.') or ip.startswith('172.25.') or
                    ip.startswith('172.26.') or ip.startswith('172.27.') or
                    ip.startswith('172.28.') or ip.startswith('172.29.') or
                    ip.startswith('172.30.') or ip.startswith('172.31.')):
                    return True
                return False
            
            # Regex patterns
            ipv4_pattern = re.compile(r'IP\s+(\d+\.\d+\.\d+\.\d+)(?:\.\d+)?\s+>\s+(\d+\.\d+\.\d+\.\d+)(?:\.\d+)?')
            length_pattern = re.compile(r'length:?\s+(\d+)')
            
            for line in result.stdout.split('\n'):
                if not line.strip() or ('IP ' not in line and 'IP6 ' not in line):
                    continue
                
                ip_match = ipv4_pattern.search(line)
                if ip_match:
                    src_ip = ip_match.group(1)
                    dst_ip = ip_match.group(2)
                    
                    # Only count outgoing traffic (local source -> remote destination)
                    if not is_local_ip(src_ip) or is_local_ip(dst_ip):
                        continue
                    
                    packet_count += 1
                    
                    # Extract packet length
                    length_match = length_pattern.search(line)
                    length = int(length_match.group(1)) if length_match else 60
                    
                    total_bytes += length
                    ip_bytes[dst_ip] = ip_bytes.get(dst_ip, 0) + length
            
            self.stats['total_packets'] = packet_count
            self.stats['total_bytes'] = total_bytes
            self.stats['ips'] = ip_bytes
            
        except subprocess.TimeoutExpired:
            print("✗ Warning: tcpdump analysis timed out")
        except Exception as e:
            print(f"✗ Warning: Error analyzing capture: {e}")
    
    def get_stats(self):
        """Return collected statistics"""
        return self.stats


class AbnemoMonitor:
    """Abnemo monitor wrapper"""
    
    def __init__(self):
        self.process = None
        self.log_dir = "/tmp/verification_logs"
        self.stats = {
            'total_bytes': 0,
            'total_packets': 0,
            'total_ips': 0,
            'ips': {}
        }
    
    def start(self):
        """Start abnemo monitoring"""
        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Clean old logs
        for f in Path(self.log_dir).glob("*.json"):
            f.unlink()
        
        # Start abnemo
        cmd = [
            sys.executable,
            'src/abnemo.py',
            'monitor',
            '--duration', '60',
            '--log-dir', self.log_dir,
            '--traffic-direction', 'outgoing',
            '--log-level', 'ERROR',  # Suppress output
            '--extraverbosefortesting'  # Log every packet for comparison
        ]
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            print(f"✓ Started abnemo (PID: {self.process.pid})")
            return True
        except Exception as e:
            print(f"✗ Error starting abnemo: {e}")
            return False
    
    def wait(self):
        """Wait for abnemo to finish"""
        if self.process:
            try:
                self.process.wait(timeout=70)  # 60s duration + 10s buffer
            except subprocess.TimeoutExpired:
                print("✗ Warning: abnemo timed out, terminating...")
                self.process.terminate()
                self.process.wait(timeout=5)
    
    def load_stats(self):
        """Load statistics from abnemo logs"""
        log_files = list(Path(self.log_dir).glob("*.json"))
        
        if not log_files:
            print("✗ Warning: No abnemo log files found")
            return
        
        # Load the most recent log
        log_file = max(log_files, key=lambda f: f.stat().st_mtime)
        
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
            
            self.stats['total_bytes'] = data.get('total_bytes', 0)
            self.stats['total_packets'] = data.get('total_packets', 0)
            self.stats['total_ips'] = data.get('total_ips', 0)
            
            # Extract per-IP stats
            traffic_by_ip = data.get('traffic_by_ip', {})
            for ip, ip_data in traffic_by_ip.items():
                self.stats['ips'][ip] = ip_data.get('bytes', 0)
            
            print(f"  Debug: Abnemo captured {self.stats['total_ips']} unique IPs, {self.stats['total_packets']} packets")
            
        except Exception as e:
            print(f"✗ Warning: Error loading abnemo stats: {e}")
    
    def get_stats(self):
        """Return collected statistics"""
        return self.stats


def format_bytes(bytes_val):
    """Format bytes in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"


def print_comparison(tcpdump_stats, abnemo_stats):
    """Print comparison of results"""
    print("\n" + "="*80)
    print("VERIFICATION RESULTS")
    print("="*80)
    
    print("\n📊 TRAFFIC SUMMARY")
    print("-" * 80)
    
    # Total bytes
    tcpdump_bytes = tcpdump_stats['total_bytes']
    abnemo_bytes = abnemo_stats['total_bytes']
    
    print(f"\nTotal Bytes Captured:")
    print(f"  tcpdump:  {format_bytes(tcpdump_bytes):>12} ({tcpdump_bytes:,} bytes)")
    print(f"  abnemo:   {format_bytes(abnemo_bytes):>12} ({abnemo_bytes:,} bytes)")
    
    if tcpdump_bytes > 0:
        percentage = (abnemo_bytes / tcpdump_bytes) * 100
        print(f"  Match:    {percentage:>11.1f}%")
    else:
        percentage = 0
        print(f"  Match:    N/A (no traffic captured)")
    
    # Total packets
    print(f"\nTotal Packets Captured:")
    print(f"  tcpdump:  {tcpdump_stats['total_packets']:>12,}")
    print(f"  abnemo:   {abnemo_stats['total_packets']:>12,}")
    
    # Unique IPs
    print(f"\nUnique Destination IPs:")
    print(f"  tcpdump:  {len(tcpdump_stats['ips']):>12,}")
    print(f"  abnemo:   {abnemo_stats['total_ips']:>12,}")
    
    # Top IPs comparison
    print("\n📍 TOP 10 DESTINATION IPs")
    print("-" * 80)
    
    # Get top IPs from both
    tcpdump_top = sorted(tcpdump_stats['ips'].items(), key=lambda x: x[1], reverse=True)[:10]
    abnemo_top = sorted(abnemo_stats['ips'].items(), key=lambda x: x[1], reverse=True)[:10]
    
    print("\nTcpdump Top IPs:")
    if tcpdump_top:
        for i, (ip, bytes_val) in enumerate(tcpdump_top, 1):
            print(f"  {i:2}. {ip:15} - {format_bytes(bytes_val)}")
    else:
        print("  (no data)")
    
    print("\nAbnemo Top IPs:")
    if abnemo_top:
        for i, (ip, bytes_val) in enumerate(abnemo_top, 1):
            print(f"  {i:2}. {ip:15} - {format_bytes(bytes_val)}")
    else:
        print("  (no data)")
    
    # Verdict
    print("\n" + "="*80)
    print("VERDICT")
    print("="*80)
    
    if tcpdump_bytes == 0 and abnemo_bytes == 0:
        print("\n⚠️  NO TRAFFIC DETECTED")
        print("No network traffic was captured during the test period.")
        print("Try generating some traffic (e.g., curl https://example.com)")
    elif percentage >= 80:
        print("\n✅ ABNEMO IS WORKING CORRECTLY")
        print(f"Abnemo captured {percentage:.1f}% of the traffic detected by tcpdump.")
        print("This is within acceptable range (≥80%).")
    elif percentage >= 50:
        print("\n⚠️  ABNEMO IS PARTIALLY WORKING")
        print(f"Abnemo captured {percentage:.1f}% of the traffic detected by tcpdump.")
        print("This might be acceptable depending on your use case.")
        print("\nPossible reasons for difference:")
        print("  - Different timing windows")
        print("  - Packet filtering differences")
        print("  - eBPF vs tcpdump capture differences")
    else:
        print("\n❌ ABNEMO MAY NOT BE WORKING CORRECTLY")
        print(f"Abnemo only captured {percentage:.1f}% of the traffic detected by tcpdump.")
        print("\nPossible issues:")
        print("  - eBPF program not loading correctly")
        print("  - Permissions issues")
        print("  - Interface filtering")
        print("  - Check abnemo logs for errors")
    
    print("\n" + "="*80)


def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("✗ Error: This script requires root privileges")
        print("Please run with sudo:")
        print(f"  sudo python3 {sys.argv[0]}")
        sys.exit(1)


def main():
    print("="*80)
    print("ABNEMO VERIFICATION TOOL")
    print("="*80)
    print("\nThis tool will:")
    print("  1. Monitor outgoing traffic using tcpdump (independent reference)")
    print("  2. Monitor outgoing traffic using abnemo (system under test)")
    print("  3. Run both for 60 seconds")
    print("  4. Compare results to verify abnemo is working correctly")
    print("\n" + "="*80)
    
    # Check root
    check_root()
    
    # Initialize monitors
    tcpdump = TrafficMonitor()
    abnemo = AbnemoMonitor()
    
    # Start monitoring
    print("\n🚀 STARTING MONITORS")
    print("-" * 80)
    
    if not tcpdump.start():
        sys.exit(1)
    
    time.sleep(1)  # Give tcpdump a moment to start
    
    if not abnemo.start():
        tcpdump.stop()
        sys.exit(1)
    
    # Monitor progress
    print("\n⏱️  MONITORING IN PROGRESS")
    print("-" * 80)
    print("Duration: 60 seconds")
    print("\nProgress: ", end='', flush=True)
    
    for i in range(60):
        time.sleep(1)
        if (i + 1) % 10 == 0:
            print(f"{i+1}s ", end='', flush=True)
        elif (i + 1) % 5 == 0:
            print(".", end='', flush=True)
    
    print("\n\n✓ Monitoring complete")
    
    # Stop monitors
    print("\n🛑 STOPPING MONITORS")
    print("-" * 80)
    
    print("Stopping tcpdump...")
    tcpdump.stop()
    print("✓ tcpdump stopped")
    
    print("Waiting for abnemo to finish...")
    abnemo.wait()
    print("✓ abnemo stopped")
    
    # Load results
    print("\n📥 LOADING RESULTS")
    print("-" * 80)
    
    print("Analyzing tcpdump capture...")
    tcpdump_stats = tcpdump.get_stats()
    print(f"✓ Found {tcpdump_stats['total_packets']} packets, {format_bytes(tcpdump_stats['total_bytes'])}")
    
    print("Loading abnemo logs...")
    abnemo.load_stats()
    abnemo_stats = abnemo.get_stats()
    print(f"✓ Found {abnemo_stats['total_packets']} packets, {format_bytes(abnemo_stats['total_bytes'])}")
    
    # Print comparison
    print_comparison(tcpdump_stats, abnemo_stats)
    
    # Cleanup
    print("\n🧹 CLEANUP")
    print("-" * 80)
    print(f"Tcpdump capture saved to: {tcpdump.pcap_file}")
    print(f"Tcpdump packet log: /tmp/verification_tcpdump_packets.log")
    print(f"Abnemo logs saved to: {abnemo.log_dir}")
    print(f"Abnemo packet log: /tmp/verification_abnemo_packets.log")
    print("\nTo investigate packet-by-packet:")
    print("  cat /tmp/verification_tcpdump_packets.log")
    print("  cat /tmp/verification_abnemo_packets.log")
    print("\n" + "="*80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
