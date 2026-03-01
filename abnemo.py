#!/usr/bin/env python3
"""
Abnemo - Network Traffic Monitor and IPTables Rule Generator
Main CLI interface for the network monitoring tool
"""

import argparse
import sys
import os
import json
import glob
import subprocess
from datetime import datetime, timedelta
from packet_monitor import PacketMonitor
from iptables_generator import IPTablesGenerator


def monitor_command(args):
    """Handle the monitor subcommand"""
    # Get API key from args or environment variable
    api_key = args.isp_api_key or os.environ.get('IPAPI_KEY')
    
    # Start web server in background if requested
    if args.web:
        import threading
        web_thread = threading.Thread(
            target=start_web_server,
            args=(args.log_dir, args.web_port),
            daemon=True
        )
        web_thread.start()
        print(f"[*] Web server started on http://0.0.0.0:{args.web_port}")
        print(f"[*] Access at: http://localhost:{args.web_port}/")
        print()
    
    # Check if eBPF mode is requested
    if args.ebpf:
        from ebpf_monitor import EBPFMonitor
        monitor = EBPFMonitor(
            log_dir=args.log_dir,
            isp_api_key=api_key,
            log_retention_days=args.log_retention_days,
            log_max_size_mb=args.log_max_size_mb,
            continuous_log_interval=args.continuous_log_interval,
            top_n=args.top,
            isp_cache_ttl_hours=args.isp_cache_ttl,
            isp_debug=args.isp_debug,
            traffic_direction=args.traffic_direction
        )
        
        try:
            monitor.start_monitoring_ebpf(
                interface=args.interface,
                duration=args.duration,
                summary_interval=args.summary_interval,
                top_n=args.top
            )
        except PermissionError:
            print("[!] Error: eBPF requires root privileges")
            print("[!] Please run with sudo: sudo python3 abnemo.py monitor --ebpf")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error during eBPF monitoring: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        # Standard Scapy mode
        monitor = PacketMonitor(
            log_dir=args.log_dir,
            isp_api_key=api_key,
            log_retention_days=args.log_retention_days,
            log_max_size_mb=args.log_max_size_mb,
            continuous_log_interval=args.continuous_log_interval,
            enable_process_tracking=args.enable_process_tracking,
            top_n=args.top,
            isp_cache_ttl_hours=args.isp_cache_ttl,
            isp_debug=args.isp_debug,
            traffic_direction=args.traffic_direction
        )
        
        try:
            monitor.start_monitoring(
                interface=args.interface, 
                duration=args.duration,
                summary_interval=args.summary_interval,
                top_n=args.top
            )
        except PermissionError:
            print("[!] Error: Packet capture requires root privileges")
            print("[!] Please run with sudo: sudo python3 abnemo.py monitor")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error during monitoring: {e}")
            sys.exit(1)
    
    # Print summary
    monitor.print_summary(top_n=args.top)
    
    # Save statistics
    log_file = monitor.save_statistics()
    
    print(f"\n[*] To generate iptables rules from this log, run:")
    print(f"    python3 abnemo.py generate --log {log_file} --interactive")


def generate_command(args):
    """Handle the generate subcommand"""
    generator = IPTablesGenerator()
    
    if not os.path.exists(args.log):
        print(f"[!] Error: Log file not found: {args.log}")
        sys.exit(1)
    
    # Load traffic data
    print(f"[*] Loading traffic data from: {args.log}")
    
    if args.interactive:
        # Interactive mode - let user select IPs
        import json
        with open(args.log, 'r') as f:
            data = json.load(f)
        
        traffic_data = data.get('traffic_by_ip', {})
        sorted_traffic = sorted(traffic_data.items(), 
                               key=lambda x: x[1]['bytes'], 
                               reverse=True)
        
        print("\n" + "="*80)
        print("INTERACTIVE MODE - Select IPs to block")
        print("="*80)
        print(f"{'#':<5} {'IP Address':<20} {'Domain':<30} {'Bytes':<15} {'Packets'}")
        print("-"*80)
        
        for idx, (ip, stats) in enumerate(sorted_traffic, 1):
            domain = stats['domains'][0] if stats['domains'] else "unknown"
            if len(domain) > 28:
                domain = domain[:25] + "..."
            print(f"{idx:<5} {ip:<20} {domain:<30} {stats['bytes']:>13,} {stats['packets']:>8}")
        
        print("\nEnter IP numbers to block (comma-separated, e.g., 1,3,5) or 'all' for all IPs:")
        print("You can also enter IP addresses directly (e.g., 192.168.1.1,10.0.0.1)")
        print("Press Enter to skip: ", end='')
        
        selection = input().strip()
        
        if selection.lower() == 'all':
            for ip in traffic_data.keys():
                generator.add_ip_to_blocklist(ip)
        elif selection:
            # Parse selection
            parts = [p.strip() for p in selection.split(',')]
            for part in parts:
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(sorted_traffic):
                        ip = sorted_traffic[idx][0]
                        generator.add_ip_to_blocklist(ip)
                else:
                    # Assume it's an IP address
                    generator.add_ip_to_blocklist(part)
    
    else:
        # Automatic mode based on thresholds
        generator.load_from_traffic_log(
            args.log,
            min_bytes=args.min_bytes,
            min_packets=args.min_packets,
            specific_ips=args.ips.split(',') if args.ips else None,
            specific_domains=args.domains.split(',') if args.domains else None
        )
    
    if not generator.blocked_ips:
        print("[!] No IPs selected for blocking")
        sys.exit(0)
    
    # Print summary
    generator.print_summary()
    
    # Generate rules
    output_file = args.output or "block_rules.sh"
    unblock_file = args.output.replace('.sh', '_unblock.sh') if args.output else "unblock_rules.sh"
    
    generator.save_rules(output_file, format=args.format, chain=args.chain, action=args.action)
    generator.generate_unblock_script(unblock_file, chain=args.chain, action=args.action)
    
    print(f"\n[*] To apply these rules, run:")
    print(f"    sudo bash {output_file}")
    print(f"\n[*] To remove these rules later, run:")
    print(f"    sudo bash {unblock_file}")


def list_logs_command(args):
    """Handle the list-logs subcommand"""
    log_dir = args.log_dir
    
    if not os.path.exists(log_dir):
        print(f"[!] Log directory not found: {log_dir}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.endswith('.json')]
    
    if not log_files:
        print(f"[!] No log files found in {log_dir}")
        return
    
    print(f"\nLog files in {log_dir}:")
    print("-" * 80)
    
    for log_file in sorted(log_files, reverse=True):
        filepath = os.path.join(log_dir, log_file)
        size = os.path.getsize(filepath)
        
        # Try to load and show summary
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            print(f"\n{log_file}")
            print(f"  Timestamp: {data.get('timestamp', 'unknown')}")
            print(f"  Total IPs: {data.get('total_ips', 0)}")
            print(f"  Total Bytes: {data.get('total_bytes', 0):,}")
            print(f"  Total Packets: {data.get('total_packets', 0):,}")
            print(f"  File Size: {size:,} bytes")
        except:
            print(f"\n{log_file} ({size:,} bytes)")


def get_logs_in_range(log_dir, begin_time, end_time):
    """Get aggregated traffic data from logs within time range.
    Reads the timestamp field inside each JSON file to determine if it falls within range.
    Each file represents a snapshot of cumulative traffic at that timestamp.
    """
    if not os.path.exists(log_dir):
        return {"error": "Log directory not found"}
    
    log_files = glob.glob(os.path.join(log_dir, "traffic_log_*.json"))
    aggregated_data = {}
    total_bytes = 0
    total_packets = 0
    files_processed = 0
    
    for log_file in log_files:
        try:
            # Read the file to get its internal timestamp
            with open(log_file, 'r') as f:
                data = json.load(f)
            
            # Get the timestamp from inside the file
            timestamp_str = data.get('timestamp', '')
            if not timestamp_str:
                continue
            
            # Parse the ISO format timestamp
            try:
                # Handle both formats: "2026-03-01T21:07:07.015487" and "2026-03-01 21:07:07"
                if 'T' in timestamp_str:
                    file_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if file_timestamp.tzinfo:
                        file_timestamp = file_timestamp.replace(tzinfo=None)
                else:
                    file_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except (ValueError, AttributeError):
                # Skip files with invalid timestamp
                continue
            
            # Filter: only include files whose timestamp falls within the requested range
            if file_timestamp < begin_time or file_timestamp >= end_time:
                continue
            
            files_processed += 1
            
            # Aggregate traffic data
            traffic_by_ip = data.get('traffic_by_ip', {})
            for ip, stats in traffic_by_ip.items():
                if ip not in aggregated_data:
                    aggregated_data[ip] = {
                        'bytes': 0,
                        'packets': 0,
                        'domains': set(),
                        'ports': set(),
                        'ip_type': stats.get('ip_type', 'unknown'),
                        'isp': stats.get('isp', {}),
                        'processes': []
                    }
                
                aggregated_data[ip]['bytes'] += stats.get('bytes', 0)
                aggregated_data[ip]['packets'] += stats.get('packets', 0)
                aggregated_data[ip]['domains'].update(stats.get('domains', []))
                aggregated_data[ip]['ports'].update(stats.get('ports', []))
                
                # Aggregate process information
                if 'processes' in stats and stats['processes']:
                    # stats['processes'] can be either:
                    # - Array format: [{"name": "firefox", "pid": 1234, ...}, ...]
                    # - Dict format: {"1234": {"name": "firefox", "count": 5}}
                    if isinstance(stats['processes'], list):
                        # Array format from eBPF logs
                        for proc in stats['processes']:
                            if isinstance(proc, dict) and 'pid' in proc:
                                aggregated_data[ip]['processes'].append({
                                    'pid': str(proc['pid']),
                                    'name': proc.get('name', 'unknown')
                                })
                    elif isinstance(stats['processes'], dict):
                        # Dict format from standard logs
                        for pid, proc_info in stats['processes'].items():
                            aggregated_data[ip]['processes'].append({
                                'pid': pid,
                                'name': proc_info.get('name', 'unknown')
                            })
                
                total_bytes += stats.get('bytes', 0)
                total_packets += stats.get('packets', 0)
        except Exception as e:
            print(f"Error reading {log_file}: {e}")
            continue
    
    # Convert sets to lists for JSON serialization and deduplicate processes
    for ip in aggregated_data:
        aggregated_data[ip]['domains'] = list(aggregated_data[ip]['domains'])
        aggregated_data[ip]['ports'] = sorted(list(aggregated_data[ip]['ports']))
        
        # Deduplicate processes by pid
        if aggregated_data[ip]['processes']:
            seen_pids = {}
            for proc in aggregated_data[ip]['processes']:
                pid = proc['pid']
                if pid not in seen_pids:
                    seen_pids[pid] = proc
            aggregated_data[ip]['processes'] = list(seen_pids.values())
    
    return {
        'begin': begin_time.isoformat(),
        'end': end_time.isoformat(),
        'total_bytes': total_bytes,
        'total_packets': total_packets,
        'total_ips': len(aggregated_data),
        'traffic_by_ip': aggregated_data,
        'files_processed': files_processed
    }


def start_web_server(log_dir, port):
    """Start Flask web server for live monitoring"""
    from flask import Flask, request, jsonify, send_from_directory
    
    app = Flask(__name__, static_folder='web_static')
    
    # Disable Flask's default logging to avoid cluttering monitor output
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    @app.route('/api/traffic')
    def api_traffic():
        """API endpoint for traffic data with time range query parameters.
        Loads and filters files dynamically at request time.
        """
        begin_str = request.args.get('begin')
        end_str = request.args.get('end')
        
        # Default to last 5 minutes if not specified
        if not end_str:
            end_time = datetime.now()
        else:
            try:
                end_time = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
                if end_time.tzinfo:
                    end_time = end_time.replace(tzinfo=None)
            except ValueError:
                return jsonify({'error': 'Invalid end timestamp format. Use ISO8601.'}), 400
        
        if not begin_str:
            begin_time = end_time - timedelta(minutes=5)
        else:
            try:
                begin_time = datetime.fromisoformat(begin_str.replace('Z', '+00:00'))
                if begin_time.tzinfo:
                    begin_time = begin_time.replace(tzinfo=None)
            except ValueError:
                return jsonify({'error': 'Invalid begin timestamp format. Use ISO8601.'}), 400
        
        if begin_time >= end_time:
            return jsonify({'error': 'begin must be before end'}), 400
        
        # Load data dynamically from files at request time
        data = get_logs_in_range(log_dir, begin_time, end_time)
        return jsonify(data)
    
    @app.route('/')
    def index():
        """Serve index.html"""
        return send_from_directory('web_static', 'index.html')
    
    @app.route('/<path:path>')
    def static_files(path):
        """Serve static files"""
        return send_from_directory('web_static', path)
    
    @app.route('/api/process/<pid>')
    def api_process(pid):
        """API endpoint to get process details via ps command"""
        try:
            # Validate PID is numeric
            if not pid.isdigit():
                return jsonify({'error': 'Invalid PID'}), 400
            
            # Run ps command and grep for the PID
            result = subprocess.run(
                ['ps', '-Af'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return jsonify({'error': 'Failed to run ps command'}), 500
            
            # Filter for the specific PID
            lines = result.stdout.split('\n')
            header = lines[0] if lines else ''
            matching_lines = [line for line in lines if f' {pid} ' in line or line.endswith(f' {pid}')]
            
            if not matching_lines:
                output = f"No process found with PID {pid}\n(Process may have terminated)"
            else:
                output = header + '\n' + '\n'.join(matching_lines)
            
            return jsonify({'pid': pid, 'output': output})
            
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Command timed out'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Create web_static directory if it doesn't exist
    os.makedirs('web_static', exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)


def web_command(args):
    """Handle the web subcommand - start standalone web server"""
    print(f"[*] Starting web server on http://0.0.0.0:{args.port}")
    print(f"[*] Log directory: {args.log_dir}")
    print(f"[*] API endpoint: http://0.0.0.0:{args.port}/api/traffic")
    print(f"[*] Web interface: http://0.0.0.0:{args.port}/")
    print(f"[*] Press Ctrl+C to stop")
    print()
    
    start_web_server(args.log_dir, args.port)


def main():
    parser = argparse.ArgumentParser(
        description="Abnemo - Network Traffic Monitor and IPTables Rule Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor traffic for 60 seconds
  sudo python3 abnemo.py monitor --duration 60

  # Monitor specific interface
  sudo python3 abnemo.py monitor --interface eth0

  # Generate rules interactively from a log
  python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --interactive

  # Generate rules for IPs with >10MB traffic
  python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --min-bytes 10485760

  # Block specific domains
  python3 abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --domains "example.com,ads.com"

  # List all captured logs
  python3 abnemo.py list-logs
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor network traffic')
    monitor_parser.add_argument('-i', '--interface', help='Network interface to monitor (default: all)')
    monitor_parser.add_argument('-d', '--duration', type=int, help='Monitoring duration in seconds')
    monitor_parser.add_argument('-s', '--summary-interval', type=int, help='Print periodic summary every N seconds (default: disabled)')
    monitor_parser.add_argument('-t', '--top', type=int, default=20, help='Number of top IPs to display (default: 20)')
    monitor_parser.add_argument('--log-dir', default='traffic_logs', help='Directory to save logs (default: traffic_logs)')
    monitor_parser.add_argument('--isp-api-key', help='IP-API.com pro API key (or set IPAPI_KEY env var)')
    monitor_parser.add_argument('--log-retention-days', type=int, default=30, help='Delete logs older than N days (default: 30)')
    monitor_parser.add_argument('--log-max-size-mb', type=int, default=100, help='Delete oldest logs if total size exceeds N MB (default: 100)')
    monitor_parser.add_argument('--continuous-log-interval', type=int, default=60, help='Save logs every N seconds in continuous mode (default: 60, 0=disabled)')
    monitor_parser.add_argument('--enable-process-tracking', action='store_true', help='Enable process/container identification (adds overhead)')
    monitor_parser.add_argument('--ebpf', action='store_true', help='Use eBPF mode for zero-overhead process tracking (requires BCC)')
    monitor_parser.add_argument('--web', action='store_true', help='Start web server for live monitoring')
    monitor_parser.add_argument('--web-port', type=int, default=5000, help='Port for web server (default: 5000, only used with --web)')
    monitor_parser.add_argument('--isp-cache-ttl', type=int, default=72, help='ISP cache TTL in hours (default: 72)')
    monitor_parser.add_argument('--isp-debug', action='store_true', help='Enable debug logging for ISP lookups')
    monitor_parser.add_argument('--traffic-direction', choices=['outgoing', 'incoming', 'bidirectional', 'all'], default='outgoing',
                               help='Traffic to monitor: outgoing (default, local->remote only), '
                                    'incoming (unsolicited incoming only, e.g., server traffic), '
                                    'bidirectional (responses to outgoing connections), '
                                    'all (everything)')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate iptables rules from log')
    generate_parser.add_argument('-l', '--log', required=True, help='Traffic log file to analyze')
    generate_parser.add_argument('-o', '--output', help='Output file for iptables rules (default: block_rules.sh)')
    generate_parser.add_argument('-f', '--format', choices=['script', 'restore'], default='script',
                                help='Output format (default: script)')
    generate_parser.add_argument('-c', '--chain', default='OUTPUT', help='IPTables chain (default: OUTPUT)')
    generate_parser.add_argument('-a', '--action', default='DROP', choices=['DROP', 'REJECT'],
                                help='Action to take (default: DROP)')
    generate_parser.add_argument('--interactive', action='store_true', help='Interactive IP selection mode')
    generate_parser.add_argument('--min-bytes', type=int, help='Minimum bytes threshold for auto-blocking')
    generate_parser.add_argument('--min-packets', type=int, help='Minimum packets threshold for auto-blocking')
    generate_parser.add_argument('--ips', help='Comma-separated list of specific IPs to block')
    generate_parser.add_argument('--domains', help='Comma-separated list of domains to block')
    
    # List logs command
    list_parser = subparsers.add_parser('list-logs', help='List all captured traffic logs')
    list_parser.add_argument('--log-dir', default='traffic_logs', help='Directory containing logs (default: traffic_logs)')
    
    # Web server command
    web_parser = subparsers.add_parser('web', help='Start web server for traffic visualization')
    web_parser.add_argument('--log-dir', default='traffic_logs', help='Directory containing logs (default: traffic_logs)')
    web_parser.add_argument('--port', type=int, default=5000, help='Port to run web server on (default: 5000)')
    web_parser.add_argument('--debug', action='store_true', help='Run Flask in debug mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    if args.command == 'monitor':
        monitor_command(args)
    elif args.command == 'generate':
        generate_command(args)
    elif args.command == 'list-logs':
        list_logs_command(args)
    elif args.command == 'web':
        web_command(args)


if __name__ == '__main__':
    main()
