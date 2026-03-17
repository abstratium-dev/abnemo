#!/usr/bin/env python3
"""
Abnemo - Network Traffic Monitor and IPTables Rule Generator
Main CLI interface for the network monitoring tool
"""

import argparse
import sys
import os
import json
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ebpf_monitor import EBPFMonitor

logger = logging.getLogger(__name__)


def configure_logging(log_level):
    """Configure logging for the entire application.
    
    Args:
        log_level: String log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Suppress overly verbose third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)


def monitor_command(args):
    """Handle the monitor subcommand"""
    # Configure logging
    configure_logging(args.log_level)
    
    # Get API key from args or environment variable
    api_key = args.isp_api_key or os.environ.get('IPAPI_KEY')
    
    # Start web server in background if requested
    if args.web:
        import threading
        from src.web_server import start_web_server
        web_thread = threading.Thread(
            target=start_web_server,
            args=(args.log_dir, args.web_port),
            daemon=True
        )
        web_thread.start()
        logger.info(f"Web server started on http://0.0.0.0:{args.web_port}")
        logger.info(f"Access at: http://localhost:{args.web_port}/")
    
    # Always use eBPF mode for process tracking
    monitor = EBPFMonitor(
        log_dir=args.log_dir,
        isp_api_key=api_key,
        log_retention_days=args.log_retention_days,
        log_max_size_mb=args.log_max_size_mb,
        continuous_log_interval=args.continuous_log_interval,
        top_n=args.top,
        isp_cache_ttl_hours=args.isp_cache_ttl,
        traffic_direction=args.traffic_direction,
        extra_verbose_for_testing=args.extraverbosefortesting
    )
    
    try:
        monitor.start_monitoring_ebpf(
            interface=args.interface,
            duration=args.duration,
            summary_interval=args.summary_interval,
            top_n=args.top
        )
    except PermissionError:
        logger.error("eBPF monitoring requires root privileges")
        logger.error("Please run with sudo: sudo python3 abnemo.py monitor")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during monitoring: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Print summary
    monitor.print_summary(top_n=args.top)
    
    # Save statistics
    log_file = monitor.save_statistics()
    
    logger.info(f"\nTo generate iptables rules from this log, run:")
    logger.info(f"    python3 src/abnemo.py generate --log {log_file} --interactive")


def list_logs_command(args):
    """Handle the list-logs subcommand"""
    configure_logging(args.log_level)
    
    log_dir = args.log_dir
    
    if not os.path.exists(log_dir):
        logger.error(f"Log directory not found: {log_dir}")
        return
    
    log_files = [f for f in os.listdir(log_dir) if f.endswith('.json')]
    
    if not log_files:
        logger.warning(f"No log files found in {log_dir}")
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




def iptables_tree_command(args):
    """Handle the iptables-tree subcommand - visualize iptables as tree"""
    configure_logging(args.log_level)
    
    from src.iptables import load_iptables_config, IptablesTreeFormatter
    
    # Load configuration
    try:
        config = load_iptables_config(
            enrichment_file=args.enrichment,
            iptables_file=args.file,
            table=args.table,
            use_sudo=not args.file
        )
    except Exception as e:
        logger.error(f"Error loading iptables configuration: {e}")
        sys.exit(1)
    
    # Create formatter
    formatter = IptablesTreeFormatter(
        show_docker_only=args.docker_only,
        show_rules=not args.no_rules
    )
    
    # Format and print
    if args.chain:
        # Show specific chain
        table = config.get_table(args.table)
        if not table:
            logger.error(f"Table '{args.table}' not found")
            sys.exit(1)
        
        chain = table.get_chain(args.chain)
        if not chain:
            logger.error(f"Chain '{args.chain}' not found in table '{args.table}'")
            sys.exit(1)
        
        output = formatter.format_chain(chain, table)
    else:
        # Show full config
        output = formatter.format_config(config)
    
    print(output)


def web_command(args):
    """Handle the web subcommand - start standalone web server"""
    configure_logging(args.log_level)
    
    from src.web_server import start_web_server
    
    logger.info(f"Starting web server on http://0.0.0.0:{args.port}")
    logger.info(f"Log directory: {args.log_dir}")
    logger.info(f"API endpoint: http://0.0.0.0:{args.port}/api/traffic")
    logger.info(f"Web interface: http://0.0.0.0:{args.port}/")
    logger.info(f"Press Ctrl+C to stop")
    
    start_web_server(args.log_dir, args.port)


def main():
    parser = argparse.ArgumentParser(
        description="Abnemo - Network Traffic Monitor and IPTables Rule Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor traffic for 60 seconds
  sudo python3 src/abnemo.py monitor --duration 60

  # Monitor specific interface
  sudo python3 src/abnemo.py monitor --interface eth0

  # Generate rules interactively from a log
  python3 src/abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --interactive

  # Generate rules for IPs with >10MB traffic
  python3 src/abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --min-bytes 10485760

  # Block specific domains
  python3 src/abnemo.py generate --log traffic_logs/traffic_log_20240301_120000.json --domains "example.com,ads.com"

  # List all captured logs
  python3 src/abnemo.py list-logs

  # Visualize iptables configuration as tree
  sudo python3 src/abnemo.py iptables-tree

  # Show only Docker-related chains and rules
  sudo python3 src/abnemo.py iptables-tree --docker-only

  # Show specific chain
  sudo python3 src/abnemo.py iptables-tree --chain DOCKER --max-rules 10
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
    monitor_parser.add_argument('--web', action='store_true', help='Start web server for live monitoring')
    monitor_parser.add_argument('--web-port', type=int, default=5000, help='Port for web server (default: 5000, only used with --web)')
    monitor_parser.add_argument('--isp-cache-ttl', type=int, default=72, help='ISP cache TTL in hours (default: 72)')
    monitor_parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                               help='Set logging level (default: INFO)')
    monitor_parser.add_argument('--traffic-direction', choices=['outgoing', 'incoming', 'bidirectional', 'all'], default='outgoing',
                               help='Traffic to monitor: outgoing (default, local->remote only), '
                                    'incoming (unsolicited incoming only, e.g., server traffic), '
                                    'bidirectional (responses to outgoing connections), '
                                    'all (everything)')
    monitor_parser.add_argument('--extraverbosefortesting', action='store_true',
                               help='Log every packet to /tmp/verification_abnemo_packets.log for testing')
    
    # List logs command
    list_parser = subparsers.add_parser('list-logs', help='List all captured traffic logs')
    list_parser.add_argument('--log-dir', default='traffic_logs', help='Directory containing logs (default: traffic_logs)')
    list_parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help='Set logging level (default: INFO)')
    
    # Web server command
    web_parser = subparsers.add_parser('web', help='Start web server for traffic visualization')
    web_parser.add_argument('--log-dir', default='traffic_logs', help='Directory containing logs (default: traffic_logs)')
    web_parser.add_argument('--port', type=int, default=5000, help='Port to run web server on (default: 5000)')
    web_parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                           help='Set logging level (default: INFO)')
    
    # IPTables tree visualization command
    tree_parser = subparsers.add_parser('iptables-tree', help='Visualize iptables configuration as tree')
    tree_parser.add_argument('-f', '--file', help='Path to iptables output file (if not provided, runs iptables command)')
    tree_parser.add_argument('-e', '--enrichment', help='Path to Docker enrichment data file (if not provided, runs docker ps command)')
    tree_parser.add_argument('-t', '--table', default='filter', help='Table to visualize (default: filter)')
    tree_parser.add_argument('-d', '--docker-only', action='store_true', help='Show only Docker-related chains and rules')
    tree_parser.add_argument('-n', '--no-rules', action='store_true', help='Hide rules, show only chains')
    tree_parser.add_argument('-c', '--chain', help='Show only a specific chain')
    tree_parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help='Set logging level (default: INFO)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    if args.command == 'monitor':
        monitor_command(args)
    elif args.command == 'list-logs':
        list_logs_command(args)
    elif args.command == 'web':
        web_command(args)
    elif args.command == 'iptables-tree':
        iptables_tree_command(args)


if __name__ == '__main__':
    main()
