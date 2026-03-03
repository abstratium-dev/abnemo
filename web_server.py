#!/usr/bin/env python3
"""
Web Server Module - Flask web server for live traffic monitoring
Provides REST API and web interface for real-time traffic visualization
"""

import os
import json
import glob
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, send_from_directory


def parse_log_timestamp(timestamp_str):
    """
    Parse timestamp from log file and convert to UTC.
    Log files store timestamps in local time, so we need to convert to UTC for comparison.
    
    Args:
        timestamp_str: Timestamp string from log file
        
    Returns:
        datetime object in UTC (timezone-aware)
    """
    # Handle both formats: "2026-03-01T21:07:07.015487" and "2026-03-01 21:07:07"
    if 'T' in timestamp_str:
        # ISO format - check if it has timezone info
        if 'Z' in timestamp_str or '+' in timestamp_str or timestamp_str.count('-') > 2:
            # Has timezone info - parse and convert to UTC
            file_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            file_timestamp = file_timestamp.astimezone(timezone.utc)
        else:
            # No timezone info - assume local time
            file_timestamp = datetime.fromisoformat(timestamp_str)
            # Convert from local time to UTC
            file_timestamp = file_timestamp.astimezone(timezone.utc)
    else:
        # Space-separated format - assume local time
        file_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        # Convert from local time to UTC
        file_timestamp = file_timestamp.replace(tzinfo=None).astimezone(timezone.utc)
    
    return file_timestamp


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
                file_timestamp = parse_log_timestamp(timestamp_str)
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
                                proc_data = {
                                    'pid': str(proc['pid']),
                                    'name': proc.get('name', 'unknown')
                                }
                                # Add container info if available
                                if 'container' in proc:
                                    proc_data['container'] = proc['container']
                                aggregated_data[ip]['processes'].append(proc_data)
                    elif isinstance(stats['processes'], dict):
                        # Dict format from standard logs
                        for pid, proc_info in stats['processes'].items():
                            proc_data = {
                                'pid': pid,
                                'name': proc_info.get('name', 'unknown')
                            }
                            # Add container info if available
                            if 'container' in proc_info:
                                proc_data['container'] = proc_info['container']
                            aggregated_data[ip]['processes'].append(proc_data)
                
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
                pid = proc.get('pid')
                if not pid:
                    continue
                if pid not in seen_pids:
                    seen_pids[pid] = proc
                    continue
                existing = seen_pids[pid]
                if (not existing.get('container')) and proc.get('container'):
                    existing['container'] = proc['container']
                if (not existing.get('name') or existing.get('name') == 'unknown') and proc.get('name'):
                    existing['name'] = proc['name']
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


def create_app(log_dir):
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder='web_static')

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
            end_time = datetime.now(timezone.utc)
        else:
            try:
                end_time = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
                # Ensure timezone-aware (convert to UTC if needed)
                if not end_time.tzinfo:
                    end_time = end_time.replace(tzinfo=timezone.utc)
                else:
                    end_time = end_time.astimezone(timezone.utc)
            except ValueError:
                return jsonify({'error': 'Invalid end timestamp format. Use ISO8601.'}), 400
        
        if not begin_str:
            begin_time = end_time - timedelta(minutes=5)
        else:
            try:
                begin_time = datetime.fromisoformat(begin_str.replace('Z', '+00:00'))
                # Ensure timezone-aware (convert to UTC if needed)
                if not begin_time.tzinfo:
                    begin_time = begin_time.replace(tzinfo=timezone.utc)
                else:
                    begin_time = begin_time.astimezone(timezone.utc)
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
    
    return app


def start_web_server(log_dir, port):
    """Start Flask web server for live monitoring"""
    app = create_app(log_dir)

    # Create web_static directory if it doesn't exist
    os.makedirs('web_static', exist_ok=True)

    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
