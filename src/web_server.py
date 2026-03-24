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
from flask import Flask, request, jsonify, send_from_directory, redirect, g, Response, render_template
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError

# Import modular components
from src.oauth import (
    build_oauth_config, summarize_oauth_config, MemorySessionStore,
    register_oauth_routes, user_has_required_group
)
from src.filters import register_filter_routes
from src.iptables_endpoints import register_iptables_routes
from src.fail2ban_endpoints import register_fail2ban_routes
from src.ip_bans import register_ip_ban_routes


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


logger = logging.getLogger(__name__)


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


def get_traffic_time_series(log_dir, begin_time, end_time, pattern):
    """Get time series traffic data filtered by regex pattern.
    
    Args:
        log_dir: Directory containing traffic log files
        begin_time: Start time (timezone-aware datetime)
        end_time: End time (timezone-aware datetime)
        pattern: Compiled regex pattern to match against traffic
    
    Returns:
        Dictionary with time_series, traffic_by_ip, and aggregate stats
    """
    import re
    
    if not os.path.exists(log_dir):
        return {"error": "Log directory not found"}
    
    log_files = glob.glob(os.path.join(log_dir, "traffic_log_*.json"))
    time_series_dict = {}  # timestamp -> {bytes, packets}
    aggregated_data = {}
    total_bytes = 0
    total_packets = 0
    
    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)
            
            timestamp_str = data.get('timestamp', '')
            if not timestamp_str:
                continue
            
            try:
                file_timestamp = parse_log_timestamp(timestamp_str)
            except (ValueError, AttributeError):
                continue
            
            if file_timestamp < begin_time or file_timestamp >= end_time:
                continue
            
            # Initialize time series point with zero (will be updated if there's matching traffic)
            timestamp_iso = file_timestamp.isoformat()
            if timestamp_iso not in time_series_dict:
                time_series_dict[timestamp_iso] = {'bytes': 0, 'packets': 0}
            
            # Filter traffic by pattern
            traffic_by_ip = data.get('traffic_by_ip', {})
            period_bytes = 0
            period_packets = 0
            
            for ip, stats in traffic_by_ip.items():
                matched = False
                
                # Check if pattern matches IP
                if pattern.search(ip):
                    matched = True
                
                # Check if pattern matches domain
                domains = stats.get('domains', [])
                if not matched and any(pattern.search(str(d)) for d in domains):
                    matched = True
                
                # Check if pattern matches ISP
                isp = stats.get('isp', {})
                if not matched and isp:
                    isp_str = str(isp.get('org', '')) + ' ' + str(isp.get('country_code', ''))
                    if pattern.search(isp_str):
                        matched = True
                
                # Check if pattern matches ports
                ports = stats.get('ports', [])
                if not matched and any(pattern.search(str(p)) for p in ports):
                    matched = True
                
                # Check if pattern matches processes
                processes = stats.get('processes', [])
                if not matched and processes:
                    if isinstance(processes, list):
                        for proc in processes:
                            if isinstance(proc, dict) and pattern.search(str(proc.get('name', ''))):
                                matched = True
                                break
                    elif isinstance(processes, dict):
                        if any(pattern.search(str(name)) for name in processes.keys()):
                            matched = True
                
                if matched:
                    # Add to aggregated data
                    if ip not in aggregated_data:
                        aggregated_data[ip] = {
                            'bytes': 0,
                            'packets': 0,
                            'domains': set(),
                            'ports': set(),
                            'ip_type': stats.get('ip_type', 'unknown'),
                            'isp': stats.get('isp', {}),
                            'first_seen': timestamp_iso,
                            'last_seen': timestamp_iso
                        }
                    
                    aggregated_data[ip]['bytes'] += stats.get('bytes', 0)
                    aggregated_data[ip]['packets'] += stats.get('packets', 0)
                    aggregated_data[ip]['domains'].update(stats.get('domains', []))
                    aggregated_data[ip]['ports'].update(stats.get('ports', []))
                    aggregated_data[ip]['last_seen'] = timestamp_iso
                    
                    period_bytes += stats.get('bytes', 0)
                    period_packets += stats.get('packets', 0)
                    total_bytes += stats.get('bytes', 0)
                    total_packets += stats.get('packets', 0)
            
            # Update time series point with actual data
            time_series_dict[timestamp_iso]['bytes'] += period_bytes
            time_series_dict[timestamp_iso]['packets'] += period_packets
        
        except Exception as e:
            logger.error(f"Error reading {log_file}: {e}")
            continue
    
    # Convert sets to lists for JSON serialization
    for ip in aggregated_data:
        aggregated_data[ip]['domains'] = list(aggregated_data[ip]['domains'])
        aggregated_data[ip]['ports'] = sorted(list(aggregated_data[ip]['ports']))
    
    # Convert time series dict to sorted list
    time_series = [
        {
            'timestamp': ts,
            'bytes': data['bytes'],
            'packets': data['packets']
        }
        for ts, data in sorted(time_series_dict.items())
    ]
    
    return {
        'begin': begin_time.isoformat(),
        'end': end_time.isoformat(),
        'pattern': pattern.pattern,
        'total_bytes': total_bytes,
        'total_packets': total_packets,
        'total_ips': len(aggregated_data),
        'time_series': time_series,
        'traffic_by_ip': aggregated_data
    }




def create_app(log_dir):
    """Create and configure the Flask application."""
    # Get the project root directory (parent of src/)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_folder = os.path.join(project_root, 'web_static')
    template_folder = os.path.join(project_root, 'templates')
    app = Flask(__name__, static_folder=static_folder, template_folder=template_folder)

    # Configure CSRF protection
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # We'll manually check on state-changing endpoints
    app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for CSRF tokens
    csrf = CSRFProtect(app)

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    oauth_config = build_oauth_config()
    session_store = MemorySessionStore(oauth_config['session_ttl']) if oauth_config['enabled'] else None
    oauth_summary = summarize_oauth_config(oauth_config)
    logger.info('OAuth configuration summary: %s', oauth_summary)
    if oauth_config['enabled']:
        logger.info('OAuth enforcement ENABLED - sign-in required for web endpoints.')
        print('[*] OAuth enforcement enabled (abstrauth configuration detected).')
    else:
        missing = [key.upper() for key, present in (
            ('client_id', oauth_summary['client_id_present']),
            ('client_secret', oauth_summary['client_secret_present']),
            ('authorization_endpoint', oauth_summary['authorization_endpoint']),
            ('token_endpoint', oauth_summary['token_endpoint']),
            ('redirect_uri', oauth_summary['redirect_uri'])
        ) if not present]
        logger.warning('OAuth is disabled - all web endpoints are open. Missing: %s', ', '.join(missing) or 'unknown')
        print(f"[!] OAuth enforcement disabled. Missing required ABSTRAUTH_* values: {', '.join(missing) if missing else 'unknown'}")

    def _ensure_authenticated_response():
        if not oauth_config['enabled']:
            return None
        session = getattr(g, 'session_data', {})
        if session.get('authenticated'):
            if oauth_config['required_groups'] and not user_has_required_group(session, oauth_config['required_groups']):
                return jsonify({
                    'error': 'Missing required group',
                    'code': 'missing_required_group',
                    'oauth_enabled': True,
                    'required_groups': oauth_config['required_groups'],
                    'required_group': oauth_config.get('required_group'),
                    'user': session.get('user'),
                    'has_access': False
                }), 403
            return None
        return jsonify({
            'error': 'Authentication required',
            'code': 'not_authenticated',
            'oauth_enabled': True,
            'has_access': False
        }), 401

    if oauth_config['enabled']:

        @app.before_request
        def _load_bff_session():
            session_id = request.cookies.get(oauth_config['session_cookie_name'])
            session_data = session_store.get(session_id)
            if not session_data:
                session_id, session_data = session_store.create_session()
                g.session_is_new = True
            g.session_id = session_id
            g.session_data = session_data

        @app.after_request
        def _persist_bff_session(response):
            if getattr(g, 'clear_session_cookie', False):
                response.delete_cookie(oauth_config['session_cookie_name'])
                return response

            session_id = getattr(g, 'session_id', None)
            if session_id:
                response.set_cookie(
                    oauth_config['session_cookie_name'],
                    session_id,
                    httponly=True,
                    secure=oauth_config['cookie_secure'],
                    samesite=oauth_config['cookie_samesite'],
                    max_age=oauth_config['session_ttl'],
                    path='/'
                )
            return response

    # Generate CSP nonce for each request
    @app.before_request
    def generate_csp_nonce():
        """Generate a unique nonce for Content-Security-Policy on each request."""
        import secrets
        g.csp_nonce = secrets.token_urlsafe(16)
    
    # Security headers middleware (OWASP best practices)
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses for defense-in-depth protection.
        
        Implements OWASP recommendations:
        - Content-Security-Policy: Prevents XSS attacks
        - X-Frame-Options: Prevents clickjacking
        - X-Content-Type-Options: Prevents MIME sniffing
        - Strict-Transport-Security: Enforces HTTPS
        - Referrer-Policy: Controls referrer information
        - Permissions-Policy: Restricts browser features
        """
        # Content Security Policy - prevents XSS and injection attacks
        # Use nonce for inline scripts, event delegation for handlers
        nonce = getattr(g, 'csp_nonce', '')
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "  # Nonce for inline scripts, no unsafe-inline!
            "style-src 'self' 'unsafe-inline'; "   # unsafe-inline needed for inline styles (consider nonce in future)
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' https://cdn.jsdelivr.net; "  # Allow CDN for source maps
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        
        # Prevent clickjacking attacks
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Enforce HTTPS (only if cookie_secure is enabled)
        if oauth_config.get('cookie_secure', False):
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains; preload'
            )
        
        # Control referrer information leakage
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Restrict browser features
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=(), payment=()'
        )
        
        return response

    # CSRF error handler
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return jsonify({
            'error': 'CSRF token validation failed',
            'code': 'csrf_error',
            'reason': e.description
        }), 403

    @app.route('/api/traffic')
    def api_traffic():
        """API endpoint for traffic data with time range query parameters.
        Loads and filters files dynamically at request time.
        """
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
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
    
    @app.route('/api/traffic-viz')
    def api_traffic_viz():
        """API endpoint for traffic visualization with regex pattern filtering.
        Returns time series data and aggregated traffic matching the pattern.
        """
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
        
        begin_str = request.args.get('begin')
        end_str = request.args.get('end')
        pattern_str = request.args.get('pattern')
        
        if not pattern_str:
            return jsonify({'error': 'Missing pattern parameter'}), 400
        
        # Validate regex pattern
        try:
            import re
            pattern = re.compile(pattern_str)
        except re.error as e:
            return jsonify({'error': f'Invalid regex pattern: {str(e)}'}), 400
        
        # Parse time range
        if not end_str:
            end_time = datetime.now(timezone.utc)
        else:
            try:
                end_time = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
                if not end_time.tzinfo:
                    end_time = end_time.replace(tzinfo=timezone.utc)
                else:
                    end_time = end_time.astimezone(timezone.utc)
            except ValueError:
                return jsonify({'error': 'Invalid end timestamp format. Use ISO8601.'}), 400
        
        if not begin_str:
            begin_time = end_time - timedelta(minutes=60)
        else:
            try:
                begin_time = datetime.fromisoformat(begin_str.replace('Z', '+00:00'))
                if not begin_time.tzinfo:
                    begin_time = begin_time.replace(tzinfo=timezone.utc)
                else:
                    begin_time = begin_time.astimezone(timezone.utc)
            except ValueError:
                return jsonify({'error': 'Invalid begin timestamp format. Use ISO8601.'}), 400
        
        if begin_time >= end_time:
            return jsonify({'error': 'begin must be before end'}), 400
        
        # Get traffic data with time series
        data = get_traffic_time_series(log_dir, begin_time, end_time, pattern)
        return jsonify(data)
    
    @app.route('/')
    def index():
        """Serve index page using template"""
        return render_template('index.html')
    
    @app.route('/iptables')
    def iptables_page():
        """Display iptables visualizer page using template"""
        return render_template('iptables.html')
    
    @app.route('/fail2ban')
    def fail2ban_page():
        """Serve fail2ban visualizer page using template"""
        return render_template('fail2ban.html')
    
    @app.route('/traffic-viz')
    def traffic_viz_page():
        """Serve traffic visualization page using template"""
        return render_template('traffic_viz.html')
    
    @app.route('/ip-bans')
    def ip_bans_page():
        """Serve IP ban management page using template"""
        return render_template('ip_bans.html')
    
    @app.route('/<path:path>')
    def static_files(path):
        """Serve static files"""
        return send_from_directory(static_folder, path)
    
    @app.route('/api/process/<pid>')
    def api_process(pid):
        """API endpoint to get process details via ps command"""
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
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
    
    # Register OAuth routes (includes /api/user, /api/logout, /api/oauth/status, /oauth/login, /oauth/callback)
    register_oauth_routes(app, oauth_config, session_store)

    # Register modular routes
    register_iptables_routes(app, _ensure_authenticated_response)
    register_fail2ban_routes(app, _ensure_authenticated_response)
    register_filter_routes(app, _ensure_authenticated_response)
    register_ip_ban_routes(app, _ensure_authenticated_response)

    return app


def start_web_server(log_dir, port):
    """Start Flask web server for live monitoring"""
    app = create_app(log_dir)

    # Create web_static directory if it doesn't exist
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_folder = os.path.join(project_root, 'web_static')
    os.makedirs(static_folder, exist_ok=True)

    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
