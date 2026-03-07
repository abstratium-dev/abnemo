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
import base64
import hashlib
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, send_from_directory, redirect, g, Response

# Import iptables visualizer
try:
    from iptables_visualizer import get_iptables_output, IptablesParser, MermaidGenerator, generate_html_visualization
    IPTABLES_AVAILABLE = True
except ImportError:
    IPTABLES_AVAILABLE = False

# Import fail2ban visualizer
try:
    from fail2ban_visualizer import get_fail2ban_output, Fail2banParser, Fail2banMermaidGenerator
    from fail2ban_visualizer import generate_html_visualization as generate_fail2ban_html
    FAIL2BAN_AVAILABLE = True
except ImportError:
    FAIL2BAN_AVAILABLE = False


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


def _base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _generate_code_verifier():
    return _base64url_encode(os.urandom(32))


def _generate_state():
    return _base64url_encode(os.urandom(16))


def _build_code_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    return _base64url_encode(digest)


def _parse_jwt_claims(token):
    if not token or '.' not in token:
        return {}
    try:
        payload = token.split('.')[1]
        padded = payload + '=' * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded.decode('utf-8'))
    except Exception:
        return {}


def _build_oauth_config():
    config = {
        'client_id': os.getenv('ABSTRAUTH_CLIENT_ID'),
        'client_secret': os.getenv('ABSTRAUTH_CLIENT_SECRET'),
        'authorization_endpoint': os.getenv('ABSTRAUTH_AUTHORIZATION_ENDPOINT'),
        'token_endpoint': os.getenv('ABSTRAUTH_TOKEN_ENDPOINT'),
        'redirect_uri': os.getenv('ABSTRAUTH_REDIRECT_URI'),
        'scope': os.getenv('ABSTRAUTH_SCOPE', 'openid profile email'),
        'session_cookie_name': os.getenv('ABSTRAUTH_SESSION_COOKIE', 'abnemo_session'),
        'cookie_secure': os.getenv('ABSTRAUTH_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes'),
        'cookie_samesite': 'Lax',
        'session_ttl': int(os.getenv('ABSTRAUTH_SESSION_TTL', '3600')),
    }
    required_groups_raw = os.getenv('ABSTRAUTH_REQUIRED_GROUPS')
    if required_groups_raw:
        required_groups = [group.strip() for group in required_groups_raw.split(',') if group.strip()]
    else:
        single_group = os.getenv('ABSTRAUTH_REQUIRED_GROUP')
        required_groups = [single_group] if single_group else []
    config['required_groups'] = required_groups
    config['required_group'] = required_groups[0] if len(required_groups) == 1 else None
    required = ['client_id', 'client_secret', 'authorization_endpoint', 'token_endpoint', 'redirect_uri']
    config['enabled'] = all(config[key] for key in required)
    return config


def _summarize_oauth_config(config):
    summary = {
        'enabled': config.get('enabled', False),
        'client_id_present': bool(config.get('client_id')),
        'client_secret_present': bool(config.get('client_secret')),
        'authorization_endpoint': bool(config.get('authorization_endpoint')),
        'token_endpoint': bool(config.get('token_endpoint')),
        'redirect_uri': bool(config.get('redirect_uri')),
        'scope': config.get('scope'),
        'session_cookie_name': config.get('session_cookie_name'),
        'cookie_secure': config.get('cookie_secure'),
        'cookie_samesite': config.get('cookie_samesite'),
        'session_ttl': config.get('session_ttl'),
        'required_group': config.get('required_group'),
        'required_groups': config.get('required_groups'),
    }
    return summary


class MemorySessionStore:
    """Simple in-memory session storage for BFF state."""

    def __init__(self, ttl_seconds=3600):
        self.ttl_seconds = ttl_seconds
        self._sessions = {}
        self._lock = threading.Lock()

    def _now(self):
        return datetime.now(timezone.utc)

    def _is_expired(self, session):
        expires_at = session.get('_session_expires_at')
        return bool(expires_at and expires_at < self._now())

    def create_session(self):
        with self._lock:
            session_id = secrets.token_urlsafe(32)
            data = {
                '_session_expires_at': self._now() + timedelta(seconds=self.ttl_seconds),
                'authenticated': False
            }
            self._sessions[session_id] = data
            return session_id, data

    def get(self, session_id):
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if self._is_expired(session):
                del self._sessions[session_id]
                return None
            session['_session_expires_at'] = self._now() + timedelta(seconds=self.ttl_seconds)
            return session

    def delete(self, session_id):
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)


def _build_authorization_url(base_url, params):
    parsed = urllib.parse.urlparse(base_url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query.update(params)
    encoded = urllib.parse.urlencode(query)
    rebuilt = parsed._replace(query=encoded)
    return urllib.parse.urlunparse(rebuilt)


def _exchange_code_for_token(config, code, code_verifier):
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config['redirect_uri'],
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'code_verifier': code_verifier
    }
    data = urllib.parse.urlencode(payload).encode('utf-8')
    request_obj = urllib.request.Request(
        config['token_endpoint'],
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=15) as response:
            body = response.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='ignore')
        logger.error('Token exchange failed: %s', error_body)
        raise


def _extract_user(tokens):
    token = tokens.get('id_token') or tokens.get('access_token')
    claims = _parse_jwt_claims(token)
    if not claims:
        return None

    def _normalize_groups(raw_groups):
        if not raw_groups:
            return []
        if isinstance(raw_groups, str):
            return [raw_groups]
        if isinstance(raw_groups, (list, tuple, set)):
            return [str(group) for group in raw_groups if group]
        return [str(raw_groups)]

    user = {
        'sub': claims.get('sub'),
        'email': claims.get('email'),
        'name': claims.get('name'),
        'groups': _normalize_groups(claims.get('groups')),
    }
    # Remove empty values
    return {k: v for k, v in user.items() if v}


def _user_has_required_group(session, required_groups):
    if not required_groups:
        return True
    user = session.get('user') or {}
    groups = user.get('groups') or []
    return any(group in groups for group in required_groups)


def create_app(log_dir):
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder='web_static')

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    oauth_config = _build_oauth_config()
    session_store = MemorySessionStore(oauth_config['session_ttl']) if oauth_config['enabled'] else None
    oauth_summary = _summarize_oauth_config(oauth_config)
    if oauth_summary['cookie_samesite'] == 'Strict':
        logger.warning('ABSTRAUTH_COOKIE_SAMESITE is set to Strict; OAuth redirects from another domain may not carry the session cookie. Consider Lax for Authorization Code flow.')
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
            if oauth_config['required_groups'] and not _user_has_required_group(session, oauth_config['required_groups']):
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
    
    @app.route('/')
    def index():
        """Serve index.html"""
        return send_from_directory('web_static', 'index.html')
    
    @app.route('/iptables')
    def iptables_page():
        """Serve iptables visualizer page"""
        return send_from_directory('web_static', 'iptables_page.html')
    
    @app.route('/fail2ban')
    def fail2ban_page():
        """Serve fail2ban visualizer page"""
        return send_from_directory('web_static', 'fail2ban_page.html')
    
    @app.route('/<path:path>')
    def static_files(path):
        """Serve static files"""
        return send_from_directory('web_static', path)
    
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
    
    @app.route('/api/user')
    def api_user():
        """Return authentication status and user info."""
        if not oauth_config['enabled']:
            return jsonify({'authenticated': True, 'oauth_enabled': False, 'user': None})

        session = getattr(g, 'session_data', {})
        if not session.get('authenticated'):
            return jsonify({
                'authenticated': False,
                'oauth_enabled': True,
                'user': None,
                'code': 'not_authenticated',
                'required_groups': oauth_config['required_groups'],
                'required_group': oauth_config.get('required_group'),
                'has_access': False
            }), 401

        if oauth_config['required_groups'] and not _user_has_required_group(session, oauth_config['required_groups']):
            return jsonify({
                'authenticated': True,
                'oauth_enabled': True,
                'user': session.get('user'),
                'code': 'missing_required_group',
                'required_groups': oauth_config['required_groups'],
                'required_group': oauth_config.get('required_group'),
                'has_access': False
            }), 403

        return jsonify({
            'authenticated': True,
            'oauth_enabled': True,
            'user': session.get('user'),
            'required_groups': oauth_config['required_groups'],
            'required_group': oauth_config.get('required_group'),
            'has_access': True
        })

    @app.route('/api/logout', methods=['POST'])
    def api_logout():
        """Clear authentication session."""
        if not oauth_config['enabled']:
            return jsonify({'success': True, 'oauth_enabled': False})

        session_id = getattr(g, 'session_id', None)
        session_store.delete(session_id)
        g.clear_session_cookie = True
        return jsonify({'success': True})

    @app.route('/api/oauth/status')
    def api_oauth_status():
        """Expose non-secret OAuth configuration details for diagnostics."""
        summary = _summarize_oauth_config(oauth_config)
        summary['active_session'] = bool(getattr(g, 'session_data', {}).get('authenticated'))
        if oauth_config['enabled']:
            summary['session_cookie_received'] = bool(request.cookies.get(oauth_config['session_cookie_name']))
        return jsonify(summary)

    @app.route('/oauth/login')
    def oauth_login():
        if not oauth_config['enabled']:
            return jsonify({'error': 'OAuth not configured'}), 404

        session = getattr(g, 'session_data', {})
        code_verifier = _generate_code_verifier()
        code_challenge = _build_code_challenge(code_verifier)
        state = _generate_state()

        session['pkce'] = {
            'code_verifier': code_verifier,
            'state': state,
            'created_at': datetime.now(timezone.utc).isoformat()
        }

        auth_url = _build_authorization_url(
            oauth_config['authorization_endpoint'],
            {
                'response_type': 'code',
                'client_id': oauth_config['client_id'],
                'redirect_uri': oauth_config['redirect_uri'],
                'scope': oauth_config['scope'],
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256'
            }
        )
        return redirect(auth_url)

    @app.route('/oauth/callback')
    def oauth_callback():
        if not oauth_config['enabled']:
            return jsonify({'error': 'OAuth not configured'}), 404

        session = getattr(g, 'session_data', {})
        pkce = session.get('pkce', {})
        expected_state = pkce.get('state')
        received_state = request.args.get('state')
        if not expected_state or expected_state != received_state:
            return redirect('/?error=invalid_state')

        code = request.args.get('code')
        if not code:
            return redirect('/?error=missing_code')

        try:
            tokens = _exchange_code_for_token(oauth_config, code, pkce.get('code_verifier', ''))
        except Exception:
            return redirect('/?error=token_exchange_failed')

        session.pop('pkce', None)
        session['authenticated'] = True
        session['tokens'] = {
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=tokens.get('expires_in', 3600))).isoformat()
        }
        session['user'] = _extract_user(tokens)

        return redirect('/')

    @app.route('/api/iptables/visualize')
    def api_iptables_visualize():
        """API endpoint to get iptables Mermaid diagram code
        
        Query parameters:
            show_all: If 'true', shows all rules instead of just the first 5 of each type
        
        Returns JSON with mermaid_code field
        """
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
        
        if not IPTABLES_AVAILABLE:
            return jsonify({
                'error': 'iptables visualizer module not available',
                'details': 'Could not import iptables_visualizer module'
            }), 500
        
        try:
            # Check if user wants to see all rules
            show_all = request.args.get('show_all', 'false').lower() == 'true'
            
            # Get iptables output
            iptables_output = get_iptables_output()
            
            # Parse the output
            parser = IptablesParser()
            chains = parser.parse_output(iptables_output)
            
            # Generate Mermaid diagram
            generator = MermaidGenerator(chains)
            # If show_all is True, set max_rules_per_type to 0 (unlimited)
            # Otherwise use default of 5
            max_rules = 0 if show_all else 5
            mermaid_code = generator.generate(simplified=True, max_rules_per_type=max_rules)
            
            # Return JSON with Mermaid code
            return jsonify({'mermaid_code': mermaid_code})
            
        except RuntimeError as e:
            return jsonify({
                'error': 'Failed to get iptables data',
                'details': str(e)
            }), 500
        except Exception as e:
            logger.error(f'Error generating iptables visualization: {e}', exc_info=True)
            return jsonify({
                'error': 'Failed to generate visualization',
                'details': str(e)
            }), 500

    @app.route('/api/iptables/visualize/custom', methods=['POST'])
    def api_iptables_visualize_custom():
        """API endpoint to visualize custom iptables rules from user input
        
        POST body should contain:
            config: The iptables -L -v -n output as text
            show_all: Optional boolean to show all rules
        """
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
        
        if not IPTABLES_AVAILABLE:
            return jsonify({
                'error': 'iptables visualizer module not available',
                'details': 'Could not import iptables_visualizer module'
            }), 500
        
        try:
            data = request.get_json()
            if not data or 'config' not in data:
                return jsonify({
                    'error': 'Missing config in request body',
                    'details': 'POST body must contain "config" field with iptables output'
                }), 400
            
            iptables_output = data['config']
            show_all = data.get('show_all', False)
            
            # Parse the output
            parser = IptablesParser()
            chains = parser.parse_output(iptables_output)
            
            # Generate Mermaid diagram
            generator = MermaidGenerator(chains)
            max_rules = 0 if show_all else 5
            mermaid_code = generator.generate(simplified=True, max_rules_per_type=max_rules)
            
            # Return JSON with Mermaid code
            return jsonify({'mermaid_code': mermaid_code})
            
        except Exception as e:
            logger.error(f'Error generating custom iptables visualization: {e}', exc_info=True)
            return jsonify({
                'error': 'Failed to generate visualization',
                'details': str(e)
            }), 500

    @app.route('/api/fail2ban/visualize')
    def api_fail2ban_visualize():
        """API endpoint to get fail2ban Mermaid diagram code
        
        Returns JSON with mermaid_code field
        """
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
        
        if not FAIL2BAN_AVAILABLE:
            return jsonify({
                'error': 'fail2ban visualizer module not available',
                'details': 'Could not import fail2ban_visualizer module'
            }), 500
        
        try:
            # Get fail2ban output
            fail2ban_output = get_fail2ban_output()
            
            # Parse the output
            parser = Fail2banParser()
            data = parser.parse_output(fail2ban_output)
            
            # Generate Mermaid diagram
            generator = Fail2banMermaidGenerator(data)
            mermaid_code = generator.generate(simplified=True)
            
            # Return JSON with Mermaid code
            return jsonify({'mermaid_code': mermaid_code})
            
        except RuntimeError as e:
            return jsonify({
                'error': 'Failed to get fail2ban data',
                'details': str(e)
            }), 500
        except Exception as e:
            logger.error(f'Error generating fail2ban visualization: {e}', exc_info=True)
            return jsonify({
                'error': 'Failed to generate visualization',
                'details': str(e)
            }), 500

    @app.route('/api/fail2ban/visualize/custom', methods=['POST'])
    def api_fail2ban_visualize_custom():
        """API endpoint to visualize custom fail2ban config from user input
        
        POST body should contain:
            config: The fail2ban-client --dp output as text
        """
        auth_error = _ensure_authenticated_response()
        if auth_error:
            return auth_error
        
        if not FAIL2BAN_AVAILABLE:
            return jsonify({
                'error': 'fail2ban visualizer module not available',
                'details': 'Could not import fail2ban_visualizer module'
            }), 500
        
        try:
            data = request.get_json()
            if not data or 'config' not in data:
                return jsonify({
                    'error': 'Missing config in request body',
                    'details': 'POST body must contain "config" field with fail2ban --dp output'
                }), 400
            
            fail2ban_output = data['config']
            
            # Parse the output
            parser = Fail2banParser()
            parsed_data = parser.parse_output(fail2ban_output)
            
            # Generate Mermaid diagram
            generator = Fail2banMermaidGenerator(parsed_data)
            mermaid_code = generator.generate(simplified=True)
            
            # Return JSON with Mermaid code
            return jsonify({'mermaid_code': mermaid_code})
            
        except Exception as e:
            logger.error(f'Error generating custom fail2ban visualization: {e}', exc_info=True)
            return jsonify({
                'error': 'Failed to generate visualization',
                'details': str(e)
            }), 500

    return app


def start_web_server(log_dir, port):
    """Start Flask web server for live monitoring"""
    app = create_app(log_dir)

    # Create web_static directory if it doesn't exist
    os.makedirs('web_static', exist_ok=True)

    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
