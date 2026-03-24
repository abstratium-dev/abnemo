#!/usr/bin/env python3
"""
Filters Module - Accept-list filter management for traffic filtering
Handles both accept-list filters (hide matching) and warn-list filters (highlight matching)
"""

import os
import json
import uuid
import re
import logging
import socket
import smtplib
from datetime import datetime, timezone
from threading import Thread, Lock
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_wtf.csrf import validate_csrf
from flask import request
from werkzeug.exceptions import BadRequest

logger = logging.getLogger(__name__)

# Track which files have been analyzed to avoid duplicate emails
_analyzed_files = set()
_analyzed_files_lock = Lock()


def get_filters_directory():
    """Get the directory where filter files are stored.
    
    Can be overridden with ABNEMO_CONFIG_DIR environment variable.
    Defaults to project root.
    """
    custom_dir = os.getenv('ABNEMO_CONFIG_DIR')
    if custom_dir:
        return custom_dir
    
    # Default to project root (parent of src/)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return project_root


def get_accept_list_filters_file():
    """Get the path to the accept-list filters JSON file"""
    filters_dir = get_filters_directory()
    return os.path.join(filters_dir, 'accept_list_filters.json')


def get_warnlist_filters_file():
    """Get the path to the warn-list filters JSON file"""
    filters_dir = get_filters_directory()
    return os.path.join(filters_dir, 'warnlist_filters.json')


def load_accept_list_filters():
    """Load accept-list filters from JSON file"""
    filters_file = get_accept_list_filters_file()
    if not os.path.exists(filters_file):
        return []
    
    try:
        with open(filters_file, 'r') as f:
            data = json.load(f)
            return data.get('filters', [])
    except Exception as e:
        logger.error(f'Error loading accept-list filters: {e}')
        return []


def load_warnlist_filters():
    """Load warn-list filters from JSON file"""
    filters_file = get_warnlist_filters_file()
    if not os.path.exists(filters_file):
        return []
    
    try:
        with open(filters_file, 'r') as f:
            data = json.load(f)
            return data.get('filters', [])
    except Exception as e:
        logger.error(f'Error loading warn-list filters: {e}')
        return []


def save_filter(filter_data, is_warnlist=False):
    """Save a new filter and return its ID
    
    Args:
        filter_data: Dictionary with pattern, description, etc.
        is_warnlist: If True, save to warn-list file, else to accept-list filters file
    
    Returns:
        filter_id: UUID string
    """
    if is_warnlist:
        filters = load_warnlist_filters()
        filters_file = get_warnlist_filters_file()
    else:
        filters = load_accept_list_filters()
        filters_file = get_accept_list_filters_file()
    
    # Generate a unique ID
    filter_id = str(uuid.uuid4())
    filter_data['id'] = filter_id
    
    filters.append(filter_data)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filters_file), exist_ok=True)
    
    with open(filters_file, 'w') as f:
        json.dump({'filters': filters}, f, indent=2)
    
    return filter_id


def update_filter(filter_id, update_data, is_warnlist=False):
    """Update an existing filter
    
    Args:
        filter_id: UUID of the filter to update
        update_data: Dictionary with fields to update
        is_warnlist: If True, update in warn-list file, else in accept-list filters file
    
    Returns:
        Updated filter object or None if not found
    """
    if is_warnlist:
        filters = load_warnlist_filters()
        filters_file = get_warnlist_filters_file()
    else:
        filters = load_accept_list_filters()
        filters_file = get_accept_list_filters_file()
    
    for filter_obj in filters:
        if filter_obj.get('id') == filter_id:
            # Update only provided fields
            if update_data.get('pattern') is not None:
                filter_obj['pattern'] = update_data['pattern']
            if update_data.get('description') is not None:
                filter_obj['description'] = update_data['description']
            if update_data.get('user_email') is not None:
                filter_obj['user_email'] = update_data['user_email']
            if update_data.get('updated_at') is not None:
                filter_obj['updated_at'] = update_data['updated_at']
            
            with open(filters_file, 'w') as f:
                json.dump({'filters': filters}, f, indent=2)
            
            return filter_obj
    
    return None


def delete_filter(filter_id, is_warnlist=False):
    """Delete a filter
    
    Args:
        filter_id: UUID of the filter to delete
        is_warnlist: If True, delete from warn-list file, else from accept-list filters file
    
    Returns:
        True if deleted, False if not found
    """
    if is_warnlist:
        filters = load_warnlist_filters()
        filters_file = get_warnlist_filters_file()
    else:
        filters = load_accept_list_filters()
        filters_file = get_accept_list_filters_file()
    
    original_count = len(filters)
    filters = [f for f in filters if f.get('id') != filter_id]
    
    if len(filters) == original_count:
        return False
    
    with open(filters_file, 'w') as f:
        json.dump({'filters': filters}, f, indent=2)
    
    return True


def check_warnlist_matches(traffic_data):
    """Check traffic data against warn-list filters, excluding accept-list matches
    
    Packets that match the warn-list will trigger email notifications, UNLESS they
    also match any pattern in the accept-list. The accept-list takes precedence.
    
    Args:
        traffic_data: Dictionary with 'traffic_by_ip' key containing IP data
    
    Returns:
        List of match dictionaries with 'filter', 'matched_ips', and 'details' keys
    """
    warnlist_filters = load_warnlist_filters()
    if not warnlist_filters:
        return []
    
    # Load accept-list filters to exclude from warn-list matches
    accept_list_filters = load_accept_list_filters()
    
    matches = []
    traffic_by_ip = traffic_data.get('traffic_by_ip', {})
    
    for filter_obj in warnlist_filters:
        pattern = filter_obj.get('pattern')
        if not pattern:
            continue
        
        try:
            regex = re.compile(pattern)
            matched_details = {}  # IP -> details dict
            
            for ip, ip_data in traffic_by_ip.items():
                matched = False
                match_reason = []
                
                # Check IP address
                if regex.search(ip):
                    matched = True
                    match_reason.append('IP address')
                
                # Check domains
                domains = ip_data.get('domains', [])
                matched_domains = [d for d in domains if regex.search(str(d))]
                if matched_domains:
                    matched = True
                    match_reason.append(f'Domain: {matched_domains[0]}')
                
                # Check ISP
                isp = ip_data.get('isp')
                if isp and regex.search(str(isp)):
                    matched = True
                    match_reason.append(f'ISP: {isp}')
                
                # Check ports
                ports = ip_data.get('ports', [])
                matched_ports = [p for p in ports if regex.search(str(p))]
                if matched_ports:
                    matched = True
                    match_reason.append(f'Port: {matched_ports[0]}')
                
                # Check processes
                processes = ip_data.get('processes', {})
                # Handle both dict (from live data) and list (from saved logs)
                if isinstance(processes, list):
                    # Convert list to dict for uniform processing
                    processes_dict = {f"proc_{i}": proc for i, proc in enumerate(processes)}
                    matched_procs = [proc.get('name', str(proc)) for proc in processes if regex.search(str(proc.get('name', '')))]
                else:
                    # Dict format
                    matched_procs = [proc for proc in processes.keys() if regex.search(str(proc))]
                
                if matched_procs:
                    matched = True
                    match_reason.append(f'Process: {matched_procs[0]}')
                
                if matched:
                    # Check if this IP also matches any accept-list filter
                    # If it does, skip it (accept-list takes precedence)
                    is_accepted = False
                    for accept_filter in accept_list_filters:
                        accept_pattern = accept_filter.get('pattern')
                        if not accept_pattern:
                            continue
                        try:
                            accept_regex = re.compile(accept_pattern)
                            # Check all fields that could match
                            if accept_regex.search(ip):
                                is_accepted = True
                                break
                            if any(accept_regex.search(str(d)) for d in ip_data.get('domains', [])):
                                is_accepted = True
                                break
                            if ip_data.get('isp') and accept_regex.search(str(ip_data.get('isp'))):
                                is_accepted = True
                                break
                            if any(accept_regex.search(str(p)) for p in ip_data.get('ports', [])):
                                is_accepted = True
                                break
                            # Check processes
                            processes_check = ip_data.get('processes', {})
                            if isinstance(processes_check, list):
                                if any(accept_regex.search(str(proc.get('name', ''))) for proc in processes_check):
                                    is_accepted = True
                                    break
                            else:
                                if any(accept_regex.search(str(proc)) for proc in processes_check.keys()):
                                    is_accepted = True
                                    break
                        except re.error:
                            continue
                    
                    # Only add to matched_details if NOT in accept-list
                    if not is_accepted:
                        # Handle processes field - keep original format
                        processes_field = ip_data.get('processes', {})
                        if isinstance(processes_field, list):
                            processes_output = processes_field
                        else:
                            processes_output = dict(processes_field)
                        
                        matched_details[ip] = {
                            'ip': ip,
                            'domains': list(ip_data.get('domains', [])),
                            'isp': ip_data.get('isp'),
                            'ports': list(ip_data.get('ports', [])),
                            'processes': processes_output,
                            'bytes': ip_data.get('bytes', 0),
                            'packets': ip_data.get('packets', 0),
                            'ip_type': ip_data.get('ip_type'),
                            'match_reason': ', '.join(match_reason)
                        }
            
            if matched_details:
                matches.append({
                    'filter': filter_obj,
                    'matched_ips': list(matched_details.keys()),
                    'details': matched_details
                })
        
        except re.error as e:
            logger.error(f'Invalid regex pattern "{pattern}": {e}')
            continue
    
    return matches


def send_warnlist_email(matches, log_file_path, hostname=None):
    """Send email notification about warn-list matches
    
    Args:
        matches: List of match dictionaries from check_warnlist_matches
        log_file_path: Absolute path to the traffic log file
        hostname: Name of the computer (defaults to socket.gethostname())
    
    Returns:
        True if email sent successfully, False otherwise
    """
    # Check if email is configured
    smtp_host = os.getenv('ABNEMO_SMTP_HOST')
    smtp_port = os.getenv('ABNEMO_SMTP_PORT', '587')
    smtp_username = os.getenv('ABNEMO_SMTP_USERNAME')
    smtp_password = os.getenv('ABNEMO_SMTP_PASSWORD')
    smtp_from = os.getenv('ABNEMO_SMTP_FROM', smtp_username)
    smtp_to = os.getenv('ABNEMO_SMTP_TO')
    smtp_tls = os.getenv('ABNEMO_SMTP_TLS', 'true').lower() in ('true', '1', 'yes')
    
    if not all([smtp_host, smtp_username, smtp_password, smtp_to]):
        logger.debug('Email not configured, skipping notification')
        return False
    
    if not hostname:
        hostname = socket.gethostname()
    
    # Build email content
    subject = f'[ABNEMO] Warn-list traffic detected on {hostname}'
    
    body_lines = [
        f'Warn-list traffic has been detected on {hostname}.',
        f'Traffic log file: {log_file_path}',
        '',
        'IMPORTANT: This traffic matched the warn-list and did NOT match any accept-list patterns.',
        'Traffic that matches the accept-list is automatically excluded from email notifications.',
        '',
        '=' * 80,
        ''
    ]
    
    for match in matches:
        filter_obj = match['filter']
        details = match.get('details', {})
        pattern = filter_obj.get('pattern', 'N/A')
        description = filter_obj.get('description', 'No description')
        
        body_lines.append(f'FILTER: {pattern}')
        body_lines.append(f'Description: {description}')
        body_lines.append('')
        
        for ip, ip_details in details.items():
            body_lines.append(f'  IP: {ip}')
            body_lines.append(f'    Match Reason: {ip_details.get("match_reason", "N/A")}')
            body_lines.append(f'    Type: {ip_details.get("ip_type", "N/A")}')
            
            domains = ip_details.get('domains', [])
            if domains:
                body_lines.append(f'    Domains: {", ".join(str(d) for d in domains)}')
            
            isp = ip_details.get('isp')
            if isp:
                body_lines.append(f'    ISP: {isp}')
            
            ports = ip_details.get('ports', [])
            if ports:
                body_lines.append(f'    Ports: {", ".join(str(p) for p in ports)}')
            
            processes = ip_details.get('processes', {})
            if processes:
                body_lines.append(f'    Processes:')
                # Handle both dict and list formats
                if isinstance(processes, list):
                    for proc_info in processes:
                        proc_name = proc_info.get('name', 'unknown')
                        body_lines.append(f'      - {proc_name}')
                else:
                    for proc_name, proc_info in processes.items():
                        body_lines.append(f'      - {proc_name}: {proc_info.get("bytes", 0)} bytes, {proc_info.get("packets", 0)} packets')
            
            body_lines.append(f'    Total: {ip_details.get("bytes", 0)} bytes, {ip_details.get("packets", 0)} packets')
            body_lines.append('')
        
        body_lines.append('-' * 80)
        body_lines.append('')
    
    body_lines.append('This is an automated notification from ABNEMO.')
    body = '\n'.join(body_lines)
    
    # Create email message
    msg = MIMEMultipart()
    msg['From'] = smtp_from
    msg['To'] = smtp_to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    # Send email
    try:
        smtp_port = int(smtp_port)
        
        logger.debug(f'Attempting to send email to {smtp_to} via {smtp_host}:{smtp_port} (TLS: {smtp_tls})')
        
        if smtp_tls:
            # Use STARTTLS
            logger.debug(f'Connecting to SMTP server with STARTTLS')
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.starttls()
        else:
            # Use SSL/TLS directly
            logger.debug(f'Connecting to SMTP server with SSL/TLS')
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30)
        
        logger.debug(f'Logging in as {smtp_username}')
        server.login(smtp_username, smtp_password)
        
        logger.debug(f'Sending email message')
        server.send_message(msg)
        server.quit()
        
        logger.info(f'Warn-list email sent to {smtp_to}')
        logger.debug(f'Email subject: {subject}')
        return True
    
    except Exception as e:
        logger.error(f'Failed to send warn-list email: {e}')
        logger.debug(f'Email error details:', exc_info=True)
        return False


def analyze_traffic_file_async(log_file_path):
    """Asynchronously analyze a traffic log file for warn-list matches
    
    This function is meant to be called in a background thread.
    Only analyzes each file once to avoid duplicate emails.
    
    Args:
        log_file_path: Path to the traffic log JSON file
    """
    # Get absolute path
    abs_path = os.path.abspath(log_file_path)
    
    # Check if already analyzed
    with _analyzed_files_lock:
        if abs_path in _analyzed_files:
            logger.debug(f'File {abs_path} already analyzed, skipping')
            return
        _analyzed_files.add(abs_path)
    
    try:
        logger.debug(f'Starting analysis of traffic file: {abs_path}')
        with open(abs_path, 'r') as f:
            data = json.load(f)
        
        logger.debug(f'Loaded traffic file, data type: {type(data).__name__}')
        
        # Handle both list and dict formats
        if isinstance(data, list):
            # If it's a list, convert to expected format
            logger.debug(f'Traffic file {abs_path} is in list format, skipping warn-list analysis')
            # Lists are typically raw packet data, skip warn-list analysis
            return
        
        # Ensure it has the expected structure
        if not isinstance(data, dict):
            logger.warning(f'Traffic file {abs_path} has unexpected format (type: {type(data).__name__}), skipping')
            return
        
        if 'traffic_by_ip' not in data:
            logger.warning(f'Traffic file {abs_path} missing "traffic_by_ip" key, available keys: {list(data.keys())}, skipping')
            return
        
        logger.debug(f'Checking warn-list matches for {len(data.get("traffic_by_ip", {}))} IPs')
        matches = check_warnlist_matches(data)
        
        if matches:
            logger.warning(f'Warn-list matches found in {abs_path}')
            for match in matches:
                filter_obj = match['filter']
                matched_ips = match['matched_ips']
                logger.warning(f'  Filter "{filter_obj.get("pattern")}" matched IPs: {", ".join(matched_ips)}')
            
            # Send email notification with absolute path
            send_warnlist_email(matches, abs_path)
    
    except Exception as e:
        logger.error(f'Error analyzing traffic file {abs_path}: {e}', exc_info=True)
        # Remove from analyzed set on error so it can be retried
        with _analyzed_files_lock:
            _analyzed_files.discard(abs_path)


def start_traffic_analysis(log_file_path):
    """Start asynchronous analysis of a traffic log file
    
    Args:
        log_file_path: Path to the traffic log JSON file
    """
    thread = Thread(target=analyze_traffic_file_async, args=(log_file_path,), daemon=True)
    thread.start()


def _validate_csrf_token():
    """Validate CSRF token from request headers or form data.
    
    Returns:
        tuple: (success: bool, error_response: dict or None)
    """
    try:
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not csrf_token:
            return False, ({'error': 'CSRF token missing', 'code': 'csrf_token_missing'}, 403)
        validate_csrf(csrf_token)
        return True, None
    except (BadRequest, Exception) as e:
        return False, ({'error': 'CSRF token validation failed', 'code': 'csrf_error', 'reason': str(e)}, 403)


def register_filter_routes(app, auth_check_func):
    """Register filter management routes with the Flask app
    
    Args:
        app: Flask application instance
        auth_check_func: Function that returns (error_response, status_code) or None if authenticated
    """
    from flask import request, jsonify, g
    
    @app.route('/api/accept-list-filters', methods=['GET'])
    def api_get_accept_list_filters():
        """Get all accept-list filters"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            filters = load_accept_list_filters()
            return jsonify({'filters': filters, 'type': 'accept-list'})
        except Exception as e:
            logger.error(f'Error loading accept-list filters: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/warnlist-filters', methods=['GET'])
    def api_get_warnlist_filters():
        """Get all warn-list filters"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            filters = load_warnlist_filters()
            return jsonify({'filters': filters, 'type': 'warnlist'})
        except Exception as e:
            logger.error(f'Error loading warn-list filters: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/accept-list-filters', methods=['POST'])
    def api_create_accept_list_filter():
        """Create a new accept-list filter"""
        # Validate CSRF token
        csrf_valid, csrf_error = _validate_csrf_token()
        if not csrf_valid:
            return jsonify(csrf_error[0]), csrf_error[1]
        
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json()
            if not data or 'pattern' not in data:
                return jsonify({'error': 'Missing pattern field'}), 400
            
            # Get user email from session
            session = getattr(g, 'session_data', {})
            user = session.get('user', {})
            user_email = user.get('email', 'anonymous')
            
            filter_data = {
                'pattern': data['pattern'],
                'description': data.get('description', ''),
                'user_email': user_email,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            filter_id = save_filter(filter_data, is_warnlist=False)
            filter_data['id'] = filter_id
            
            return jsonify({'filter': filter_data}), 201
        except Exception as e:
            logger.error(f'Error creating accept-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/warnlist-filters', methods=['POST'])
    def api_create_warnlist_filter():
        """Create a new warn-list filter"""
        # Validate CSRF token
        csrf_valid, csrf_error = _validate_csrf_token()
        if not csrf_valid:
            return jsonify(csrf_error[0]), csrf_error[1]
        
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json()
            if not data or 'pattern' not in data:
                return jsonify({'error': 'Missing pattern field'}), 400
            
            # Get user email from session
            session = getattr(g, 'session_data', {})
            user = session.get('user', {})
            user_email = user.get('email', 'anonymous')
            
            filter_data = {
                'pattern': data['pattern'],
                'description': data.get('description', ''),
                'user_email': user_email,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            filter_id = save_filter(filter_data, is_warnlist=True)
            filter_data['id'] = filter_id
            
            return jsonify({'filter': filter_data}), 201
        except Exception as e:
            logger.error(f'Error creating warn-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/accept-list-filters/<filter_id>', methods=['PUT'])
    def api_update_accept_list_filter(filter_id):
        """Update an existing accept-list filter"""
        # Validate CSRF token
        csrf_valid, csrf_error = _validate_csrf_token()
        if not csrf_valid:
            return jsonify(csrf_error[0]), csrf_error[1]
        
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Missing request body'}), 400
            
            # Get user email from session
            session = getattr(g, 'session_data', {})
            user = session.get('user', {})
            user_email = user.get('email', 'anonymous')
            
            update_data = {
                'pattern': data.get('pattern'),
                'description': data.get('description'),
                'user_email': user_email,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            updated_filter = update_filter(filter_id, update_data, is_warnlist=False)
            if not updated_filter:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'filter': updated_filter})
        except Exception as e:
            logger.error(f'Error updating accept-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/warnlist-filters/<filter_id>', methods=['PUT'])
    def api_update_warnlist_filter(filter_id):
        """Update an existing warn-list filter"""
        # Validate CSRF token
        csrf_valid, csrf_error = _validate_csrf_token()
        if not csrf_valid:
            return jsonify(csrf_error[0]), csrf_error[1]
        
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Missing request body'}), 400
            
            # Get user email from session
            session = getattr(g, 'session_data', {})
            user = session.get('user', {})
            user_email = user.get('email', 'anonymous')
            
            update_data = {
                'pattern': data.get('pattern'),
                'description': data.get('description'),
                'user_email': user_email,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            updated_filter = update_filter(filter_id, update_data, is_warnlist=True)
            if not updated_filter:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'filter': updated_filter})
        except Exception as e:
            logger.error(f'Error updating warn-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/accept-list-filters/<filter_id>', methods=['DELETE'])
    def api_delete_accept_list_filter(filter_id):
        """Delete an accept-list filter"""
        # Validate CSRF token
        csrf_valid, csrf_error = _validate_csrf_token()
        if not csrf_valid:
            return jsonify(csrf_error[0]), csrf_error[1]
        
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            success = delete_filter(filter_id, is_warnlist=False)
            if not success:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f'Error deleting accept-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/warnlist-filters/<filter_id>', methods=['DELETE'])
    def api_delete_warnlist_filter(filter_id):
        """Delete a warn-list filter"""
        # Validate CSRF token
        csrf_valid, csrf_error = _validate_csrf_token()
        if not csrf_valid:
            return jsonify(csrf_error[0]), csrf_error[1]
        
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            success = delete_filter(filter_id, is_warnlist=True)
            if not success:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f'Error deleting warn-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
