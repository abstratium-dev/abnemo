#!/usr/bin/env python3
"""
Filters Module - Regex filter management for traffic filtering
Handles both accepted filters (hide matching) and warn-list filters (highlight matching)
"""

import os
import json
import logging
import uuid
import re
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from threading import Thread

logger = logging.getLogger(__name__)


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


def get_regex_filters_file():
    """Get the path to the accepted regex filters JSON file"""
    filters_dir = get_filters_directory()
    return os.path.join(filters_dir, 'regex_filters_accepted.json')


def get_regex_warnlist_file():
    """Get the path to the warn-list regex filters JSON file"""
    filters_dir = get_filters_directory()
    return os.path.join(filters_dir, 'regex_filters_warnlist.json')


def load_regex_filters():
    """Load accepted regex filters from JSON file"""
    filters_file = get_regex_filters_file()
    if not os.path.exists(filters_file):
        return []
    
    try:
        with open(filters_file, 'r') as f:
            data = json.load(f)
            return data.get('filters', [])
    except Exception as e:
        logger.error(f'Error loading regex filters: {e}')
        return []


def load_regex_warnlist():
    """Load warn-list regex filters from JSON file"""
    filters_file = get_regex_warnlist_file()
    if not os.path.exists(filters_file):
        return []
    
    try:
        with open(filters_file, 'r') as f:
            data = json.load(f)
            return data.get('filters', [])
    except Exception as e:
        logger.error(f'Error loading warn-list filters: {e}')
        return []


def save_regex_filter(filter_data, is_warnlist=False):
    """Save a new regex filter and return its ID
    
    Args:
        filter_data: Dictionary with pattern, description, etc.
        is_warnlist: If True, save to warn-list file, else to accepted filters file
    
    Returns:
        filter_id: UUID string
    """
    if is_warnlist:
        filters = load_regex_warnlist()
        filters_file = get_regex_warnlist_file()
    else:
        filters = load_regex_filters()
        filters_file = get_regex_filters_file()
    
    # Generate a unique ID
    filter_id = str(uuid.uuid4())
    filter_data['id'] = filter_id
    
    filters.append(filter_data)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filters_file), exist_ok=True)
    
    with open(filters_file, 'w') as f:
        json.dump({'filters': filters}, f, indent=2)
    
    return filter_id


def update_regex_filter(filter_id, update_data, is_warnlist=False):
    """Update an existing regex filter
    
    Args:
        filter_id: UUID of the filter to update
        update_data: Dictionary with fields to update
        is_warnlist: If True, update in warn-list file, else in accepted filters file
    
    Returns:
        Updated filter object or None if not found
    """
    if is_warnlist:
        filters = load_regex_warnlist()
        filters_file = get_regex_warnlist_file()
    else:
        filters = load_regex_filters()
        filters_file = get_regex_filters_file()
    
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


def delete_regex_filter(filter_id, is_warnlist=False):
    """Delete a regex filter
    
    Args:
        filter_id: UUID of the filter to delete
        is_warnlist: If True, delete from warn-list file, else from accepted filters file
    
    Returns:
        True if deleted, False if not found
    """
    if is_warnlist:
        filters = load_regex_warnlist()
        filters_file = get_regex_warnlist_file()
    else:
        filters = load_regex_filters()
        filters_file = get_regex_filters_file()
    
    original_count = len(filters)
    filters = [f for f in filters if f.get('id') != filter_id]
    
    if len(filters) == original_count:
        return False
    
    with open(filters_file, 'w') as f:
        json.dump({'filters': filters}, f, indent=2)
    
    return True


def check_warnlist_matches(traffic_data):
    """Check if traffic data matches any warn-list filters
    
    Args:
        traffic_data: Dictionary with traffic_by_ip data
    
    Returns:
        List of matches: [{'filter': filter_obj, 'matched_ips': [ip1, ip2, ...]}]
    """
    warnlist = load_regex_warnlist()
    if not warnlist:
        return []
    
    matches = []
    
    for filter_obj in warnlist:
        pattern = filter_obj.get('pattern', '')
        if not pattern:
            continue
        
        try:
            regex = re.compile(pattern)
            matched_ips = []
            
            # Check against all IPs and their associated data
            traffic_by_ip = traffic_data.get('traffic_by_ip', {})
            for ip, stats in traffic_by_ip.items():
                # Check IP address
                if regex.search(ip):
                    matched_ips.append(ip)
                    continue
                
                # Check domains
                for domain in stats.get('domains', []):
                    if regex.search(domain):
                        matched_ips.append(ip)
                        break
                else:
                    # Check ISP/org
                    isp = stats.get('isp', {})
                    if isp:
                        org = isp.get('org', '')
                        if org and regex.search(org):
                            matched_ips.append(ip)
                            continue
            
            if matched_ips:
                matches.append({
                    'filter': filter_obj,
                    'matched_ips': list(set(matched_ips))  # Deduplicate
                })
        
        except re.error as e:
            logger.error(f'Invalid regex pattern "{pattern}": {e}')
            continue
    
    return matches


def send_warnlist_email(matches, hostname=None):
    """Send email notification about warn-list matches
    
    Args:
        matches: List of match dictionaries from check_warnlist_matches
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
        '',
        'The following filters matched:',
        ''
    ]
    
    for match in matches:
        filter_obj = match['filter']
        matched_ips = match['matched_ips']
        pattern = filter_obj.get('pattern', 'N/A')
        description = filter_obj.get('description', 'No description')
        
        body_lines.append(f'Filter: {pattern}')
        body_lines.append(f'Description: {description}')
        body_lines.append(f'Matched IPs: {", ".join(matched_ips)}')
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
        
        if smtp_tls:
            # Use STARTTLS
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.starttls()
        else:
            # Use SSL/TLS directly
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30)
        
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f'Warn-list email sent to {smtp_to}')
        return True
    
    except Exception as e:
        logger.error(f'Failed to send warn-list email: {e}')
        return False


def analyze_traffic_file_async(log_file_path):
    """Asynchronously analyze a traffic log file for warn-list matches
    
    This function is meant to be called in a background thread.
    
    Args:
        log_file_path: Path to the traffic log JSON file
    """
    try:
        with open(log_file_path, 'r') as f:
            data = json.load(f)
        
        matches = check_warnlist_matches(data)
        
        if matches:
            logger.warning(f'Warn-list matches found in {log_file_path}')
            for match in matches:
                filter_obj = match['filter']
                matched_ips = match['matched_ips']
                logger.warning(f'  Filter "{filter_obj.get("pattern")}" matched IPs: {", ".join(matched_ips)}')
            
            # Send email notification
            send_warnlist_email(matches)
    
    except Exception as e:
        logger.error(f'Error analyzing traffic file {log_file_path}: {e}')


def start_traffic_analysis(log_file_path):
    """Start asynchronous analysis of a traffic log file
    
    Args:
        log_file_path: Path to the traffic log JSON file
    """
    thread = Thread(target=analyze_traffic_file_async, args=(log_file_path,), daemon=True)
    thread.start()


def register_filter_routes(app, auth_check_func):
    """Register filter management routes with the Flask app
    
    Args:
        app: Flask application instance
        auth_check_func: Function that returns (error_response, status_code) or None if authenticated
    """
    from flask import request, jsonify, g
    
    @app.route('/api/regex-filters', methods=['GET'])
    def api_get_regex_filters():
        """Get all accepted regex filters"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            filters = load_regex_filters()
            return jsonify({'filters': filters, 'type': 'accepted'})
        except Exception as e:
            logger.error(f'Error loading regex filters: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters/warnlist', methods=['GET'])
    def api_get_regex_warnlist():
        """Get all warn-list regex filters"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            filters = load_regex_warnlist()
            return jsonify({'filters': filters, 'type': 'warnlist'})
        except Exception as e:
            logger.error(f'Error loading warn-list filters: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters', methods=['POST'])
    def api_create_regex_filter():
        """Create a new accepted regex filter"""
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
            
            filter_id = save_regex_filter(filter_data, is_warnlist=False)
            filter_data['id'] = filter_id
            
            return jsonify({'filter': filter_data}), 201
        except Exception as e:
            logger.error(f'Error creating regex filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters/warnlist', methods=['POST'])
    def api_create_regex_warnlist():
        """Create a new warn-list regex filter"""
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
            
            filter_id = save_regex_filter(filter_data, is_warnlist=True)
            filter_data['id'] = filter_id
            
            return jsonify({'filter': filter_data}), 201
        except Exception as e:
            logger.error(f'Error creating warn-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters/<filter_id>', methods=['PUT'])
    def api_update_regex_filter(filter_id):
        """Update an existing accepted regex filter"""
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
            
            updated_filter = update_regex_filter(filter_id, update_data, is_warnlist=False)
            if not updated_filter:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'filter': updated_filter})
        except Exception as e:
            logger.error(f'Error updating regex filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters/warnlist/<filter_id>', methods=['PUT'])
    def api_update_regex_warnlist(filter_id):
        """Update an existing warn-list regex filter"""
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
            
            updated_filter = update_regex_filter(filter_id, update_data, is_warnlist=True)
            if not updated_filter:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'filter': updated_filter})
        except Exception as e:
            logger.error(f'Error updating warn-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters/<filter_id>', methods=['DELETE'])
    def api_delete_regex_filter(filter_id):
        """Delete an accepted regex filter"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            success = delete_regex_filter(filter_id, is_warnlist=False)
            if not success:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f'Error deleting regex filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/regex-filters/warnlist/<filter_id>', methods=['DELETE'])
    def api_delete_regex_warnlist(filter_id):
        """Delete a warn-list regex filter"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            success = delete_regex_filter(filter_id, is_warnlist=True)
            if not success:
                return jsonify({'error': 'Filter not found'}), 404
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f'Error deleting warn-list filter: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
