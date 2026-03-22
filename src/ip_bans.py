#!/usr/bin/env python3
"""
IP Bans Module - Manage IP address bans using UFW and fail2ban
Provides endpoints for listing, banning, and unbanning IP addresses
"""

import subprocess
import logging
import re
from flask import request, jsonify

logger = logging.getLogger(__name__)


def run_command(cmd, timeout=10):
    """Run a shell command and return the result.
    
    Args:
        cmd: Command to run (string or list)
        timeout: Timeout in seconds
        
    Returns:
        tuple: (success: bool, output: str, error: str)
    """
    try:
        if isinstance(cmd, str):
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        
        success = result.returncode == 0
        return success, result.stdout, result.stderr
    
    except subprocess.TimeoutExpired:
        logger.error(f'Command timed out: {cmd}')
        return False, '', 'Command timed out'
    except Exception as e:
        logger.error(f'Error running command {cmd}: {e}')
        return False, '', str(e)


def is_fail2ban_installed():
    """Check if fail2ban-client is installed and accessible.
    
    Returns:
        bool: True if fail2ban-client is available
    """
    success, _, _ = run_command(['which', 'fail2ban-client'])
    return success


def get_banned_ips():
    """Get list of all banned/denied IP addresses from UFW.
    
    Returns:
        list: List of dictionaries with IP address and rule details
    """
    banned_ips = []
    
    # Get UFW status with numbered rules
    success, output, error = run_command(['sudo', 'ufw', 'status', 'numbered'])
    
    if not success:
        logger.error(f'Failed to get UFW status: {error}')
        return banned_ips
    
    # Parse UFW output to find DENY rules
    # Example line: "[ 1] Deny from 192.168.1.100"
    # or: "[ 1] 22/tcp                     DENY IN     192.168.1.100"
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Skip header and empty lines
        if not line or line.startswith('Status:') or line.startswith('To') or line.startswith('--'):
            continue
        
        # Match numbered rules with DENY
        # Pattern 1: [ 1] Deny from 192.168.1.100
        match1 = re.search(r'\[\s*(\d+)\]\s+Deny\s+from\s+([\d\.]+)', line, re.IGNORECASE)
        if match1:
            rule_num = match1.group(1)
            ip = match1.group(2)
            banned_ips.append({
                'ip': ip,
                'rule_number': rule_num,
                'rule': line
            })
            continue
        
        # Pattern 2: [ 1] 22/tcp                     DENY IN     192.168.1.100
        match2 = re.search(r'\[\s*(\d+)\]\s+.*?\s+DENY\s+.*?\s+([\d\.]+)', line, re.IGNORECASE)
        if match2:
            rule_num = match2.group(1)
            ip = match2.group(2)
            banned_ips.append({
                'ip': ip,
                'rule_number': rule_num,
                'rule': line
            })
            continue
        
        # Pattern 3: DENY rules without rule numbers (fallback)
        if 'DENY' in line.upper() or 'REJECT' in line.upper():
            # Try to extract IP address
            ip_match = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                # Avoid duplicates
                if not any(b['ip'] == ip for b in banned_ips):
                    banned_ips.append({
                        'ip': ip,
                        'rule_number': None,
                        'rule': line
                    })
    
    return banned_ips


def ban_ip(ip_address):
    """Ban an IP address using UFW.
    
    Args:
        ip_address: IP address to ban
        
    Returns:
        tuple: (success: bool, message: str)
    """
    # Validate IP address format
    if not re.match(r'^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}$', ip_address):
        return False, 'Invalid IP address format'
    
    # Check if already banned
    banned = get_banned_ips()
    if any(b['ip'] == ip_address for b in banned):
        return False, f'IP {ip_address} is already banned'
    
    # Add deny rule (UFW will add it with appropriate priority)
    cmd = f'sudo ufw deny from {ip_address} to any'
    success, output, error = run_command(cmd)
    
    if not success:
        logger.error(f'Failed to ban IP {ip_address}: {error}')
        return False, f'Failed to ban IP: {error}'
    
    # Reload UFW to apply changes
    reload_success, reload_output, reload_error = run_command(['sudo', 'ufw', 'reload'])
    
    if not reload_success:
        logger.warning(f'UFW reload failed after banning {ip_address}: {reload_error}')
        # Don't fail the operation, the rule is still added
    
    logger.info(f'Successfully banned IP {ip_address}')
    return True, f'Successfully banned IP {ip_address}'


def unban_ip(ip_address):
    """Unban an IP address using fail2ban (if available) and UFW.
    
    Args:
        ip_address: IP address to unban
        
    Returns:
        tuple: (success: bool, message: str)
    """
    # Validate IP address format
    if not re.match(r'^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}$', ip_address):
        return False, 'Invalid IP address format'
    
    messages = []
    overall_success = False
    
    # Try to unban from fail2ban if installed
    if is_fail2ban_installed():
        cmd = f'sudo fail2ban-client unban {ip_address}'
        success, output, error = run_command(cmd)
        
        if success:
            messages.append(f'Unbanned from fail2ban')
            logger.info(f'Unbanned {ip_address} from fail2ban')
        else:
            # fail2ban-client unban returns error if IP wasn't banned by fail2ban
            # This is not a critical error
            logger.debug(f'fail2ban unban result for {ip_address}: {error}')
            messages.append('Not banned by fail2ban (or already unbanned)')
    else:
        messages.append('fail2ban not installed')
    
    # Remove from UFW
    cmd = f'sudo ufw delete deny from {ip_address} to any'
    success, output, error = run_command(cmd)
    
    if success:
        messages.append(f'Removed UFW deny rule')
        overall_success = True
        logger.info(f'Removed UFW deny rule for {ip_address}')
    else:
        # Try alternative approach - the rule might be in different format
        logger.debug(f'Standard UFW delete failed, trying alternative: {error}')
        messages.append(f'UFW rule not found or already removed')
    
    # Reload UFW to apply changes
    reload_success, reload_output, reload_error = run_command(['sudo', 'ufw', 'reload'])
    
    if not reload_success:
        logger.warning(f'UFW reload failed after unbanning {ip_address}: {reload_error}')
    
    if overall_success or 'fail2ban' in ' '.join(messages):
        return True, '; '.join(messages)
    else:
        return False, f'IP {ip_address} was not banned or could not be unbanned: {"; ".join(messages)}'


def register_ip_ban_routes(app, auth_check_func):
    """Register IP ban management routes with the Flask app.
    
    Args:
        app: Flask application instance
        auth_check_func: Function that returns (error_response, status_code) or None if authenticated
    """
    
    @app.route('/api/ip-bans', methods=['GET'])
    def api_get_banned_ips():
        """Get all banned IP addresses"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            banned_ips = get_banned_ips()
            return jsonify({
                'banned_ips': banned_ips,
                'count': len(banned_ips)
            })
        except Exception as e:
            logger.error(f'Error getting banned IPs: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/ip-bans', methods=['POST'])
    def api_ban_ip():
        """Ban an IP address"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            data = request.get_json()
            if not data or 'ip' not in data:
                return jsonify({'error': 'Missing ip field'}), 400
            
            ip_address = data['ip'].strip()
            success, message = ban_ip(ip_address)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': message,
                    'ip': ip_address
                }), 201
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 400
        
        except Exception as e:
            logger.error(f'Error banning IP: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/ip-bans/<ip_address>', methods=['DELETE'])
    def api_unban_ip(ip_address):
        """Unban an IP address"""
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        try:
            success, message = unban_ip(ip_address)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': message,
                    'ip': ip_address
                })
            else:
                return jsonify({
                    'success': False,
                    'error': message
                }), 400
        
        except Exception as e:
            logger.error(f'Error unbanning IP: {e}', exc_info=True)
            return jsonify({'error': str(e)}), 500
