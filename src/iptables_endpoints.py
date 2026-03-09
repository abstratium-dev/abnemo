#!/usr/bin/env python3
"""
IPTables Endpoints Module - API endpoints for iptables visualization
"""

import logging

logger = logging.getLogger(__name__)

# Import iptables tree formatter
try:
    from src.iptables import load_iptables_config, IptablesTreeFormatter
    IPTABLES_AVAILABLE = True
except ImportError:
    IPTABLES_AVAILABLE = False


def register_iptables_routes(app, auth_check_func):
    """Register iptables routes with the Flask app
    
    Args:
        app: Flask application instance
        auth_check_func: Function that returns (error_response, status_code) or None if authenticated
    """
    from flask import request, jsonify
    
    @app.route('/api/iptables/text')
    def api_iptables_text():
        """API endpoint to get iptables configuration as text tree
        
        Query parameters:
            docker_only: If 'true', shows only Docker-related chains and rules
            no_rules: If 'true', hides rules and shows only chains
        
        Returns JSON with text field containing the tree representation
        """
        auth_error = auth_check_func()
        if auth_error:
            return auth_error
        
        if not IPTABLES_AVAILABLE:
            return jsonify({
                'error': 'iptables module not available',
                'details': 'Could not import iptables module'
            }), 500
        
        try:
            # Parse query parameters
            docker_only = request.args.get('docker_only', 'false').lower() == 'true'
            no_rules = request.args.get('no_rules', 'false').lower() == 'true'
            
            # Load iptables configuration
            config = load_iptables_config()
            
            # Format as tree
            formatter = IptablesTreeFormatter(
                show_docker_only=docker_only,
                show_rules=not no_rules,
                inline_chains=True,
                compress_same_target=True
            )
            tree_text = formatter.format_config(config)
            
            # Return JSON with text
            return jsonify({'text': tree_text})
            
        except Exception as e:
            logger.error(f'Error generating iptables text: {e}', exc_info=True)
            return jsonify({
                'error': 'Failed to generate text representation',
                'details': str(e)
            }), 500
