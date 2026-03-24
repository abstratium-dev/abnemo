#!/usr/bin/env python3
"""
Fail2ban Endpoints Module - API endpoints for fail2ban visualization
"""

import logging
from flask_wtf.csrf import validate_csrf
from werkzeug.exceptions import BadRequest

logger = logging.getLogger(__name__)

# Import fail2ban visualizer
try:
    from src.fail2ban_visualizer import get_fail2ban_output, Fail2banParser, Fail2banMermaidGenerator
    from src.fail2ban_visualizer import generate_html_visualization as generate_fail2ban_html
    FAIL2BAN_AVAILABLE = True
except ImportError:
    FAIL2BAN_AVAILABLE = False


def register_fail2ban_routes(app, auth_check_func):
    """Register fail2ban routes with the Flask app
    
    Args:
        app: Flask application instance
        auth_check_func: Function that returns (error_response, status_code) or None if authenticated
    """
    from flask import request, jsonify
    
    @app.route('/api/fail2ban/visualize')
    def api_fail2ban_visualize():
        """API endpoint to get fail2ban Mermaid diagram code
        
        Returns JSON with mermaid_code field
        """
        auth_error = auth_check_func()
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
        # Validate CSRF token
        try:
            csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not csrf_token:
                return jsonify({'error': 'CSRF token missing', 'code': 'csrf_token_missing'}), 403
            validate_csrf(csrf_token)
        except (BadRequest, Exception) as e:
            return jsonify({'error': 'CSRF token validation failed', 'code': 'csrf_error', 'reason': str(e)}), 403
        
        auth_error = auth_check_func()
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
