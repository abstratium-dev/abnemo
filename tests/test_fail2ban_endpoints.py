#!/usr/bin/env python3
"""
Tests for Fail2ban Endpoints Module
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from flask import Flask


class TestRegisterFail2banRoutes:
    """Test fail2ban route registration"""
    
    def test_register_routes(self):
        """Test that fail2ban routes are registered"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        # Verify routes were registered
        route_names = [rule.endpoint for rule in app.url_map.iter_rules()]
        assert any('fail2ban' in r.lower() for r in route_names)


class TestFail2banVisualizeEndpoint:
    """Test /api/fail2ban/visualize endpoint"""
    
    def test_visualize_success(self):
        """Test successful fail2ban visualization"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        # Mock the fail2ban functions
        mock_output = "test fail2ban output"
        mock_data = {'jails': {}, 'global_settings': {}}
        mock_mermaid = "graph TD\n  A[Test]"
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with patch('src.fail2ban_endpoints.get_fail2ban_output', return_value=mock_output):
                with patch('src.fail2ban_endpoints.Fail2banParser') as mock_parser_class:
                    with patch('src.fail2ban_endpoints.Fail2banMermaidGenerator') as mock_gen_class:
                        # Setup mocks
                        mock_parser = Mock()
                        mock_parser.parse_output.return_value = mock_data
                        mock_parser_class.return_value = mock_parser
                        
                        mock_generator = Mock()
                        mock_generator.generate.return_value = mock_mermaid
                        mock_gen_class.return_value = mock_generator
                        
                        with app.test_client() as client:
                            response = client.get('/api/fail2ban/visualize')
                            
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert 'mermaid_code' in data
                            assert data['mermaid_code'] == mock_mermaid
    
    def test_visualize_not_available(self):
        """Test when fail2ban module is not available"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', False):
            with app.test_client() as client:
                response = client.get('/api/fail2ban/visualize')
                
                assert response.status_code == 500
                data = json.loads(response.data)
                assert 'error' in data
                assert 'not available' in data['error']
    
    def test_visualize_runtime_error(self):
        """Test when fail2ban raises RuntimeError"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with patch('src.fail2ban_endpoints.get_fail2ban_output', side_effect=RuntimeError('fail2ban not running')):
                with app.test_client() as client:
                    response = client.get('/api/fail2ban/visualize')
                    
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'error' in data
                    assert 'Failed to get fail2ban data' in data['error']
    
    def test_visualize_general_exception(self):
        """Test when fail2ban raises general exception"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with patch('src.fail2ban_endpoints.get_fail2ban_output', side_effect=Exception('Test error')):
                with app.test_client() as client:
                    response = client.get('/api/fail2ban/visualize')
                    
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'error' in data
                    assert 'Failed to generate visualization' in data['error']
    
    def test_visualize_auth_required(self):
        """Test that authentication is required"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        # Mock auth check to return error
        mock_auth_check = Mock(return_value=({'error': 'Unauthorized'}, 401))
        register_fail2ban_routes(app, mock_auth_check)
        
        with app.test_client() as client:
            response = client.get('/api/fail2ban/visualize')
            
            assert response.status_code == 401


class TestFail2banVisualizeCustomEndpoint:
    """Test /api/fail2ban/visualize/custom endpoint"""
    
    def test_visualize_custom_success(self):
        """Test successful custom fail2ban visualization"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        # Mock the fail2ban functions
        mock_data = {'jails': {}, 'global_settings': {}}
        mock_mermaid = "graph TD\n  A[Test]"
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with patch('src.fail2ban_endpoints.Fail2banParser') as mock_parser_class:
                with patch('src.fail2ban_endpoints.Fail2banMermaidGenerator') as mock_gen_class:
                    with patch('src.fail2ban_endpoints.validate_csrf'):
                        # Setup mocks
                        mock_parser = Mock()
                        mock_parser.parse_output.return_value = mock_data
                        mock_parser_class.return_value = mock_parser
                        
                        mock_generator = Mock()
                        mock_generator.generate.return_value = mock_mermaid
                        mock_gen_class.return_value = mock_generator
                        
                        with app.test_client() as client:
                            response = client.post('/api/fail2ban/visualize/custom',
                                                 json={'config': 'test config'},
                                                 headers={'X-CSRF-Token': 'test_token'})
                            
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert 'mermaid_code' in data
                            assert data['mermaid_code'] == mock_mermaid
    
    def test_visualize_custom_missing_config(self):
        """Test custom visualization with missing config"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with patch('src.fail2ban_endpoints.validate_csrf'):
                with app.test_client() as client:
                    response = client.post('/api/fail2ban/visualize/custom',
                                         json={},
                                         headers={'X-CSRF-Token': 'test_token'})
                    
                    assert response.status_code == 400
                    data = json.loads(response.data)
                    assert 'error' in data
                    assert 'Missing config' in data['error']
    
    def test_visualize_custom_not_available(self):
        """Test custom visualization when module not available"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', False):
            with patch('src.fail2ban_endpoints.validate_csrf'):
                with app.test_client() as client:
                    response = client.post('/api/fail2ban/visualize/custom',
                                         json={'config': 'test'},
                                         headers={'X-CSRF-Token': 'test_token'})
                    
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'error' in data
                    assert 'not available' in data['error']
    
    def test_visualize_custom_exception(self):
        """Test custom visualization with exception"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with patch('src.fail2ban_endpoints.Fail2banParser', side_effect=Exception('Test error')):
                with patch('src.fail2ban_endpoints.validate_csrf'):
                    with app.test_client() as client:
                        response = client.post('/api/fail2ban/visualize/custom',
                                             json={'config': 'test'},
                                             headers={'X-CSRF-Token': 'test_token'})
                        
                        assert response.status_code == 500
                        data = json.loads(response.data)
                        assert 'error' in data
                        assert 'Failed to generate visualization' in data['error']
    
    def test_visualize_custom_csrf_missing(self):
        """Test custom visualization with missing CSRF token"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.FAIL2BAN_AVAILABLE', True):
            with app.test_client() as client:
                response = client.post('/api/fail2ban/visualize/custom',
                                     json={'config': 'test'})
                
                assert response.status_code == 403
                data = json.loads(response.data)
                assert 'error' in data
                assert 'CSRF token missing' in data['error']
    
    def test_visualize_custom_auth_required(self):
        """Test that authentication is required for custom visualization"""
        from src.fail2ban_endpoints import register_fail2ban_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        # Mock auth check to return error
        mock_auth_check = Mock(return_value=({'error': 'Unauthorized'}, 401))
        register_fail2ban_routes(app, mock_auth_check)
        
        with patch('src.fail2ban_endpoints.validate_csrf'):
            with app.test_client() as client:
                response = client.post('/api/fail2ban/visualize/custom',
                                     json={'config': 'test'},
                                     headers={'X-CSRF-Token': 'test_token'})
                
                assert response.status_code == 401
