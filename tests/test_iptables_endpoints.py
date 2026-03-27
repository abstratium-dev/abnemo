#!/usr/bin/env python3
"""
Tests for IPTables Endpoints Module
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from flask import Flask


class TestRegisterIptablesRoutes:
    """Test iptables route registration"""
    
    def test_register_routes(self):
        """Test that iptables routes are registered"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        # Verify routes were registered
        route_names = [rule.endpoint for rule in app.url_map.iter_rules()]
        assert any('iptables' in r.lower() for r in route_names)


class TestIptablesTextEndpoint:
    """Test /api/iptables/text endpoint"""
    
    def test_iptables_text_success(self):
        """Test successful iptables text generation"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        # Mock the iptables functions
        mock_config = {'filter': {'chains': {}}, 'nat': {'chains': {}}}
        mock_text = "Filter Table\n  INPUT Chain\n    Rule 1"
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', True):
            with patch('src.iptables_endpoints.load_iptables_config', return_value=mock_config):
                with patch('src.iptables_endpoints.IptablesTreeFormatter') as mock_formatter_class:
                    # Setup mock
                    mock_formatter = Mock()
                    mock_formatter.format_config.return_value = mock_text
                    mock_formatter_class.return_value = mock_formatter
                    
                    with app.test_client() as client:
                        response = client.get('/api/iptables/text')
                        
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert 'text' in data
                        assert data['text'] == mock_text
                        
                        # Verify formatter was created with correct defaults
                        mock_formatter_class.assert_called_once_with(
                            show_docker_only=False,
                            show_rules=True,
                            inline_chains=True,
                            compress_same_target=True
                        )
    
    def test_iptables_text_docker_only(self):
        """Test iptables text with docker_only parameter"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        mock_config = {'filter': {'chains': {}}}
        mock_text = "Docker chains only"
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', True):
            with patch('src.iptables_endpoints.load_iptables_config', return_value=mock_config):
                with patch('src.iptables_endpoints.IptablesTreeFormatter') as mock_formatter_class:
                    mock_formatter = Mock()
                    mock_formatter.format_config.return_value = mock_text
                    mock_formatter_class.return_value = mock_formatter
                    
                    with app.test_client() as client:
                        response = client.get('/api/iptables/text?docker_only=true')
                        
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert 'text' in data
                        
                        # Verify formatter was created with docker_only=True
                        mock_formatter_class.assert_called_once_with(
                            show_docker_only=True,
                            show_rules=True,
                            inline_chains=True,
                            compress_same_target=True
                        )
    
    def test_iptables_text_no_rules(self):
        """Test iptables text with no_rules parameter"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        mock_config = {'filter': {'chains': {}}}
        mock_text = "Chains only"
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', True):
            with patch('src.iptables_endpoints.load_iptables_config', return_value=mock_config):
                with patch('src.iptables_endpoints.IptablesTreeFormatter') as mock_formatter_class:
                    mock_formatter = Mock()
                    mock_formatter.format_config.return_value = mock_text
                    mock_formatter_class.return_value = mock_formatter
                    
                    with app.test_client() as client:
                        response = client.get('/api/iptables/text?no_rules=true')
                        
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert 'text' in data
                        
                        # Verify formatter was created with show_rules=False
                        mock_formatter_class.assert_called_once_with(
                            show_docker_only=False,
                            show_rules=False,
                            inline_chains=True,
                            compress_same_target=True
                        )
    
    def test_iptables_text_combined_params(self):
        """Test iptables text with both docker_only and no_rules"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        mock_config = {'filter': {'chains': {}}}
        mock_text = "Docker chains only, no rules"
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', True):
            with patch('src.iptables_endpoints.load_iptables_config', return_value=mock_config):
                with patch('src.iptables_endpoints.IptablesTreeFormatter') as mock_formatter_class:
                    mock_formatter = Mock()
                    mock_formatter.format_config.return_value = mock_text
                    mock_formatter_class.return_value = mock_formatter
                    
                    with app.test_client() as client:
                        response = client.get('/api/iptables/text?docker_only=true&no_rules=true')
                        
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert 'text' in data
                        
                        # Verify formatter was created with both flags
                        mock_formatter_class.assert_called_once_with(
                            show_docker_only=True,
                            show_rules=False,
                            inline_chains=True,
                            compress_same_target=True
                        )
    
    def test_iptables_text_not_available(self):
        """Test when iptables module is not available"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', False):
            with app.test_client() as client:
                response = client.get('/api/iptables/text')
                
                assert response.status_code == 500
                data = json.loads(response.data)
                assert 'error' in data
                assert 'not available' in data['error']
    
    def test_iptables_text_exception(self):
        """Test when iptables raises exception"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', True):
            with patch('src.iptables_endpoints.load_iptables_config', side_effect=Exception('Test error')):
                with app.test_client() as client:
                    response = client.get('/api/iptables/text')
                    
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'error' in data
                    assert 'Failed to generate text representation' in data['error']
    
    def test_iptables_text_auth_required(self):
        """Test that authentication is required"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        # Mock auth check to return error
        mock_auth_check = Mock(return_value=({'error': 'Unauthorized'}, 401))
        register_iptables_routes(app, mock_auth_check)
        
        with app.test_client() as client:
            response = client.get('/api/iptables/text')
            
            assert response.status_code == 401
    
    def test_iptables_text_false_params(self):
        """Test iptables text with explicitly false parameters"""
        from src.iptables_endpoints import register_iptables_routes
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_iptables_routes(app, mock_auth_check)
        
        mock_config = {'filter': {'chains': {}}}
        mock_text = "Full output"
        
        with patch('src.iptables_endpoints.IPTABLES_AVAILABLE', True):
            with patch('src.iptables_endpoints.load_iptables_config', return_value=mock_config):
                with patch('src.iptables_endpoints.IptablesTreeFormatter') as mock_formatter_class:
                    mock_formatter = Mock()
                    mock_formatter.format_config.return_value = mock_text
                    mock_formatter_class.return_value = mock_formatter
                    
                    with app.test_client() as client:
                        response = client.get('/api/iptables/text?docker_only=false&no_rules=false')
                        
                        assert response.status_code == 200
                        
                        # Verify formatter was created with defaults
                        mock_formatter_class.assert_called_once_with(
                            show_docker_only=False,
                            show_rules=True,
                            inline_chains=True,
                            compress_same_target=True
                        )
