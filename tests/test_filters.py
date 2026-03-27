#!/usr/bin/env python3
"""
Tests for Filters Module - Accept-list and Warn-list filter management
"""

import os
import sys
import json
import tempfile
import shutil
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Import the module under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from filters import (
    get_filters_directory,
    get_accept_list_filters_file,
    get_warnlist_filters_file,
    load_accept_list_filters,
    load_warnlist_filters,
    save_filter,
    update_filter,
    delete_filter,
    check_warnlist_matches,
    send_warnlist_email,
    analyze_traffic_file_async,
    start_traffic_analysis,
    register_filter_routes
)


class TestFilterDirectories:
    """Test filter directory and file path functions"""
    
    def test_get_filters_directory_default(self):
        """Test that default filters directory is project root"""
        with patch.dict(os.environ, {}, clear=True):
            filters_dir = get_filters_directory()
            assert filters_dir is not None
            assert os.path.isabs(filters_dir)
    
    def test_get_filters_directory_custom(self):
        """Test that ABNEMO_CONFIG_DIR environment variable is respected"""
        custom_dir = '/custom/config/dir'
        with patch.dict(os.environ, {'ABNEMO_CONFIG_DIR': custom_dir}):
            filters_dir = get_filters_directory()
            assert filters_dir == custom_dir
    
    def test_get_accept_list_filters_file(self):
        """Test accept-list filters file path"""
        filters_file = get_accept_list_filters_file()
        assert filters_file.endswith('accept_list_filters.json')
    
    def test_get_warnlist_filters_file(self):
        """Test warn-list filters file path"""
        filters_file = get_warnlist_filters_file()
        assert filters_file.endswith('warnlist_filters.json')


class TestFilterLoading:
    """Test filter loading functions"""
    
    def test_load_accept_list_filters_no_file(self):
        """Test loading accept-list filters when file doesn't exist"""
        with patch('filters.get_accept_list_filters_file', return_value='/nonexistent/file.json'):
            filters = load_accept_list_filters()
            assert filters == []
    
    def test_load_accept_list_filters_valid(self, tmp_path):
        """Test loading accept-list filters from valid file"""
        filters_file = tmp_path / 'accept_list_filters.json'
        test_filters = {
            'filters': [
                {'id': '123', 'pattern': '192\\.168\\..*', 'description': 'Local network'}
            ]
        }
        filters_file.write_text(json.dumps(test_filters))
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            filters = load_accept_list_filters()
            assert len(filters) == 1
            assert filters[0]['id'] == '123'
            assert filters[0]['pattern'] == '192\\.168\\..*'
    
    def test_load_accept_list_filters_invalid_json(self, tmp_path):
        """Test loading accept-list filters from invalid JSON file"""
        filters_file = tmp_path / 'accept_list_filters.json'
        filters_file.write_text('invalid json{')
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            filters = load_accept_list_filters()
            assert filters == []
    
    def test_load_warnlist_filters_no_file(self):
        """Test loading warn-list filters when file doesn't exist"""
        with patch('filters.get_warnlist_filters_file', return_value='/nonexistent/file.json'):
            filters = load_warnlist_filters()
            assert filters == []
    
    def test_load_warnlist_filters_valid(self, tmp_path):
        """Test loading warn-list filters from valid file"""
        filters_file = tmp_path / 'warnlist_filters.json'
        test_filters = {
            'filters': [
                {'id': '456', 'pattern': 'malicious\\.com', 'description': 'Known bad domain'}
            ]
        }
        filters_file.write_text(json.dumps(test_filters))
        
        with patch('filters.get_warnlist_filters_file', return_value=str(filters_file)):
            filters = load_warnlist_filters()
            assert len(filters) == 1
            assert filters[0]['id'] == '456'


class TestFilterSaving:
    """Test filter saving functions"""
    
    def test_save_filter_accept_list(self, tmp_path):
        """Test saving a new accept-list filter"""
        filters_file = tmp_path / 'accept_list_filters.json'
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            with patch('filters.load_accept_list_filters', return_value=[]):
                filter_data = {
                    'pattern': '10\\.0\\..*',
                    'description': 'Internal network'
                }
                filter_id = save_filter(filter_data, is_warnlist=False)
                
                assert filter_id is not None
                assert len(filter_id) > 0
                assert filters_file.exists()
                
                # Verify file contents
                with open(filters_file) as f:
                    data = json.load(f)
                    assert len(data['filters']) == 1
                    assert data['filters'][0]['id'] == filter_id
                    assert data['filters'][0]['pattern'] == '10\\.0\\..*'
    
    def test_save_filter_warnlist(self, tmp_path):
        """Test saving a new warn-list filter"""
        filters_file = tmp_path / 'warnlist_filters.json'
        
        with patch('filters.get_warnlist_filters_file', return_value=str(filters_file)):
            with patch('filters.load_warnlist_filters', return_value=[]):
                filter_data = {
                    'pattern': 'suspicious\\..*',
                    'description': 'Suspicious domains'
                }
                filter_id = save_filter(filter_data, is_warnlist=True)
                
                assert filter_id is not None
                assert filters_file.exists()


class TestFilterUpdating:
    """Test filter updating functions"""
    
    def test_update_filter_success(self, tmp_path):
        """Test updating an existing filter"""
        filters_file = tmp_path / 'accept_list_filters.json'
        existing_filters = [
            {'id': 'test-123', 'pattern': 'old-pattern', 'description': 'Old description'}
        ]
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            with patch('filters.load_accept_list_filters', return_value=existing_filters):
                update_data = {
                    'pattern': 'new-pattern',
                    'description': 'New description'
                }
                result = update_filter('test-123', update_data, is_warnlist=False)
                
                assert result is not None
                assert result['pattern'] == 'new-pattern'
                assert result['description'] == 'New description'
    
    def test_update_filter_not_found(self, tmp_path):
        """Test updating a non-existent filter"""
        with patch('filters.load_accept_list_filters', return_value=[]):
            result = update_filter('nonexistent-id', {'pattern': 'test'}, is_warnlist=False)
            assert result is None
    
    def test_update_filter_partial(self, tmp_path):
        """Test updating only some fields of a filter"""
        existing_filters = [
            {'id': 'test-456', 'pattern': 'original', 'description': 'Original desc'}
        ]
        
        with patch('filters.load_accept_list_filters', return_value=existing_filters):
            with patch('filters.get_accept_list_filters_file', return_value='/tmp/test.json'):
                with patch('builtins.open', create=True) as mock_open:
                    mock_open.return_value.__enter__ = Mock()
                    mock_open.return_value.__exit__ = Mock()
                    
                    update_data = {'description': 'Updated description'}
                    result = update_filter('test-456', update_data, is_warnlist=False)
                    
                    assert result is not None
                    assert result['pattern'] == 'original'  # Unchanged
                    assert result['description'] == 'Updated description'  # Changed


class TestFilterDeleting:
    """Test filter deleting functions"""
    
    def test_delete_filter_success(self, tmp_path):
        """Test deleting an existing filter"""
        filters_file = tmp_path / 'accept_list_filters.json'
        existing_filters = [
            {'id': 'delete-me', 'pattern': 'test'},
            {'id': 'keep-me', 'pattern': 'test2'}
        ]
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            with patch('filters.load_accept_list_filters', return_value=existing_filters):
                result = delete_filter('delete-me', is_warnlist=False)
                
                assert result is True
                assert filters_file.exists()
                
                # Verify file contents
                with open(filters_file) as f:
                    data = json.load(f)
                    assert len(data['filters']) == 1
                    assert data['filters'][0]['id'] == 'keep-me'
    
    def test_delete_filter_not_found(self):
        """Test deleting a non-existent filter"""
        with patch('filters.load_accept_list_filters', return_value=[]):
            with patch('filters.get_accept_list_filters_file', return_value='/tmp/test.json'):
                with patch('builtins.open', create=True):
                    result = delete_filter('nonexistent', is_warnlist=False)
                    assert result is False


class TestWarnlistMatching:
    """Test warn-list matching functions"""
    
    def test_check_warnlist_matches_no_filters(self):
        """Test checking warn-list matches when no filters exist"""
        traffic_data = {'traffic_by_ip': {}}
        
        with patch('filters.load_warnlist_filters', return_value=[]):
            matches = check_warnlist_matches(traffic_data)
            assert matches == []
    
    def test_check_warnlist_matches_ip_match(self):
        """Test warn-list matching by IP address"""
        traffic_data = {
            'traffic_by_ip': {
                '192.168.1.100': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': {},
                    'bytes': 1000,
                    'packets': 10,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '192\\.168\\..*', 'description': 'Local network'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                
                assert len(matches) == 1
                assert '192.168.1.100' in matches[0]['matched_ips']
                assert 'IP address' in matches[0]['details']['192.168.1.100']['match_reason']
    
    def test_check_warnlist_matches_domain_match(self):
        """Test warn-list matching by domain"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': ['malicious.com'],
                    'isp': 'Test ISP',
                    'ports': [443],
                    'processes': {},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '2', 'pattern': 'malicious\\.com', 'description': 'Bad domain'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                
                assert len(matches) == 1
                assert '1.2.3.4' in matches[0]['matched_ips']
                assert 'Domain' in matches[0]['details']['1.2.3.4']['match_reason']
    
    def test_check_warnlist_matches_accept_list_precedence(self):
        """Test that accept-list takes precedence over warn-list"""
        traffic_data = {
            'traffic_by_ip': {
                '192.168.1.100': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': {},
                    'bytes': 1000,
                    'packets': 10,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '192\\.168\\..*', 'description': 'Local network'}
        ]
        
        accept_list_filters = [
            {'id': '2', 'pattern': '192\\.168\\..*', 'description': 'Trusted local'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=accept_list_filters):
                matches = check_warnlist_matches(traffic_data)
                
                # Should be empty because accept-list takes precedence
                assert len(matches) == 0
    
    def test_check_warnlist_matches_invalid_regex(self):
        """Test that invalid regex patterns are handled gracefully"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {'domains': [], 'isp': None, 'ports': [], 'processes': {}}
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '[invalid(regex', 'description': 'Bad pattern'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                assert matches == []


class TestEmailNotifications:
    """Test email notification functions"""
    
    def test_send_warnlist_email_not_configured(self):
        """Test that email is not sent when SMTP is not configured"""
        with patch.dict(os.environ, {}, clear=True):
            matches = [{'filter': {}, 'matched_ips': [], 'details': {}}]
            result = send_warnlist_email(matches, '/tmp/test.log')
            assert result is False
    
    @patch('filters.smtplib.SMTP')
    def test_send_warnlist_email_success(self, mock_smtp):
        """Test successful email sending"""
        env_vars = {
            'ABNEMO_SMTP_HOST': 'smtp.example.com',
            'ABNEMO_SMTP_PORT': '587',
            'ABNEMO_SMTP_USERNAME': 'user@example.com',
            'ABNEMO_SMTP_PASSWORD': 'password',
            'ABNEMO_SMTP_TO': 'admin@example.com',
            'ABNEMO_SMTP_TLS': 'true'
        }
        
        matches = [{
            'filter': {'pattern': 'test', 'description': 'Test filter'},
            'matched_ips': ['1.2.3.4'],
            'details': {
                '1.2.3.4': {
                    'ip': '1.2.3.4',
                    'match_reason': 'IP address',
                    'ip_type': 'outbound',
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': {}
                }
            }
        }]
        
        with patch.dict(os.environ, env_vars):
            result = send_warnlist_email(matches, '/tmp/test.log', hostname='testhost')
            assert result is True
            mock_smtp.assert_called_once()


class TestFlaskRoutes:
    """Test Flask route registration"""
    
    def test_register_filter_routes(self):
        """Test that filter routes are registered with Flask app"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        # Create a mock auth check function
        mock_auth_check = Mock(return_value=None)
        
        register_filter_routes(app, mock_auth_check)
        
        # Verify routes were registered
        route_names = [rule.endpoint for rule in app.url_map.iter_rules()]
        # Check for any filter-related routes
        filter_routes = [r for r in route_names if 'filter' in r.lower()]
        assert len(filter_routes) > 0, f"Expected filter routes, got: {route_names}"
    
    def test_get_accept_list_filters_success(self, tmp_path):
        """Test GET /api/accept-list-filters endpoint"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        filters_file = tmp_path / 'accept_list_filters.json'
        filters_data = {'filters': [{'id': '1', 'pattern': 'test', 'description': 'Test'}]}
        filters_file.write_text(json.dumps(filters_data))
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            with app.test_client() as client:
                response = client.get('/api/accept-list-filters')
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['type'] == 'accept-list'
                assert len(data['filters']) == 1
    
    def test_get_accept_list_filters_auth_error(self):
        """Test GET /api/accept-list-filters with auth error"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        with app.app_context():
            from flask import jsonify
            auth_response = (jsonify({'error': 'Unauthorized'}), 401)
        
        mock_auth_check = Mock(return_value=auth_response)
        register_filter_routes(app, mock_auth_check)
        
        with app.test_client() as client:
            response = client.get('/api/accept-list-filters')
            assert response.status_code == 401
    
    def test_get_accept_list_filters_error(self):
        """Test GET /api/accept-list-filters with loading error"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        with patch('filters.load_accept_list_filters', side_effect=Exception('Load error')):
            with app.test_client() as client:
                response = client.get('/api/accept-list-filters')
                assert response.status_code == 500
    
    def test_get_warnlist_filters_success(self, tmp_path):
        """Test GET /api/warnlist-filters endpoint"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        filters_file = tmp_path / 'warnlist_filters.json'
        filters_data = {'filters': [{'id': '1', 'pattern': 'malware', 'description': 'Malware'}]}
        filters_file.write_text(json.dumps(filters_data))
        
        with patch('filters.get_warnlist_filters_file', return_value=str(filters_file)):
            with app.test_client() as client:
                response = client.get('/api/warnlist-filters')
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['type'] == 'warnlist'
                assert len(data['filters']) == 1
    
    def test_get_warnlist_filters_auth_error(self):
        """Test GET /api/warnlist-filters with auth error"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        with app.app_context():
            from flask import jsonify
            auth_response = (jsonify({'error': 'Unauthorized'}), 401)
        
        mock_auth_check = Mock(return_value=auth_response)
        register_filter_routes(app, mock_auth_check)
        
        with app.test_client() as client:
            response = client.get('/api/warnlist-filters')
            assert response.status_code == 401
    
    def test_get_warnlist_filters_error(self):
        """Test GET /api/warnlist-filters with loading error"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        with patch('filters.load_warnlist_filters', side_effect=Exception('Load error')):
            with app.test_client() as client:
                response = client.get('/api/warnlist-filters')
                assert response.status_code == 500
    
    def test_create_accept_list_filter_success(self, tmp_path):
        """Test POST /api/accept-list-filters endpoint"""
        from flask import Flask, g
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        filters_file = tmp_path / 'accept_list_filters.json'
        filters_file.write_text('[]')
        
        with patch('filters.get_accept_list_filters_file', return_value=str(filters_file)):
            with patch('filters._validate_csrf_token', return_value=(True, None)):
                with app.test_client() as client:
                    with client.application.app_context():
                        g.session_data = {'user': {'email': 'test@example.com'}}
                        response = client.post('/api/accept-list-filters',
                                             json={'pattern': 'test.*', 'description': 'Test filter'})
                        assert response.status_code == 201
                        data = json.loads(response.data)
                        assert 'filter' in data
                        assert data['filter']['pattern'] == 'test.*'
    
    def test_create_accept_list_filter_csrf_error(self):
        """Test POST /api/accept-list-filters with CSRF error"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        with patch('filters._validate_csrf_token', return_value=(False, ({'error': 'CSRF error'}, 403))):
            with app.test_client() as client:
                response = client.post('/api/accept-list-filters',
                                     json={'pattern': 'test'})
                assert response.status_code == 403
    
    def test_create_accept_list_filter_auth_error(self):
        """Test POST /api/accept-list-filters with auth error"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        with app.app_context():
            from flask import jsonify
            auth_response = (jsonify({'error': 'Unauthorized'}), 401)
        
        mock_auth_check = Mock(return_value=auth_response)
        register_filter_routes(app, mock_auth_check)
        
        with patch('filters._validate_csrf_token', return_value=(True, None)):
            with app.test_client() as client:
                response = client.post('/api/accept-list-filters',
                                     json={'pattern': 'test'})
                assert response.status_code == 401
    
    def test_create_accept_list_filter_missing_pattern(self):
        """Test POST /api/accept-list-filters with missing pattern"""
        from flask import Flask
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        with patch('filters._validate_csrf_token', return_value=(True, None)):
            with app.test_client() as client:
                response = client.post('/api/accept-list-filters',
                                     json={'description': 'No pattern'})
                assert response.status_code == 400
    
    def test_create_accept_list_filter_error(self, tmp_path):
        """Test POST /api/accept-list-filters with save error"""
        from flask import Flask, g
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        with patch('filters._validate_csrf_token', return_value=(True, None)):
            with patch('filters.save_filter', side_effect=Exception('Save error')):
                with app.test_client() as client:
                    with client.application.app_context():
                        g.session_data = {'user': {'email': 'test@example.com'}}
                        response = client.post('/api/accept-list-filters',
                                             json={'pattern': 'test'})
                        assert response.status_code == 500
    
    def test_create_warnlist_filter_success(self, tmp_path):
        """Test POST /api/warnlist-filters endpoint"""
        from flask import Flask, g
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        
        mock_auth_check = Mock(return_value=None)
        register_filter_routes(app, mock_auth_check)
        
        filters_file = tmp_path / 'warnlist_filters.json'
        filters_file.write_text('[]')
        
        with patch('filters.get_warnlist_filters_file', return_value=str(filters_file)):
            with patch('filters._validate_csrf_token', return_value=(True, None)):
                with app.test_client() as client:
                    with client.application.app_context():
                        g.session_data = {'user': {'email': 'test@example.com'}}
                        response = client.post('/api/warnlist-filters',
                                             json={'pattern': 'malware.*', 'description': 'Malware filter'})
                        assert response.status_code == 201
                        data = json.loads(response.data)
                        assert 'filter' in data
                        assert data['filter']['pattern'] == 'malware.*'
    


class TestTrafficAnalysis:
    """Test traffic analysis functions"""
    
    def test_start_traffic_analysis(self):
        """Test starting traffic analysis in background thread"""
        with patch('filters.Thread') as mock_thread:
            start_traffic_analysis('/tmp/test.log')
            mock_thread.assert_called_once()
            mock_thread.return_value.start.assert_called_once()
    
    def test_analyze_traffic_file_async_already_analyzed(self):
        """Test that files are only analyzed once"""
        with patch('filters._analyzed_files', {'test.log'}):
            with patch('filters.logger') as mock_logger:
                analyze_traffic_file_async('test.log')
                # Should skip analysis
                mock_logger.debug.assert_called()
    
    def test_analyze_traffic_file_async_list_format(self, tmp_path):
        """Test analyzing traffic file in list format"""
        traffic_file = tmp_path / 'traffic.json'
        traffic_file.write_text(json.dumps([{'packet': 'data'}]))
        
        with patch('filters._analyzed_files', set()):
            analyze_traffic_file_async(str(traffic_file))
            # Should skip list format files
    
    def test_analyze_traffic_file_async_dict_format(self, tmp_path):
        """Test analyzing traffic file in dict format"""
        traffic_file = tmp_path / 'traffic.json'
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': ['test.com'],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': {},
                    'bytes': 100,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        traffic_file.write_text(json.dumps(traffic_data))
        
        with patch('filters._analyzed_files', set()):
            with patch('filters.load_warnlist_filters', return_value=[]):
                analyze_traffic_file_async(str(traffic_file))


class TestWarnlistMatchingAdvanced:
    """Advanced tests for warn-list matching"""
    
    def test_check_warnlist_matches_isp_match(self):
        """Test warn-list matching by ISP"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Suspicious ISP',
                    'ports': [443],
                    'processes': {},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '3', 'pattern': 'Suspicious.*', 'description': 'Suspicious ISP'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                
                assert len(matches) == 1
                assert '1.2.3.4' in matches[0]['matched_ips']
                assert 'ISP' in matches[0]['details']['1.2.3.4']['match_reason']
    
    def test_check_warnlist_matches_port_match(self):
        """Test warn-list matching by port"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [4444],
                    'processes': {},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '4', 'pattern': '4444', 'description': 'Suspicious port'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                
                assert len(matches) == 1
                assert 'Port' in matches[0]['details']['1.2.3.4']['match_reason']
    
    def test_check_warnlist_matches_process_dict_match(self):
        """Test warn-list matching by process (dict format)"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': {'malware.exe': {'bytes': 100, 'packets': 2}},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '5', 'pattern': 'malware', 'description': 'Malware process'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                
                assert len(matches) == 1
                assert 'Process' in matches[0]['details']['1.2.3.4']['match_reason']
    
    def test_check_warnlist_matches_process_list_match(self):
        """Test warn-list matching by process (list format)"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': [{'name': 'suspicious.exe', 'pid': 1234}],
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '6', 'pattern': 'suspicious', 'description': 'Suspicious process'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=[]):
                matches = check_warnlist_matches(traffic_data)
                
                assert len(matches) == 1
                assert 'Process' in matches[0]['details']['1.2.3.4']['match_reason']
    
    def test_check_warnlist_accept_list_by_domain(self):
        """Test accept-list precedence by domain"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': ['trusted.com'],
                    'isp': 'Test ISP',
                    'ports': [443],
                    'processes': {},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '.*', 'description': 'Match all'}
        ]
        
        accept_list_filters = [
            {'id': '2', 'pattern': 'trusted\\.com', 'description': 'Trusted domain'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=accept_list_filters):
                matches = check_warnlist_matches(traffic_data)
                assert len(matches) == 0
    
    def test_check_warnlist_accept_list_by_port(self):
        """Test accept-list precedence by port"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [443],
                    'processes': {},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '.*', 'description': 'Match all'}
        ]
        
        accept_list_filters = [
            {'id': '2', 'pattern': '443', 'description': 'HTTPS port'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=accept_list_filters):
                matches = check_warnlist_matches(traffic_data)
                assert len(matches) == 0
    
    def test_check_warnlist_accept_list_by_process_list(self):
        """Test accept-list precedence by process (list format)"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': [{'name': 'chrome.exe', 'pid': 1234}],
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '.*', 'description': 'Match all'}
        ]
        
        accept_list_filters = [
            {'id': '2', 'pattern': 'chrome', 'description': 'Chrome browser'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=accept_list_filters):
                matches = check_warnlist_matches(traffic_data)
                assert len(matches) == 0
    
    def test_check_warnlist_accept_list_by_process_dict(self):
        """Test accept-list precedence by process (dict format)"""
        traffic_data = {
            'traffic_by_ip': {
                '1.2.3.4': {
                    'domains': [],
                    'isp': 'Test ISP',
                    'ports': [80],
                    'processes': {'firefox.exe': {'bytes': 100, 'packets': 2}},
                    'bytes': 500,
                    'packets': 5,
                    'ip_type': 'outbound'
                }
            }
        }
        
        warnlist_filters = [
            {'id': '1', 'pattern': '.*', 'description': 'Match all'}
        ]
        
        accept_list_filters = [
            {'id': '2', 'pattern': 'firefox', 'description': 'Firefox browser'}
        ]
        
        with patch('filters.load_warnlist_filters', return_value=warnlist_filters):
            with patch('filters.load_accept_list_filters', return_value=accept_list_filters):
                matches = check_warnlist_matches(traffic_data)
                assert len(matches) == 0


class TestEmailNotificationsAdvanced:
    """Advanced tests for email notifications"""
    
    @patch('filters.smtplib.SMTP_SSL')
    def test_send_warnlist_email_ssl(self, mock_smtp_ssl):
        """Test email sending with SSL (not STARTTLS)"""
        env_vars = {
            'ABNEMO_SMTP_HOST': 'smtp.example.com',
            'ABNEMO_SMTP_PORT': '465',
            'ABNEMO_SMTP_USERNAME': 'user@example.com',
            'ABNEMO_SMTP_PASSWORD': 'password',
            'ABNEMO_SMTP_TO': 'admin@example.com',
            'ABNEMO_SMTP_TLS': 'false'
        }
        
        matches = [{
            'filter': {'pattern': 'test', 'description': 'Test filter'},
            'matched_ips': ['1.2.3.4'],
            'details': {
                '1.2.3.4': {
                    'ip': '1.2.3.4',
                    'match_reason': 'IP address',
                    'ip_type': 'outbound',
                    'domains': ['test.com'],
                    'isp': 'Test ISP',
                    'ports': [80, 443],
                    'processes': [{'name': 'test.exe', 'pid': 1234}],
                    'bytes': 1000,
                    'packets': 10
                }
            }
        }]
        
        with patch.dict(os.environ, env_vars):
            result = send_warnlist_email(matches, '/tmp/test.log')
            assert result is True
            mock_smtp_ssl.assert_called_once()
    
    @patch('filters.smtplib.SMTP')
    def test_send_warnlist_email_with_process_dict(self, mock_smtp):
        """Test email with process dict format"""
        env_vars = {
            'ABNEMO_SMTP_HOST': 'smtp.example.com',
            'ABNEMO_SMTP_PORT': '587',
            'ABNEMO_SMTP_USERNAME': 'user@example.com',
            'ABNEMO_SMTP_PASSWORD': 'password',
            'ABNEMO_SMTP_TO': 'admin@example.com',
            'ABNEMO_SMTP_TLS': 'true'
        }
        
        matches = [{
            'filter': {'pattern': 'test', 'description': 'Test filter'},
            'matched_ips': ['1.2.3.4'],
            'details': {
                '1.2.3.4': {
                    'ip': '1.2.3.4',
                    'match_reason': 'Process',
                    'ip_type': 'outbound',
                    'domains': [],
                    'isp': None,
                    'ports': [],
                    'processes': {'chrome.exe': {'bytes': 500, 'packets': 5}},
                    'bytes': 500,
                    'packets': 5
                }
            }
        }]
        
        with patch.dict(os.environ, env_vars):
            result = send_warnlist_email(matches, '/tmp/test.log')
            assert result is True
    
    @patch('filters.smtplib.SMTP')
    def test_send_warnlist_email_error(self, mock_smtp):
        """Test email sending failure"""
        mock_smtp.side_effect = Exception('Connection failed')
        
        env_vars = {
            'ABNEMO_SMTP_HOST': 'smtp.example.com',
            'ABNEMO_SMTP_PORT': '587',
            'ABNEMO_SMTP_USERNAME': 'user@example.com',
            'ABNEMO_SMTP_PASSWORD': 'password',
            'ABNEMO_SMTP_TO': 'admin@example.com',
            'ABNEMO_SMTP_TLS': 'true'
        }
        
        matches = [{
            'filter': {},
            'matched_ips': [],
            'details': {}
        }]
        
        with patch.dict(os.environ, env_vars):
            result = send_warnlist_email(matches, '/tmp/test.log')
            assert result is False
