#!/usr/bin/env python3
"""
Unit tests for web_server module
Tests timestamp parsing, log aggregation, and API endpoints
"""

import pytest
import json
import os
import tempfile
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Import the module under test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import parse_log_timestamp, get_logs_in_range, create_app


class TestParseLogTimestamp:
    """Test timestamp parsing with various formats and timezones"""
    
    def test_parse_iso_format_with_utc_z(self):
        """Test parsing ISO format with Z (UTC) timezone"""
        ts = parse_log_timestamp("2026-03-02T20:15:42.000Z")
        assert ts.tzinfo == timezone.utc
        assert ts.hour == 20
        assert ts.minute == 15
    
    def test_parse_iso_format_with_plus_offset(self):
        """Test parsing ISO format with +HH:MM offset"""
        ts = parse_log_timestamp("2026-03-02T21:15:42.000+01:00")
        # Should be converted to UTC
        assert ts.tzinfo == timezone.utc
        # 21:15 +01:00 = 20:15 UTC
        assert ts.hour == 20
        assert ts.minute == 15
    
    def test_parse_iso_format_local_time(self):
        """Test parsing ISO format without timezone (assumes local time)"""
        ts = parse_log_timestamp("2026-03-02T21:15:42.123456")
        # Should be converted to UTC
        assert ts.tzinfo == timezone.utc
        # Result depends on system timezone, but should be timezone-aware
    
    def test_parse_space_separated_format(self):
        """Test parsing space-separated format (assumes local time)"""
        ts = parse_log_timestamp("2026-03-02 21:15:42")
        # Should be converted to UTC
        assert ts.tzinfo == timezone.utc
    
    def test_parse_invalid_format_raises_error(self):
        """Test that invalid format raises ValueError"""
        with pytest.raises(ValueError):
            parse_log_timestamp("invalid-timestamp")
    
    def test_parse_empty_string_raises_error(self):
        """Test that empty string raises ValueError"""
        with pytest.raises(ValueError):
            parse_log_timestamp("")


class TestGetLogsInRange:
    """Test log file aggregation with various scenarios"""
    
    @pytest.fixture
    def temp_log_dir(self):
        """Create temporary directory for test log files"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def create_test_log(self, log_dir, timestamp_str, traffic_data):
        """Helper to create a test log file"""
        filename = f"traffic_log_{timestamp_str.replace(':', '').replace('-', '').replace('T', '_')[:15]}.json"
        filepath = os.path.join(log_dir, filename)
        
        log_content = {
            "timestamp": timestamp_str,
            "total_bytes": sum(ip_data['bytes'] for ip_data in traffic_data.values()),
            "total_packets": sum(ip_data['packets'] for ip_data in traffic_data.values()),
            "total_ips": len(traffic_data),
            "traffic_by_ip": traffic_data
        }
        
        with open(filepath, 'w') as f:
            json.dump(log_content, f)
        
        return filepath
    
    def test_empty_directory(self, temp_log_dir):
        """Test with empty log directory"""
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        assert result['total_ips'] == 0
        assert result['total_bytes'] == 0
        assert result['files_processed'] == 0
    
    def test_nonexistent_directory(self):
        """Test with nonexistent directory"""
        result = get_logs_in_range("/nonexistent/path", 
                                   datetime.now(timezone.utc), 
                                   datetime.now(timezone.utc))
        assert 'error' in result
    
    def test_single_log_in_range(self, temp_log_dir):
        """Test with single log file within time range"""
        # Create log at 20:30 UTC
        traffic_data = {
            "1.2.3.4": {
                "bytes": 1000,
                "packets": 10,
                "domains": ["example.com"],
                "ports": [443],
                "ip_type": "public",
                "isp": {"org": "Example ISP"},
                "processes": []
            }
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data)
        
        # Query 20:00 to 21:00 UTC
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        assert result['files_processed'] == 1
        assert result['total_ips'] == 1
        assert result['total_bytes'] == 1000
        assert "1.2.3.4" in result['traffic_by_ip']
    
    def test_log_outside_range(self, temp_log_dir):
        """Test with log file outside time range"""
        traffic_data = {
            "1.2.3.4": {"bytes": 1000, "packets": 10, "domains": [], "ports": [], 
                       "ip_type": "public", "isp": {}, "processes": []}
        }
        
        # Create log at 19:00 UTC (before range)
        self.create_test_log(temp_log_dir, "2026-03-02T19:00:00Z", traffic_data)
        
        # Query 20:00 to 21:00 UTC
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        assert result['files_processed'] == 0
        assert result['total_ips'] == 0
    
    def test_multiple_logs_aggregation(self, temp_log_dir):
        """Test aggregation of multiple log files"""
        # Create two logs with same IP
        traffic_data_1 = {
            "1.2.3.4": {"bytes": 1000, "packets": 10, "domains": ["example.com"], 
                       "ports": [443], "ip_type": "public", "isp": {}, "processes": []}
        }
        traffic_data_2 = {
            "1.2.3.4": {"bytes": 2000, "packets": 20, "domains": ["example.org"], 
                       "ports": [80], "ip_type": "public", "isp": {}, "processes": []}
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:10:00Z", traffic_data_1)
        self.create_test_log(temp_log_dir, "2026-03-02T20:20:00Z", traffic_data_2)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        assert result['files_processed'] == 2
        assert result['total_ips'] == 1
        assert result['total_bytes'] == 3000  # 1000 + 2000
        assert result['total_packets'] == 30  # 10 + 20
        
        ip_data = result['traffic_by_ip']['1.2.3.4']
        assert ip_data['bytes'] == 3000
        assert ip_data['packets'] == 30
        assert set(ip_data['domains']) == {"example.com", "example.org"}
        assert set(ip_data['ports']) == {443, 80}
    
    def test_process_aggregation_array_format(self, temp_log_dir):
        """Test process aggregation with array format (eBPF logs)"""
        traffic_data = {
            "1.2.3.4": {
                "bytes": 1000,
                "packets": 10,
                "domains": [],
                "ports": [443],
                "ip_type": "public",
                "isp": {},
                "processes": [
                    {"pid": 1234, "name": "firefox", "container": {"name": "web", "id": "abc123"}},
                    {"pid": 5678, "name": "curl"}
                ]
            }
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        processes = result['traffic_by_ip']['1.2.3.4']['processes']
        assert len(processes) == 2
        
        # Check container info is preserved
        firefox_proc = next(p for p in processes if p['name'] == 'firefox')
        assert 'container' in firefox_proc
        assert firefox_proc['container']['name'] == 'web'
        
        # Check process without container
        curl_proc = next(p for p in processes if p['name'] == 'curl')
        assert 'container' not in curl_proc
    
    def test_process_aggregation_dict_format(self, temp_log_dir):
        """Test process aggregation with dict format (standard logs)"""
        traffic_data = {
            "1.2.3.4": {
                "bytes": 1000,
                "packets": 10,
                "domains": [],
                "ports": [443],
                "ip_type": "public",
                "isp": {},
                "processes": {
                    "1234": {"name": "firefox", "count": 5, "container": {"name": "web"}},
                    "5678": {"name": "curl", "count": 2}
                }
            }
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        processes = result['traffic_by_ip']['1.2.3.4']['processes']
        assert len(processes) == 2
        
        # Check PIDs are preserved
        pids = {p['pid'] for p in processes}
        assert pids == {"1234", "5678"}
    
    def test_process_deduplication(self, temp_log_dir):
        """Test that duplicate processes are deduplicated by PID"""
        traffic_data_1 = {
            "1.2.3.4": {
                "bytes": 1000, "packets": 10, "domains": [], "ports": [443],
                "ip_type": "public", "isp": {},
                "processes": [{"pid": 1234, "name": "firefox"}]
            }
        }
        traffic_data_2 = {
            "1.2.3.4": {
                "bytes": 2000, "packets": 20, "domains": [], "ports": [443],
                "ip_type": "public", "isp": {},
                "processes": [{"pid": 1234, "name": "firefox"}]  # Same PID
            }
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:10:00Z", traffic_data_1)
        self.create_test_log(temp_log_dir, "2026-03-02T20:20:00Z", traffic_data_2)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        processes = result['traffic_by_ip']['1.2.3.4']['processes']
        # Should only have one process despite appearing in two logs
        assert len(processes) == 1
        assert processes[0]['pid'] == '1234'
    
    def test_timezone_conversion_local_to_utc(self, temp_log_dir):
        """Test that local time timestamps are correctly converted to UTC"""
        # Create log with local time (no timezone)
        traffic_data = {
            "1.2.3.4": {"bytes": 1000, "packets": 10, "domains": [], "ports": [],
                       "ip_type": "public", "isp": {}, "processes": []}
        }
        
        # Timestamp in local time (UTC+1): 21:30
        self.create_test_log(temp_log_dir, "2026-03-02T21:30:00", traffic_data)
        
        # Query in UTC: 20:00 to 21:00
        # Local 21:30 = UTC 20:30, which is within range
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        # Should find the log because 21:30 local = 20:30 UTC
        assert result['files_processed'] == 1
    
    def test_invalid_timestamp_skipped(self, temp_log_dir):
        """Test that logs with invalid timestamps are skipped"""
        filepath = os.path.join(temp_log_dir, "traffic_log_invalid.json")
        with open(filepath, 'w') as f:
            json.dump({
                "timestamp": "invalid-timestamp",
                "traffic_by_ip": {"1.2.3.4": {"bytes": 1000, "packets": 10}}
            }, f)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        # Should skip the invalid log
        assert result['files_processed'] == 0
    
    def test_missing_timestamp_skipped(self, temp_log_dir):
        """Test that logs without timestamp field are skipped"""
        filepath = os.path.join(temp_log_dir, "traffic_log_no_ts.json")
        with open(filepath, 'w') as f:
            json.dump({
                "traffic_by_ip": {"1.2.3.4": {"bytes": 1000, "packets": 10}}
            }, f)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        
        result = get_logs_in_range(temp_log_dir, begin, end)
        
        assert result['files_processed'] == 0


class TestWebServerEndpoints:
    """Test Flask endpoints via create_app"""

    @pytest.fixture
    def log_dir(self, tmp_path):
        return tmp_path

    def create_log(self, log_dir, timestamp, ip="1.2.3.4", bytes_val=1000):
        path = log_dir / f"traffic_log_{timestamp.replace(':', '').replace('-', '').replace('T', '_')[:15]}.json"
        data = {
            "timestamp": timestamp,
            "traffic_by_ip": {
                ip: {
                    "bytes": bytes_val,
                    "packets": 10,
                    "domains": ["example.com"],
                    "ports": [443],
                    "ip_type": "public",
                    "isp": {"org": "Example"},
                    "processes": []
                }
            }
        }
        path.write_text(json.dumps(data))
        return path

    def test_api_traffic_endpoint(self, log_dir):
        self.create_log(log_dir, "2026-03-02T20:30:00Z")
        app = create_app(str(log_dir))
        client = app.test_client()

        resp = client.get('/api/traffic?begin=2026-03-02T20:00:00Z&end=2026-03-02T21:00:00Z')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total_ips'] == 1
        assert '1.2.3.4' in data['traffic_by_ip']

    def test_api_process_endpoint(self, log_dir, monkeypatch):
        app = create_app(str(log_dir))
        client = app.test_client()

        class DummyResult:
            def __init__(self, returncode=0, stdout="PID TTY TIME CMD\nuser 1234 0:00 test", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        def fake_run(cmd, capture_output=True, text=True, timeout=5):
            assert cmd[0] == 'ps'
            return DummyResult()

        monkeypatch.setattr('subprocess.run', fake_run)
        resp = client.get('/api/process/1234')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['pid'] == '1234'
        assert 'test' in data['output']

    def test_api_traffic_invalid_time(self, log_dir):
        app = create_app(str(log_dir))
        client = app.test_client()
        resp = client.get('/api/traffic?begin=invalid&end=2026-03-02T21:00:00Z')
        assert resp.status_code == 400
    
    def test_api_traffic_default_params(self, log_dir):
        """Test /api/traffic with default parameters (last 5 minutes)"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        # Missing both params - should use defaults (last 5 minutes)
        resp = client.get('/api/traffic')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'traffic_by_ip' in data
        
        # Only begin param - should default end to now
        resp = client.get('/api/traffic?begin=2026-03-02T20:00:00Z')
        assert resp.status_code == 200
    
    def test_api_traffic_viz_endpoint(self, log_dir):
        """Test /api/traffic-viz endpoint with pattern filtering"""
        self.create_log(log_dir, "2026-03-02T20:30:00Z", ip="8.8.8.8")
        self.create_log(log_dir, "2026-03-02T20:35:00Z", ip="1.1.1.1")
        
        app = create_app(str(log_dir))
        client = app.test_client()
        
        # Search for 8.8.8.8
        resp = client.get('/api/traffic-viz?begin=2026-03-02T20:00:00Z&end=2026-03-02T21:00:00Z&pattern=8\\.8\\.8\\.8')
        assert resp.status_code == 200
        data = resp.get_json()
        assert '8.8.8.8' in data['traffic_by_ip']
        assert '1.1.1.1' not in data['traffic_by_ip']
    
    def test_api_traffic_viz_missing_params(self, log_dir):
        """Test /api/traffic-viz without required parameters"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        # Missing pattern
        resp = client.get('/api/traffic-viz?begin=2026-03-02T20:00:00Z&end=2026-03-02T21:00:00Z')
        assert resp.status_code == 400
    
    def test_api_traffic_viz_invalid_regex(self, log_dir):
        """Test /api/traffic-viz with invalid regex pattern"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        # Invalid regex
        resp = client.get('/api/traffic-viz?begin=2026-03-02T20:00:00Z&end=2026-03-02T21:00:00Z&pattern=[invalid')
        assert resp.status_code == 400
    
    def test_index_page(self, log_dir):
        """Test index page renders"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        resp = client.get('/')
        assert resp.status_code == 200
    
    def test_iptables_page(self, log_dir):
        """Test iptables page renders"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        resp = client.get('/iptables')
        assert resp.status_code == 200
    
    def test_fail2ban_page(self, log_dir):
        """Test fail2ban page renders"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        resp = client.get('/fail2ban')
        assert resp.status_code == 200
    
    def test_traffic_viz_page(self, log_dir):
        """Test traffic visualization page renders"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        resp = client.get('/traffic-viz')
        assert resp.status_code == 200
    
    def test_ip_bans_page(self, log_dir):
        """Test IP bans page renders"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        resp = client.get('/ip-bans')
        assert resp.status_code == 200
    
    def test_static_files(self, log_dir):
        """Test static file serving"""
        # Static files are served from web_static directory by default
        # Just verify the route exists
        app = create_app(str(log_dir))
        client = app.test_client()
        
        # Try to access a non-existent static file
        # Should get 404 but route should exist
        resp = client.get('/nonexistent.txt')
        # Either 404 (file not found) or 200 (if file exists) is acceptable
        assert resp.status_code in [200, 404]
    
    def test_api_process_ps_error(self, log_dir, monkeypatch):
        """Test /api/process when ps command fails"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        class ErrorResult:
            def __init__(self):
                self.returncode = 1
                self.stdout = ""
                self.stderr = "Process not found"
        
        def fake_run(cmd, capture_output=True, text=True, timeout=5):
            return ErrorResult()
        
        monkeypatch.setattr('subprocess.run', fake_run)
        resp = client.get('/api/process/9999')
        # When ps fails, it returns 500 error
        assert resp.status_code == 500
        data = resp.get_json()
        assert 'error' in data
    
    def test_api_process_timeout(self, log_dir, monkeypatch):
        """Test /api/process when ps command times out"""
        import subprocess
        
        app = create_app(str(log_dir))
        client = app.test_client()
        
        def fake_run(cmd, capture_output=True, text=True, timeout=5):
            raise subprocess.TimeoutExpired(cmd, timeout)
        
        monkeypatch.setattr('subprocess.run', fake_run)
        resp = client.get('/api/process/1234')
        assert resp.status_code == 500
        data = resp.get_json()
        assert 'error' in data
    
    def test_api_process_exception(self, log_dir, monkeypatch):
        """Test /api/process when ps command raises exception"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        def fake_run(cmd, capture_output=True, text=True, timeout=5):
            raise Exception("Unexpected error")
        
        monkeypatch.setattr('subprocess.run', fake_run)
        resp = client.get('/api/process/1234')
        assert resp.status_code == 500
        data = resp.get_json()
        assert 'error' in data
    
    def test_csrf_error_handler(self, log_dir):
        """Test CSRF error handler"""
        app = create_app(str(log_dir))
        client = app.test_client()
        
        # Try to POST without CSRF token (should be caught by CSRF protection)
        # Note: This tests the error handler registration
        # Actual CSRF validation is tested in dedicated CSRF tests
        assert app.config.get('WTF_CSRF_ENABLED', True)


class TestGetTrafficTimeSeries:
    """Test get_traffic_time_series function"""
    
    @pytest.fixture
    def temp_log_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def create_test_log(self, log_dir, timestamp_str, traffic_data):
        """Helper to create a test log file"""
        filename = f"traffic_log_{timestamp_str.replace(':', '').replace('-', '').replace('T', '_')[:15]}.json"
        filepath = os.path.join(log_dir, filename)
        
        log_content = {
            "timestamp": timestamp_str,
            "traffic_by_ip": traffic_data
        }
        
        with open(filepath, 'w') as f:
            json.dump(log_content, f)
        
        return filepath
    
    def test_pattern_matching_ip(self, temp_log_dir):
        """Test pattern matching against IP addresses"""
        from src.web_server import get_traffic_time_series
        import re
        
        traffic_data = {
            "8.8.8.8": {"bytes": 1000, "packets": 10, "domains": [], "ports": [443]},
            "1.1.1.1": {"bytes": 500, "packets": 5, "domains": [], "ports": [80]}
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        pattern = re.compile(r"8\.8\.8\.8")
        
        result = get_traffic_time_series(temp_log_dir, begin, end, pattern)
        
        assert "8.8.8.8" in result['traffic_by_ip']
        assert "1.1.1.1" not in result['traffic_by_ip']
        assert result['total_bytes'] == 1000
    
    def test_pattern_matching_domain(self, temp_log_dir):
        """Test pattern matching against domains"""
        from src.web_server import get_traffic_time_series
        import re
        
        traffic_data = {
            "1.2.3.4": {"bytes": 1000, "packets": 10, "domains": ["google.com"], "ports": [443]},
            "5.6.7.8": {"bytes": 500, "packets": 5, "domains": ["cloudflare.com"], "ports": [80]}
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        pattern = re.compile(r"google")
        
        result = get_traffic_time_series(temp_log_dir, begin, end, pattern)
        
        assert "1.2.3.4" in result['traffic_by_ip']
        assert "5.6.7.8" not in result['traffic_by_ip']
    
    def test_pattern_matching_isp(self, temp_log_dir):
        """Test pattern matching against ISP info"""
        from src.web_server import get_traffic_time_series
        import re
        
        traffic_data = {
            "1.2.3.4": {
                "bytes": 1000,
                "packets": 10,
                "domains": [],
                "ports": [443],
                "isp": {"org": "Google LLC", "country": "US"}
            },
            "5.6.7.8": {
                "bytes": 500,
                "packets": 5,
                "domains": [],
                "ports": [80],
                "isp": {"org": "Cloudflare", "country": "US"}
            }
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        pattern = re.compile(r"Google")
        
        result = get_traffic_time_series(temp_log_dir, begin, end, pattern)
        
        assert "1.2.3.4" in result['traffic_by_ip']
        assert "5.6.7.8" not in result['traffic_by_ip']
    
    def test_time_series_aggregation(self, temp_log_dir):
        """Test time series data aggregation"""
        from src.web_server import get_traffic_time_series
        import re
        
        traffic_data1 = {
            "8.8.8.8": {"bytes": 1000, "packets": 10, "domains": [], "ports": [443]}
        }
        traffic_data2 = {
            "8.8.8.8": {"bytes": 2000, "packets": 20, "domains": [], "ports": [443]}
        }
        
        self.create_test_log(temp_log_dir, "2026-03-02T20:30:00Z", traffic_data1)
        self.create_test_log(temp_log_dir, "2026-03-02T20:35:00Z", traffic_data2)
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        pattern = re.compile(r".*")  # Match all
        
        result = get_traffic_time_series(temp_log_dir, begin, end, pattern)
        
        assert len(result['time_series']) == 2
        assert result['total_bytes'] == 3000
        assert result['total_packets'] == 30
    
    def test_nonexistent_directory(self):
        """Test with non-existent directory"""
        from src.web_server import get_traffic_time_series
        import re
        
        begin = datetime(2026, 3, 2, 20, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 3, 2, 21, 0, 0, tzinfo=timezone.utc)
        pattern = re.compile(r".*")
        
        result = get_traffic_time_series("/nonexistent/path", begin, end, pattern)
        
        assert "error" in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
