#!/usr/bin/env python3
"""
Tests for Abnemo CLI Module
"""

import pytest
import os
import json
import logging
from unittest.mock import Mock, patch, MagicMock, mock_open
from io import StringIO
import sys


class TestConfigureLogging:
    """Test logging configuration"""
    
    def test_configure_logging_debug(self):
        """Test configuring DEBUG log level"""
        from src.abnemo import configure_logging
        
        # Reset root logger first
        root_logger = logging.getLogger()
        # Clear all handlers
        root_logger.handlers.clear()
        root_logger.setLevel(logging.WARNING)
        
        configure_logging('DEBUG')
        
        # Verify root logger is configured
        assert root_logger.level == logging.DEBUG
        # Verify at least one handler was added
        assert len(root_logger.handlers) > 0
    
    def test_configure_logging_info(self):
        """Test configuring INFO log level"""
        from src.abnemo import configure_logging
        
        # Reset root logger first
        root_logger = logging.getLogger()
        # Clear all handlers
        root_logger.handlers.clear()
        root_logger.setLevel(logging.WARNING)
        
        configure_logging('INFO')
        
        assert root_logger.level == logging.INFO
        # Verify at least one handler was added
        assert len(root_logger.handlers) > 0
    
    def test_configure_logging_invalid(self):
        """Test configuring invalid log level raises ValueError"""
        from src.abnemo import configure_logging
        
        with pytest.raises(ValueError, match='Invalid log level'):
            configure_logging('INVALID')
    
    def test_configure_logging_suppresses_verbose_loggers(self):
        """Test that verbose third-party loggers are suppressed"""
        from src.abnemo import configure_logging
        
        configure_logging('DEBUG')
        
        # Check that urllib3 and werkzeug are suppressed
        urllib3_logger = logging.getLogger('urllib3')
        werkzeug_logger = logging.getLogger('werkzeug')
        
        assert urllib3_logger.level == logging.WARNING
        assert werkzeug_logger.level == logging.ERROR


class TestMonitorCommand:
    """Test monitor command"""
    
    @patch('src.abnemo.EBPFMonitor')
    def test_monitor_command_basic(self, mock_monitor_class):
        """Test basic monitor command execution"""
        from src.abnemo import monitor_command
        
        # Create mock args
        args = Mock()
        args.log_level = 'INFO'
        args.isp_api_key = 'test_key'
        args.web = False
        args.log_dir = '/tmp/logs'
        args.web_port = 8080
        args.log_retention_days = 7
        args.log_max_size_mb = 100
        args.continuous_log_interval = 60
        args.top = 10
        args.isp_cache_ttl = 24
        args.traffic_direction = 'both'
        args.extraverbosefortesting = False
        args.interface = 'eth0'
        args.duration = 60
        args.summary_interval = 10
        
        # Mock the monitor instance
        mock_monitor = Mock()
        mock_monitor_class.return_value = mock_monitor
        mock_monitor.save_statistics.return_value = '/tmp/logs/stats.json'
        
        # Execute
        monitor_command(args)
        
        # Verify monitor was created with correct args
        mock_monitor_class.assert_called_once()
        mock_monitor.start_monitoring_ebpf.assert_called_once_with(
            interface='eth0',
            duration=60,
            summary_interval=10,
            top_n=10
        )
        mock_monitor.print_summary.assert_called_once_with(top_n=10)
        mock_monitor.save_statistics.assert_called_once()
    
    @patch('src.abnemo.EBPFMonitor')
    def test_monitor_command_with_web_server(self, mock_monitor_class):
        """Test monitor command with web server enabled"""
        from src.abnemo import monitor_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.isp_api_key = None
        args.web = True
        args.log_dir = '/tmp/logs'
        args.web_port = 8080
        args.log_retention_days = 7
        args.log_max_size_mb = 100
        args.continuous_log_interval = 60
        args.top = 10
        args.isp_cache_ttl = 24
        args.traffic_direction = 'both'
        args.extraverbosefortesting = False
        args.interface = 'eth0'
        args.duration = 60
        args.summary_interval = 10
        
        mock_monitor = Mock()
        mock_monitor_class.return_value = mock_monitor
        mock_monitor.save_statistics.return_value = '/tmp/logs/stats.json'
        
        with patch('threading.Thread') as mock_thread:
            with patch('src.web_server.start_web_server'):
                with patch.dict(os.environ, {'IPAPI_KEY': 'env_key'}):
                    monitor_command(args)
                    
                    # Verify web server thread was started
                    mock_thread.assert_called_once()
                    mock_thread.return_value.start.assert_called_once()
    
    @patch('src.abnemo.EBPFMonitor')
    def test_monitor_command_permission_error(self, mock_monitor_class):
        """Test monitor command handles PermissionError"""
        from src.abnemo import monitor_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.isp_api_key = 'test_key'
        args.web = False
        args.log_dir = '/tmp/logs'
        args.web_port = 8080
        args.log_retention_days = 7
        args.log_max_size_mb = 100
        args.continuous_log_interval = 60
        args.top = 10
        args.isp_cache_ttl = 24
        args.traffic_direction = 'both'
        args.extraverbosefortesting = False
        args.interface = 'eth0'
        args.duration = 60
        args.summary_interval = 10
        
        mock_monitor = Mock()
        mock_monitor_class.return_value = mock_monitor
        mock_monitor.start_monitoring_ebpf.side_effect = PermissionError("Need root")
        
        with pytest.raises(SystemExit) as exc_info:
            monitor_command(args)
        
        assert exc_info.value.code == 1
    
    @patch('src.abnemo.EBPFMonitor')
    def test_monitor_command_general_exception(self, mock_monitor_class):
        """Test monitor command handles general exceptions"""
        from src.abnemo import monitor_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.isp_api_key = 'test_key'
        args.web = False
        args.log_dir = '/tmp/logs'
        args.web_port = 8080
        args.log_retention_days = 7
        args.log_max_size_mb = 100
        args.continuous_log_interval = 60
        args.top = 10
        args.isp_cache_ttl = 24
        args.traffic_direction = 'both'
        args.extraverbosefortesting = False
        args.interface = 'eth0'
        args.duration = 60
        args.summary_interval = 10
        
        mock_monitor = Mock()
        mock_monitor_class.return_value = mock_monitor
        mock_monitor.start_monitoring_ebpf.side_effect = Exception("Test error")
        
        with pytest.raises(SystemExit) as exc_info:
            monitor_command(args)
        
        assert exc_info.value.code == 1


class TestListLogsCommand:
    """Test list-logs command"""
    
    def test_list_logs_command_success(self, tmp_path):
        """Test listing log files successfully"""
        from src.abnemo import list_logs_command
        
        # Create test log files
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()
        
        log_file1 = log_dir / 'traffic_2024-01-01.json'
        log_data1 = {
            'timestamp': '2024-01-01T12:00:00',
            'total_ips': 10,
            'total_bytes': 1000,
            'total_packets': 50
        }
        log_file1.write_text(json.dumps(log_data1))
        
        log_file2 = log_dir / 'traffic_2024-01-02.json'
        log_data2 = {
            'timestamp': '2024-01-02T12:00:00',
            'total_ips': 20,
            'total_bytes': 2000,
            'total_packets': 100
        }
        log_file2.write_text(json.dumps(log_data2))
        
        args = Mock()
        args.log_level = 'INFO'
        args.log_dir = str(log_dir)
        
        # Capture stdout
        with patch('sys.stdout', new=StringIO()) as fake_out:
            list_logs_command(args)
            output = fake_out.getvalue()
            
            assert 'traffic_2024-01-01.json' in output
            assert 'traffic_2024-01-02.json' in output
            assert 'Total IPs: 10' in output
            assert 'Total IPs: 20' in output
    
    def test_list_logs_command_no_directory(self):
        """Test list-logs when directory doesn't exist"""
        from src.abnemo import list_logs_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.log_dir = '/nonexistent/directory'
        
        # Should not raise, just log error
        list_logs_command(args)
    
    def test_list_logs_command_no_files(self, tmp_path):
        """Test list-logs when no log files exist"""
        from src.abnemo import list_logs_command
        
        log_dir = tmp_path / 'empty_logs'
        log_dir.mkdir()
        
        args = Mock()
        args.log_level = 'INFO'
        args.log_dir = str(log_dir)
        
        # Should not raise, just log warning
        list_logs_command(args)
    
    def test_list_logs_command_invalid_json(self, tmp_path):
        """Test list-logs with invalid JSON file"""
        from src.abnemo import list_logs_command
        
        log_dir = tmp_path / 'logs'
        log_dir.mkdir()
        
        # Create invalid JSON file
        log_file = log_dir / 'invalid.json'
        log_file.write_text('not valid json')
        
        args = Mock()
        args.log_level = 'INFO'
        args.log_dir = str(log_dir)
        
        with patch('sys.stdout', new=StringIO()) as fake_out:
            list_logs_command(args)
            output = fake_out.getvalue()
            
            # Should still show the file
            assert 'invalid.json' in output


class TestIptablesTreeCommand:
    """Test iptables-tree command"""
    
    @patch('src.iptables.IptablesTreeFormatter')
    @patch('src.iptables.load_iptables_config')
    def test_iptables_tree_command_full_config(self, mock_load_config, mock_formatter_class):
        """Test iptables-tree showing full config"""
        from src.abnemo import iptables_tree_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.enrichment = None
        args.file = None
        args.table = 'filter'
        args.docker_only = False
        args.no_rules = False
        args.chain = None
        
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        
        mock_formatter = Mock()
        mock_formatter_class.return_value = mock_formatter
        mock_formatter.format_config.return_value = 'Tree output'
        
        with patch('sys.stdout', new=StringIO()) as fake_out:
            iptables_tree_command(args)
            output = fake_out.getvalue()
            
            assert 'Tree output' in output
            mock_formatter.format_config.assert_called_once_with(mock_config)
    
    @patch('src.iptables.IptablesTreeFormatter')
    @patch('src.iptables.load_iptables_config')
    def test_iptables_tree_command_specific_chain(self, mock_load_config, mock_formatter_class):
        """Test iptables-tree showing specific chain"""
        from src.abnemo import iptables_tree_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.enrichment = None
        args.file = None
        args.table = 'filter'
        args.docker_only = False
        args.no_rules = False
        args.chain = 'INPUT'
        
        mock_config = Mock()
        mock_table = Mock()
        mock_chain = Mock()
        mock_table.get_chain.return_value = mock_chain
        mock_config.get_table.return_value = mock_table
        mock_load_config.return_value = mock_config
        
        mock_formatter = Mock()
        mock_formatter_class.return_value = mock_formatter
        mock_formatter.format_chain.return_value = 'Chain output'
        
        with patch('sys.stdout', new=StringIO()) as fake_out:
            iptables_tree_command(args)
            output = fake_out.getvalue()
            
            assert 'Chain output' in output
            mock_formatter.format_chain.assert_called_once_with(mock_chain, mock_table)
    
    @patch('src.iptables.load_iptables_config')
    def test_iptables_tree_command_load_error(self, mock_load_config):
        """Test iptables-tree when loading fails"""
        from src.abnemo import iptables_tree_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.enrichment = None
        args.file = None
        args.table = 'filter'
        args.docker_only = False
        args.no_rules = False
        args.chain = None
        
        mock_load_config.side_effect = Exception("Load error")
        
        with pytest.raises(SystemExit) as exc_info:
            iptables_tree_command(args)
        
        assert exc_info.value.code == 1
    
    @patch('src.iptables.IptablesTreeFormatter')
    @patch('src.iptables.load_iptables_config')
    def test_iptables_tree_command_table_not_found(self, mock_load_config, mock_formatter_class):
        """Test iptables-tree when table not found"""
        from src.abnemo import iptables_tree_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.enrichment = None
        args.file = None
        args.table = 'nonexistent'
        args.docker_only = False
        args.no_rules = False
        args.chain = 'INPUT'
        
        mock_config = Mock()
        mock_config.get_table.return_value = None
        mock_load_config.return_value = mock_config
        
        with pytest.raises(SystemExit) as exc_info:
            iptables_tree_command(args)
        
        assert exc_info.value.code == 1
    
    @patch('src.iptables.IptablesTreeFormatter')
    @patch('src.iptables.load_iptables_config')
    def test_iptables_tree_command_chain_not_found(self, mock_load_config, mock_formatter_class):
        """Test iptables-tree when chain not found"""
        from src.abnemo import iptables_tree_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.enrichment = None
        args.file = None
        args.table = 'filter'
        args.docker_only = False
        args.no_rules = False
        args.chain = 'NONEXISTENT'
        
        mock_config = Mock()
        mock_table = Mock()
        mock_table.get_chain.return_value = None
        mock_config.get_table.return_value = mock_table
        mock_load_config.return_value = mock_config
        
        with pytest.raises(SystemExit) as exc_info:
            iptables_tree_command(args)
        
        assert exc_info.value.code == 1


class TestWebCommand:
    """Test web command"""
    
    @patch('src.web_server.start_web_server')
    def test_web_command(self, mock_start_server):
        """Test web command starts server"""
        from src.abnemo import web_command
        
        args = Mock()
        args.log_level = 'INFO'
        args.log_dir = '/tmp/logs'
        args.port = 8080
        
        web_command(args)
        
        mock_start_server.assert_called_once_with('/tmp/logs', 8080)
