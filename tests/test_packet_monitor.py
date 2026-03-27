#!/usr/bin/env python3
"""
Tests for Packet Monitor Module
"""

import pytest
import os
import json
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict
from datetime import datetime

from src.packet_monitor import PacketMonitor


class TestPacketMonitorInit:
    """Test PacketMonitor initialization"""
    
    def test_init_default(self, tmp_path):
        """Test default initialization"""
        log_dir = tmp_path / "logs"
        
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.log_dir == str(log_dir)
        assert monitor.running is False
        assert isinstance(monitor.traffic_stats, defaultdict)
        assert isinstance(monitor.dns_cache, dict)
        assert monitor.traffic_direction == "outgoing"
        assert monitor.top_n == 20
        assert log_dir.exists()
    
    def test_init_with_isp_lookup(self, tmp_path):
        """Test initialization with ISP lookup enabled"""
        log_dir = tmp_path / "logs"
        
        monitor = PacketMonitor(log_dir=str(log_dir), enable_isp_lookup=True)
        
        assert monitor.enable_isp_lookup is True
        assert monitor.isp_lookup is not None
    
    def test_init_without_isp_lookup(self, tmp_path):
        """Test initialization with ISP lookup disabled"""
        log_dir = tmp_path / "logs"
        
        monitor = PacketMonitor(log_dir=str(log_dir), enable_isp_lookup=False)
        
        assert monitor.enable_isp_lookup is False
        assert monitor.isp_lookup is None
    
    def test_init_with_custom_params(self, tmp_path):
        """Test initialization with custom parameters"""
        log_dir = tmp_path / "logs"
        
        monitor = PacketMonitor(
            log_dir=str(log_dir),
            top_n=50,
            log_retention_days=7,
            log_max_size_mb=50,
            continuous_log_interval=30,
            traffic_direction="bidirectional"
        )
        
        assert monitor.top_n == 50
        assert monitor.log_retention_days == 7
        assert monitor.log_max_size_mb == 50
        assert monitor.continuous_log_interval == 30
        assert monitor.traffic_direction == "bidirectional"
    
    def test_init_invalid_traffic_direction(self, tmp_path):
        """Test initialization with invalid traffic direction"""
        log_dir = tmp_path / "logs"
        
        with pytest.raises(ValueError, match="Invalid traffic_direction"):
            PacketMonitor(log_dir=str(log_dir), traffic_direction="invalid")
    
    def test_init_creates_log_directory(self, tmp_path):
        """Test that log directory is created"""
        log_dir = tmp_path / "new_logs"
        
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert log_dir.exists()
        assert log_dir.is_dir()


class TestPortMappings:
    """Test port mapping functionality"""
    
    def test_load_port_mappings_success(self, tmp_path):
        """Test loading port mappings from file"""
        log_dir = tmp_path / "logs"
        port_file = tmp_path / "ports.txt"
        
        port_file.write_text("""# Port mappings
80 = HTTP
443 = HTTPS
22 = SSH
# Comment line
3306 = MySQL
""")
        
        monitor = PacketMonitor(log_dir=str(log_dir), port_mappings_file=str(port_file))
        
        assert monitor.port_mappings[80] == "HTTP"
        assert monitor.port_mappings[443] == "HTTPS"
        assert monitor.port_mappings[22] == "SSH"
        assert monitor.port_mappings[3306] == "MySQL"
    
    def test_load_port_mappings_nonexistent_file(self, tmp_path):
        """Test loading port mappings when file doesn't exist"""
        log_dir = tmp_path / "logs"
        
        monitor = PacketMonitor(log_dir=str(log_dir), port_mappings_file="/nonexistent/file.txt")
        
        assert len(monitor.port_mappings) == 0
    
    def test_load_port_mappings_invalid_lines(self, tmp_path):
        """Test loading port mappings with invalid lines"""
        log_dir = tmp_path / "logs"
        port_file = tmp_path / "ports.txt"
        
        port_file.write_text("""80 = HTTP
invalid_port = Service
443 = HTTPS
""")
        
        monitor = PacketMonitor(log_dir=str(log_dir), port_mappings_file=str(port_file))
        
        assert monitor.port_mappings[80] == "HTTP"
        assert monitor.port_mappings[443] == "HTTPS"
        assert "invalid_port" not in monitor.port_mappings
    
    def test_get_port_description(self, tmp_path):
        """Test getting port description"""
        log_dir = tmp_path / "logs"
        port_file = tmp_path / "ports.txt"
        
        port_file.write_text("80 = HTTP\n443 = HTTPS\n")
        
        monitor = PacketMonitor(log_dir=str(log_dir), port_mappings_file=str(port_file))
        
        assert monitor.get_port_description(80) == "HTTP"
        assert monitor.get_port_description(443) == "HTTPS"
        assert monitor.get_port_description(9999) == "9999"  # Unknown port


class TestIPClassification:
    """Test IP address classification"""
    
    def test_classify_multicast_ipv4(self, tmp_path):
        """Test classification of multicast IPv4 addresses"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("224.0.0.1") == "multicast"
        assert monitor.classify_ip_address("239.255.255.250") == "multicast"
    
    def test_classify_private_ipv4(self, tmp_path):
        """Test classification of private IPv4 addresses"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("192.168.1.1") == "private"
        assert monitor.classify_ip_address("10.0.0.1") == "private"
        assert monitor.classify_ip_address("172.16.0.1") == "private"
    
    def test_classify_loopback_ipv4(self, tmp_path):
        """Test classification of loopback IPv4 addresses"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("127.0.0.1") == "loopback"
        assert monitor.classify_ip_address("127.0.0.2") == "loopback"
    
    def test_classify_public_ipv4(self, tmp_path):
        """Test classification of public IPv4 addresses"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("8.8.8.8") == "public"
        assert monitor.classify_ip_address("1.1.1.1") == "public"
    
    def test_classify_reserved_ipv4(self, tmp_path):
        """Test classification of reserved IPv4 addresses"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("0.0.0.0") == "reserved"
        assert monitor.classify_ip_address("255.255.255.255") == "reserved"
    
    def test_classify_ipv6_loopback(self, tmp_path):
        """Test classification of IPv6 loopback"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("::1") == "loopback"
    
    def test_classify_ipv6_link_local(self, tmp_path):
        """Test classification of IPv6 link-local"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("fe80::1") == "link-local"
    
    def test_classify_ipv6_multicast(self, tmp_path):
        """Test classification of IPv6 multicast"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.classify_ip_address("ff02::1") == "multicast"


class TestDNSLookup:
    """Test DNS lookup functionality"""
    
    @patch('dns.reversename.from_address')
    @patch('dns.resolver.resolve')
    def test_reverse_dns_lookup_success(self, mock_resolve, mock_from_address, tmp_path):
        """Test successful reverse DNS lookup"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        # Mock DNS response
        mock_from_address.return_value = "1.1.1.1.in-addr.arpa"
        mock_answer = Mock()
        mock_answer.to_text.return_value = "one.one.one.one."
        mock_resolve.return_value = [mock_answer]
        
        result = monitor.reverse_dns_lookup("1.1.1.1")
        
        assert result == "one.one.one.one"
        # Should be cached
        assert monitor.dns_cache["1.1.1.1"] == "one.one.one.one"
    
    @patch('dns.resolver.Resolver')
    @patch('dns.reversename.from_address')
    def test_reverse_dns_lookup_failure(self, mock_from_address, mock_resolver_class, tmp_path):
        """Test reverse DNS lookup failure"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        mock_from_address.return_value = "8.8.8.8.in-addr.arpa"
        
        # Mock the resolver instance
        mock_resolver = Mock()
        mock_resolver.resolve.side_effect = Exception("DNS lookup failed")
        mock_resolver_class.return_value = mock_resolver
        
        result = monitor.reverse_dns_lookup("8.8.8.8")
        
        assert result is None
    
    def test_reverse_dns_lookup_cached(self, tmp_path):
        """Test reverse DNS lookup from cache"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        # Pre-populate cache
        monitor.dns_cache["1.1.1.1"] = "cached.domain.com"
        
        result = monitor.reverse_dns_lookup("1.1.1.1")
        
        assert result == "cached.domain.com"


class TestTrafficStats:
    """Test traffic statistics tracking"""
    
    def test_traffic_stats_default_dict(self, tmp_path):
        """Test that traffic_stats is a defaultdict with correct structure"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        # Access non-existent key should create default structure
        stats = monitor.traffic_stats["test_ip"]
        
        assert "bytes" in stats
        assert "packets" in stats
        assert "domains" in stats
        assert "ports" in stats
        assert "ip_type" in stats
        assert "isp" in stats
        assert "processes" in stats
        assert stats["bytes"] == 0
        assert stats["packets"] == 0
        assert isinstance(stats["domains"], set)
        assert isinstance(stats["ports"], set)


class TestLogSaving:
    """Test log saving functionality"""
    
    def test_save_traffic_log(self, tmp_path):
        """Test saving traffic log to file"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        # Add some traffic data
        monitor.traffic_stats["8.8.8.8"]["bytes"] = 1000
        monitor.traffic_stats["8.8.8.8"]["packets"] = 10
        monitor.traffic_stats["8.8.8.8"]["ports"].add(443)
        monitor.traffic_stats["8.8.8.8"]["ip_type"] = "public"
        
        monitor.save_traffic_log()
        
        # Check that log file was created
        log_files = list(log_dir.glob("traffic_log_*.json"))
        assert len(log_files) > 0
        
        # Verify log content
        with open(log_files[0]) as f:
            data = json.load(f)
        
        assert "timestamp" in data
        assert "traffic_by_ip" in data
        assert "8.8.8.8" in data["traffic_by_ip"]
        assert data["traffic_by_ip"]["8.8.8.8"]["bytes"] == 1000


class TestStopMonitoring:
    """Test stop monitoring functionality"""
    
    def test_stop_monitoring(self, tmp_path):
        """Test stopping packet monitoring"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        monitor.running = True
        monitor.stop_monitoring()
        
        assert monitor.running is False
        assert monitor.stop_event.is_set()


class TestTrafficDirection:
    """Test traffic direction filtering"""
    
    def test_traffic_direction_outgoing(self, tmp_path):
        """Test outgoing traffic direction mode"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir), traffic_direction="outgoing")
        
        assert monitor.traffic_direction == "outgoing"
    
    def test_traffic_direction_incoming(self, tmp_path):
        """Test incoming traffic direction mode"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir), traffic_direction="incoming")
        
        assert monitor.traffic_direction == "incoming"
    
    def test_traffic_direction_bidirectional(self, tmp_path):
        """Test bidirectional traffic direction mode"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir), traffic_direction="bidirectional")
        
        assert monitor.traffic_direction == "bidirectional"
        assert isinstance(monitor.outgoing_connections, set)
    
    def test_traffic_direction_all(self, tmp_path):
        """Test all traffic direction mode"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir), traffic_direction="all")
        
        assert monitor.traffic_direction == "all"


class TestThreadSafety:
    """Test thread safety mechanisms"""
    
    def test_lock_exists(self, tmp_path):
        """Test that threading lock exists"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert hasattr(monitor, 'lock')
        assert monitor.lock is not None
    
    def test_stop_event_exists(self, tmp_path):
        """Test that stop event exists"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert hasattr(monitor, 'stop_event')
        assert not monitor.stop_event.is_set()


class TestPacketCounters:
    """Test packet counting"""
    
    def test_packet_counters_initialized(self, tmp_path):
        """Test that packet counters are initialized"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(log_dir=str(log_dir))
        
        assert monitor.total_packets_seen == 0
        assert monitor.total_packets_filtered == 0


class TestLogRotation:
    """Test log rotation settings"""
    
    def test_log_rotation_settings(self, tmp_path):
        """Test log rotation configuration"""
        log_dir = tmp_path / "logs"
        monitor = PacketMonitor(
            log_dir=str(log_dir),
            log_retention_days=7,
            log_max_size_mb=50
        )
        
        assert monitor.log_retention_days == 7
        assert monitor.log_max_size_mb == 50
