#!/usr/bin/env python3
"""Tests for ProcessTracker"""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from src.process_tracker import ProcessTracker


def _ip_port_to_socket(ip, port):
    parts = ip.split('.')
    hex_ip = ''.join([f"{int(p):02X}" for p in reversed(parts)])
    hex_port = f"{int(port):04X}"
    return f"{hex_ip}:{hex_port}"


def _create_proc_layout(tmp_path, *, ip='192.168.1.5', port=54321, pid='1234', inode='55555'):
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    fd_dir = proc_root / pid / 'fd'
    net_dir.mkdir(parents=True)
    fd_dir.mkdir(parents=True)

    socket_id = _ip_port_to_socket(ip, port)
    tcp_path = net_dir / 'tcp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line = f"  0: {socket_id} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 00000000 0 {inode}\n"
    tcp_path.write_text(header + line)

    # fd symlink pointing to socket inode
    os.symlink(f"socket:[{inode}]", fd_dir / '0')

    cmdline = proc_root / pid / 'cmdline'
    cmdline.write_text('python\x00script.py')
    status = proc_root / pid / 'status'
    status.write_text('Name:\tpython\n')

    cgroup = proc_root / pid / 'cgroup'
    cgroup.write_text('0::/docker/abcdef1234567890.scope\n')

    return proc_root, socket_id


def test_identify_process_with_container(tmp_path, monkeypatch):
    proc_root, _ = _create_proc_layout(tmp_path)
    tracker = ProcessTracker(proc_root=str(proc_root))

    monkeypatch.setattr(ProcessTracker, '_get_container_name', lambda self, cid: 'webapp')

    info = tracker.identify_process('192.168.1.5', 54321)
    assert info is not None
    assert info['name'] == 'python'
    assert info['cmdline'].startswith('python')
    assert info['container']['name'] == 'webapp'

    # Second lookup should hit cache (no exception)
    cached = tracker.identify_process('192.168.1.5', 54321)
    assert cached == info


def test_identify_container_by_ip(monkeypatch, tmp_path):
    tracker = ProcessTracker()

    def fake_run(cmd, capture_output=True, text=True, timeout=2):
        if cmd[:3] == ['docker', 'ps', '-q']:
            return SimpleNamespace(returncode=0, stdout='abc123\n', stderr='')
        if cmd[:2] == ['docker', 'inspect']:
            payload = [{
                'Name': '/test-container',
                'Config': {'Image': 'debian:latest'},
                'NetworkSettings': {
                    'Networks': {
                        'bridge': {'IPAddress': '172.17.0.2'}
                    }
                }
            }]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr='')
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr('subprocess.run', fake_run)
    result = tracker.identify_container_by_ip('172.17.0.2')
    assert result['name'] == 'test-container'
    assert result['network'] == 'bridge'
    assert result['image'] == 'debian:latest'


def test_identify_process_invalid_ip(tmp_path):
    """Test handling of invalid IP address"""
    proc_root, _ = _create_proc_layout(tmp_path)
    tracker = ProcessTracker(proc_root=str(proc_root))
    
    # Invalid IP format
    result = tracker.identify_process('invalid.ip', 12345)
    assert result is None


def test_identify_process_no_proc_net(tmp_path):
    """Test handling when /proc/net/tcp doesn't exist"""
    proc_root = tmp_path / 'proc'
    proc_root.mkdir()
    tracker = ProcessTracker(proc_root=str(proc_root))
    
    result = tracker.identify_process('192.168.1.1', 12345)
    assert result is None


def test_identify_process_udp(tmp_path):
    """Test UDP protocol tracking"""
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    pid = '5678'
    fd_dir = proc_root / pid / 'fd'
    net_dir.mkdir(parents=True)
    fd_dir.mkdir(parents=True)
    
    socket_id = _ip_port_to_socket('10.0.0.1', 53)
    udp_path = net_dir / 'udp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line = f"  0: {socket_id} 00000000:0000 07 00000000:00000000 00:00000000 00000000 00000000 0 12345\n"
    udp_path.write_text(header + line)
    
    os.symlink('socket:[12345]', fd_dir / '3')
    cmdline = proc_root / pid / 'cmdline'
    cmdline.write_text('dnsmasq\x00-k')
    status = proc_root / pid / 'status'
    status.write_text('Name:\tdnsmasq\n')
    
    tracker = ProcessTracker(proc_root=str(proc_root))
    result = tracker.identify_process('10.0.0.1', 53, protocol='udp')
    
    assert result is not None
    assert result['name'] == 'dnsmasq'
    assert result['pid'] == pid


def test_identify_process_no_cmdline(tmp_path):
    """Test process with no cmdline (kernel thread)"""
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    pid = '2'
    fd_dir = proc_root / pid / 'fd'
    net_dir.mkdir(parents=True)
    fd_dir.mkdir(parents=True)
    
    socket_id = _ip_port_to_socket('127.0.0.1', 8080)
    tcp_path = net_dir / 'tcp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line = f"  0: {socket_id} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 00000000 0 99999\n"
    tcp_path.write_text(header + line)
    
    os.symlink('socket:[99999]', fd_dir / '0')
    cmdline = proc_root / pid / 'cmdline'
    cmdline.write_text('')  # Empty cmdline
    status = proc_root / pid / 'status'
    status.write_text('Name:\tkthreadd\n')
    
    tracker = ProcessTracker(proc_root=str(proc_root))
    result = tracker.identify_process('127.0.0.1', 8080)
    
    assert result is not None
    assert result['name'] == 'kthreadd'
    assert result['cmdline'] == f'[PID {pid}]'


def test_identify_process_no_status(tmp_path):
    """Test process without status file"""
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    pid = '9999'
    fd_dir = proc_root / pid / 'fd'
    net_dir.mkdir(parents=True)
    fd_dir.mkdir(parents=True)
    
    socket_id = _ip_port_to_socket('192.168.1.100', 443)
    tcp_path = net_dir / 'tcp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line = f"  0: {socket_id} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 00000000 0 77777\n"
    tcp_path.write_text(header + line)
    
    os.symlink('socket:[77777]', fd_dir / '0')
    cmdline = proc_root / pid / 'cmdline'
    cmdline.write_text('nginx\x00worker')
    # No status file
    
    tracker = ProcessTracker(proc_root=str(proc_root))
    result = tracker.identify_process('192.168.1.100', 443)
    
    assert result is not None
    assert result['name'] == 'nginx'
    assert 'nginx' in result['cmdline']


def test_container_detection_no_cgroup(tmp_path):
    """Test container detection when cgroup file doesn't exist"""
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    pid = '1111'
    fd_dir = proc_root / pid / 'fd'
    net_dir.mkdir(parents=True)
    fd_dir.mkdir(parents=True)
    
    socket_id = _ip_port_to_socket('10.1.1.1', 3000)
    tcp_path = net_dir / 'tcp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line = f"  0: {socket_id} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 00000000 0 11111\n"
    tcp_path.write_text(header + line)
    
    os.symlink('socket:[11111]', fd_dir / '0')
    cmdline = proc_root / pid / 'cmdline'
    cmdline.write_text('node\x00app.js')
    status = proc_root / pid / 'status'
    status.write_text('Name:\tnode\n')
    # No cgroup file
    
    tracker = ProcessTracker(proc_root=str(proc_root))
    result = tracker.identify_process('10.1.1.1', 3000)
    
    assert result is not None
    assert result['name'] == 'node'
    assert 'container' not in result


def test_container_detection_non_docker_cgroup(tmp_path):
    """Test cgroup without docker"""
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    pid = '2222'
    fd_dir = proc_root / pid / 'fd'
    net_dir.mkdir(parents=True)
    fd_dir.mkdir(parents=True)
    
    socket_id = _ip_port_to_socket('172.16.0.5', 8000)
    tcp_path = net_dir / 'tcp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    line = f"  0: {socket_id} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 00000000 0 22222\n"
    tcp_path.write_text(header + line)
    
    os.symlink('socket:[22222]', fd_dir / '0')
    cmdline = proc_root / pid / 'cmdline'
    cmdline.write_text('python3\x00server.py')
    status = proc_root / pid / 'status'
    status.write_text('Name:\tpython3\n')
    cgroup = proc_root / pid / 'cgroup'
    cgroup.write_text('0::/user.slice/user-1000.slice\n')
    
    tracker = ProcessTracker(proc_root=str(proc_root))
    result = tracker.identify_process('172.16.0.5', 8000)
    
    assert result is not None
    assert result['name'] == 'python3'
    assert 'container' not in result


def test_process_cache_hit(tmp_path):
    """Test that process cache is used"""
    proc_root, _ = _create_proc_layout(tmp_path, pid='3333', inode='33333')
    tracker = ProcessTracker(proc_root=str(proc_root))
    
    # First call - cache miss
    result1 = tracker.identify_process('192.168.1.5', 54321)
    assert result1 is not None
    
    # Modify the cmdline file to verify cache is used
    cmdline_path = proc_root / '3333' / 'cmdline'
    cmdline_path.write_text('different\x00command')
    
    # Second call - should use cache, not read file again
    result2 = tracker.identify_process('192.168.1.5', 54321)
    assert result2 == result1
    assert 'python' in result2['cmdline']  # Still has old value from cache


def test_malformed_proc_net_line(tmp_path):
    """Test handling of malformed /proc/net/tcp lines"""
    proc_root = tmp_path / 'proc'
    net_dir = proc_root / 'net'
    net_dir.mkdir(parents=True)
    
    tcp_path = net_dir / 'tcp'
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    # Malformed line with too few fields
    line = "  0: C0A80105:D431 00000000:0000\n"
    tcp_path.write_text(header + line)
    
    tracker = ProcessTracker(proc_root=str(proc_root))
    result = tracker.identify_process('192.168.1.5', 54321)
    
    assert result is None


def test_identify_container_by_ip_no_docker(monkeypatch):
    """Test container identification when docker is not available"""
    tracker = ProcessTracker()
    
    def fake_run(cmd, capture_output=True, text=True, timeout=2):
        return SimpleNamespace(returncode=1, stdout='', stderr='docker not found')
    
    monkeypatch.setattr('subprocess.run', fake_run)
    result = tracker.identify_container_by_ip('172.17.0.2')
    
    assert result is None


def test_identify_container_by_ip_no_match(monkeypatch):
    """Test container identification when IP doesn't match any container"""
    tracker = ProcessTracker()
    
    def fake_run(cmd, capture_output=True, text=True, timeout=2):
        if cmd[:3] == ['docker', 'ps', '-q']:
            return SimpleNamespace(returncode=0, stdout='abc123\n', stderr='')
        if cmd[:2] == ['docker', 'inspect']:
            payload = [{
                'Name': '/test-container',
                'Config': {'Image': 'debian:latest'},
                'NetworkSettings': {
                    'Networks': {
                        'bridge': {'IPAddress': '172.17.0.99'}  # Different IP
                    }
                }
            }]
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr='')
        raise AssertionError(f"Unexpected command: {cmd}")
    
    monkeypatch.setattr('subprocess.run', fake_run)
    result = tracker.identify_container_by_ip('172.17.0.2')
    
    assert result is None
