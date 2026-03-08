#!/usr/bin/env python3
"""Tests for ProcessTracker"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

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
