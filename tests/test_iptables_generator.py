#!/usr/bin/env python3
"""Tests for IPTablesGenerator"""

import json
import os
from types import SimpleNamespace

import pytest

from iptables_generator import IPTablesGenerator


@pytest.fixture
def traffic_log(tmp_path):
    data = {
        "timestamp": "2026-03-02T20:00:00Z",
        "traffic_by_ip": {
            "10.0.0.1": {
                "bytes": 5000,
                "packets": 50,
                "domains": ["test.local"],
                "ports": [80],
                "ip_type": "private",
                "isp": {"org": "Test ISP"}
            },
            "8.8.8.8": {
                "bytes": 15000,
                "packets": 150,
                "domains": ["dns.google"],
                "ports": [53],
                "ip_type": "public",
                "isp": {"org": "Google"}
            }
        }
    }
    path = tmp_path / "traffic_log.json"
    path.write_text(json.dumps(data))
    return path


def test_add_to_blocklists():
    gen = IPTablesGenerator()
    gen.add_ip_to_blocklist("1.2.3.4")
    gen.add_domain_to_blocklist("example.com")
    assert "1.2.3.4" in gen.blocked_ips
    assert "example.com" in gen.blocked_domains


def test_load_from_traffic_log_thresholds(traffic_log):
    gen = IPTablesGenerator()
    gen.load_from_traffic_log(
        str(traffic_log),
        min_bytes=20000,  # Ensure domain rule triggers separately
        specific_domains=["dns.google"],
    )
    assert "8.8.8.8" in gen.blocked_ips
    assert "10.0.0.1" not in gen.blocked_ips
    assert "dns.google" in gen.blocked_domains


def test_generate_iptables_rules_and_restore():
    gen = IPTablesGenerator()
    gen.add_ip_to_blocklist("8.8.8.8")
    gen.add_ip_to_blocklist("1.1.1.1")

    rules = gen.generate_iptables_rules(chain="OUTPUT", action="DROP")
    assert rules[0].startswith("#!/bin/bash")
    assert any("-d 1.1.1.1" in r for r in rules)

    restore = gen.generate_iptables_restore_format(chain="OUTPUT", action="DROP")
    assert "*filter" in restore
    assert "COMMIT" in restore
    assert "-A OUTPUT -d 8.8.8.8 -j DROP" in restore


def test_save_rules_and_unblock(tmp_path):
    gen = IPTablesGenerator()
    gen.add_ip_to_blocklist("2.2.2.2")

    rules_path = tmp_path / "block_rules.sh"
    unblock_path = tmp_path / "unblock_rules.sh"

    gen.save_rules(str(rules_path))
    gen.generate_unblock_script(str(unblock_path))

    assert os.access(rules_path, os.X_OK)
    assert os.access(unblock_path, os.X_OK)
    assert "2.2.2.2" in rules_path.read_text()
    assert "-D OUTPUT" in unblock_path.read_text()


def test_print_summary(capsys):
    gen = IPTablesGenerator()
    gen.add_ip_to_blocklist("9.9.9.9")
    gen.add_domain_to_blocklist("malware.test")
    gen.print_summary()
    captured = capsys.readouterr().out
    assert "IPTABLES BLOCK SUMMARY" in captured
    assert "malware.test" in captured
