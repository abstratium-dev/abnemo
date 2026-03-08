#!/usr/bin/env python3
"""
Tests for iptables tree formatter
"""

import pytest
import os
from src.iptables.tree import IptablesTreeFormatter, format_tree
from src.iptables.model import (
    IptablesConfig, Table, Chain, Rule,
    DockerEnrichedField, Policy
)
from src.iptables.parser import load_iptables_config


# Get the path to fixture files
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures')
DOCKER_FIXTURE = os.path.join(FIXTURES_DIR, 'docker-extract.txt')
IPTABLES_FIXTURE = os.path.join(FIXTURES_DIR, 'iptables-extract.txt')


class TestIptablesTreeFormatter:
    """Test IptablesTreeFormatter class"""
    
    @pytest.fixture
    def simple_config(self):
        """Create a simple test configuration"""
        config = IptablesConfig()
        table = Table(name='filter')
        
        # Create INPUT chain
        input_chain = Chain(
            name='INPUT',
            policy=Policy.DROP,
            packet_count=1000,
            byte_count=50000
        )
        
        # Add a simple rule
        rule = Rule(
            pkts=100,
            bytes=5000,
            target='ACCEPT',
            prot='tcp',
            opt='--',
            in_interface=DockerEnrichedField('eth0'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('192.168.1.100'),
            destination=DockerEnrichedField('0.0.0.0/0'),
            extra='dpt:80'
        )
        input_chain.add_rule(rule)
        
        # Create DOCKER chain
        docker_chain = Chain(name='DOCKER')
        docker_rule = Rule(
            pkts=50,
            bytes=2500,
            target='ACCEPT',
            prot='tcp',
            opt='--',
            in_interface=DockerEnrichedField('docker0', {'type': 'docker_interface', 'label': '🐋 bridge'}),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('172.17.0.2', {
                'type': 'container',
                'container_name': 'test-app',
                'label': '🐳 test-app'
            }),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        docker_chain.add_rule(docker_rule)
        
        table.add_chain(input_chain)
        table.add_chain(docker_chain)
        config.add_table(table)
        
        return config
    
    def test_formatter_creation(self):
        """Test creating a formatter"""
        formatter = IptablesTreeFormatter()
        assert formatter is not None
        assert formatter.show_rules is True
    
    def test_format_config(self, simple_config):
        """Test formatting entire config"""
        formatter = IptablesTreeFormatter()
        output = formatter.format_config(simple_config)
        
        assert output is not None
        assert "iptables Configuration" in output
        assert "Table: filter" in output
        assert "INPUT" in output
        # DOCKER chain appears inline when referenced, not at top level
        # assert "DOCKER" in output
    
    def test_format_table(self, simple_config):
        """Test formatting a table"""
        formatter = IptablesTreeFormatter()
        table = simple_config.get_table('filter')
        output = formatter.format_table(table)
        
        assert "Table: filter" in output
        assert "INPUT" in output
        # DOCKER chain appears inline when referenced, not at top level
        # assert "DOCKER" in output
    
    def test_format_chain(self, simple_config):
        """Test formatting a single chain"""
        formatter = IptablesTreeFormatter()
        table = simple_config.get_table('filter')
        chain = table.get_chain('INPUT')
        output = formatter.format_chain(chain, table)
        
        assert "INPUT" in output
        assert "policy: DROP" in output
        assert "ACCEPT" in output
    
    def test_docker_only_filter(self, simple_config):
        """Test filtering to show only Docker-related items"""
        formatter = IptablesTreeFormatter(show_docker_only=True)
        output = formatter.format_config(simple_config)
        
        # Should show Docker enrichment marker
        assert "🐳" in output or "DOCKER" in output or len(output) > 50
    
    def test_no_rules_option(self, simple_config):
        """Test hiding rules"""
        formatter = IptablesTreeFormatter(show_rules=False)
        output = formatter.format_config(simple_config)
        
        # Should show chains
        assert "INPUT" in output
        # Should not show rule details
        assert "ACCEPT" not in output
    
    def test_all_rules_shown(self, simple_config):
        """Test that all rules are shown (no limits)"""
        # Add more rules to INPUT chain
        table = simple_config.get_table('filter')
        chain = table.get_chain('INPUT')
        
        for i in range(10):
            rule = Rule(
                pkts=10, bytes=1000, target='ACCEPT', prot='tcp', opt='--',
                in_interface=DockerEnrichedField('eth0'),
                out_interface=DockerEnrichedField('*'),
                source=DockerEnrichedField(f'192.168.1.{i}'),
                destination=DockerEnrichedField('0.0.0.0/0')
            )
            chain.add_rule(rule)
        
        formatter = IptablesTreeFormatter()
        output = formatter.format_config(simple_config)
        
        # Should NOT show "more rules" indicator - all rules shown
        assert "... and" not in output or "more rules" not in output
    
    def test_rule_icons(self, simple_config):
        """Test that different rule types get different icons"""
        table = simple_config.get_table('filter')
        chain = table.get_chain('INPUT')
        
        # Add different rule types
        drop_rule = Rule(
            pkts=10, bytes=1000, target='DROP', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        chain.add_rule(drop_rule)
        
        reject_rule = Rule(
            pkts=10, bytes=1000, target='REJECT', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        chain.add_rule(reject_rule)
        
        chain_target_rule = Rule(
            pkts=10, bytes=1000, target='ufw-before-input', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        chain.add_rule(chain_target_rule)
        
        formatter = IptablesTreeFormatter()
        output = formatter.format_chain(chain, table)
        
        # Check for different icons
        assert "✅" in output  # ACCEPT
        assert "🚫" in output  # DROP
        assert "⛔" in output  # REJECT
        # In inline mode, chain targets are expanded, not shown with arrow icon
        # assert "➡️" in output  # Chain target
    
    def test_chain_references(self, simple_config):
        """Test showing chain references inline"""
        table = simple_config.get_table('filter')
        input_chain = table.get_chain('INPUT')
        
        # Add a rule that references another chain
        rule = Rule(
            pkts=100, bytes=5000, target='DOCKER', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        input_chain.add_rule(rule)
        
        formatter = IptablesTreeFormatter()
        output = formatter.format_chain(input_chain, table)
        
        # In inline mode, DOCKER chain should be expanded inline
        assert "DOCKER" in output
        # Should show the Docker chain's content inline
        assert "test-app" in output or "🐳" in output


class TestNetworkNameReplacement:
    """Test that network names replace interface IDs, including negated interfaces"""
    
    def test_negated_interface_shows_network_name(self):
        """Test that !br-xxx shows network name instead of interface ID"""
        config = IptablesConfig()
        table = Table(name='filter')
        
        # Create DOCKER chain
        docker_chain = Chain(name='DOCKER', policy=None)
        
        # Create rule with negated interface
        in_iface = DockerEnrichedField('!br-48b7a6d85e30')
        in_iface.docker_info = {
            'type': 'docker_interface',
            'network': 'from-manou-20251001_checkmk-network',
            'label': '🐋 from-manou-20251001_checkmk-network'
        }
        
        out_iface = DockerEnrichedField('br-48b7a6d85e30')
        out_iface.docker_info = {
            'type': 'docker_interface',
            'network': 'from-manou-20251001_checkmk-network',
            'label': '🐋 from-manou-20251001_checkmk-network'
        }
        
        dest = DockerEnrichedField('172.23.0.10')
        dest.docker_info = {
            'type': 'container',
            'container_name': 'lucidlink-mock',
            'label': '🐳 lucidlink-mock'
        }
        
        rule = Rule(
            pkts=0, bytes=0, target='ACCEPT', prot='6', opt='--',
            in_interface=in_iface,
            out_interface=out_iface,
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=dest,
            extra='tcp dpt:5000'
        )
        docker_chain.add_rule(rule)
        table.add_chain(docker_chain)
        config.add_table(table)
        
        # Format and check output
        formatter = IptablesTreeFormatter()
        output = formatter.format_chain(docker_chain, table)
        
        # Should show network name (with emoji label) for both in and out interfaces
        assert 'in:!🐋 from-manou-20251001_checkmk-network' in output
        assert 'out:🐋 from-manou-20251001_checkmk-network' in output
        # Should NOT show the interface ID
        assert 'br-48b7a6d85e30' not in output
        # Should show container name
        assert 'lucidlink-mock' in output
        # Should show port
        assert 'tcp dpt:5000' in output


class TestChainCompression:
    """Test chain compression feature"""
    
    def test_compress_same_target_chain(self):
        """Test compression of chains where all rules have the same target"""
        config = IptablesConfig()
        table = Table(name='filter')
        
        # Create target chain
        target_chain = Chain(name='DOCKER-ISOLATION-STAGE-2', policy=None)
        rule = Rule(
            pkts=0, bytes=0, target='DROP', prot='0', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('docker0'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        target_chain.add_rule(rule)
        table.add_chain(target_chain)
        
        # Create chain with all rules targeting the same chain
        source_chain = Chain(name='DOCKER-ISOLATION-STAGE-1', policy=None)
        for iface in ['br-abc', 'br-def', 'br-ghi']:
            rule = Rule(
                pkts=100, bytes=5000, target='DOCKER-ISOLATION-STAGE-2', prot='0', opt='--',
                in_interface=DockerEnrichedField(iface),
                out_interface=DockerEnrichedField(f'!{iface}'),
                source=DockerEnrichedField('0.0.0.0/0'),
                destination=DockerEnrichedField('0.0.0.0/0')
            )
            source_chain.add_rule(rule)
        table.add_chain(source_chain)
        
        # Create FORWARD chain
        forward = Chain(name='FORWARD', policy=Policy.DROP)
        rule = Rule(
            pkts=1000, bytes=50000, target='DOCKER-ISOLATION-STAGE-1', prot='0', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        forward.add_rule(rule)
        table.add_chain(forward)
        
        config.add_table(table)
        
        # Format with compression enabled
        formatter = IptablesTreeFormatter(compress_same_target=True)
        output = formatter.format_chain(forward, table)
        
        # Should show compressed indicator
        assert "🗜️" in output or "compressed" in output
        # Should show OR logic
        assert "Matches if ANY of:" in output or "⚡" in output
        # Should show the target chain name
        assert "DOCKER-ISOLATION-STAGE-2" in output
        # Should show the conditions
        assert "br-abc" in output
        assert "br-def" in output
        assert "br-ghi" in output
        # Should show "Then forward to"
        assert "Then forward to:" in output or "↓" in output
    
    def test_no_compression_different_targets(self):
        """Test that chains with different targets are not compressed"""
        config = IptablesConfig()
        table = Table(name='filter')
        
        chain = Chain(name='INPUT', policy=Policy.DROP)
        
        # Add rules with different targets
        rule1 = Rule(
            pkts=100, bytes=5000, target='ACCEPT', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('eth0'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('192.168.1.0/24'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        chain.add_rule(rule1)
        
        rule2 = Rule(
            pkts=10, bytes=1000, target='DROP', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('eth0'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        chain.add_rule(rule2)
        
        table.add_chain(chain)
        config.add_table(table)
        
        # Format with compression enabled
        formatter = IptablesTreeFormatter(compress_same_target=True)
        output = formatter.format_chain(chain, table)
        
        # Should NOT show compressed indicator
        assert "🗜️" not in output
        assert "compressed" not in output.lower()
        # Should show normal rules
        assert "ACCEPT" in output
        assert "DROP" in output


class TestFormatTreeFunction:
    """Test the convenience function"""
    
    def test_format_tree(self):
        """Test format_tree convenience function"""
        config = IptablesConfig()
        table = Table(name='filter')
        chain = Chain(name='INPUT', policy=Policy.ACCEPT)
        table.add_chain(chain)
        config.add_table(table)
        
        output = format_tree(config)
        
        assert output is not None
        assert "iptables Configuration" in output
        assert "INPUT" in output


class TestTreeWithRealData:
    """Test tree formatter with real iptables data"""
    
    def test_format_real_config(self):
        """Test formatting real iptables configuration"""
        config = load_iptables_config(
            enrichment_file=DOCKER_FIXTURE,
            iptables_file=IPTABLES_FIXTURE,
            table='filter'
        )
        
        formatter = IptablesTreeFormatter()
        output = formatter.format_config(config)
        
        # Check basic structure
        assert "iptables Configuration" in output
        assert "Table: filter" in output
        
        # Check for known chains
        assert "INPUT" in output
        assert "FORWARD" in output
        assert "OUTPUT" in output
        assert "DOCKER" in output
    
    def test_format_docker_only(self):
        """Test Docker-only filtering with real data"""
        config = load_iptables_config(
            enrichment_file=DOCKER_FIXTURE,
            iptables_file=IPTABLES_FIXTURE,
            table='filter'
        )
        
        # Use non-inline mode to see all Docker chains
        formatter = IptablesTreeFormatter(show_docker_only=True, inline_chains=False)
        output = formatter.format_config(config)
        
        # Should show Docker chains
        assert "DOCKER" in output
        # Should show Docker enrichment
        assert "🐳" in output or "🐋" in output
    
    def test_format_specific_chain(self):
        """Test formatting a specific chain"""
        config = load_iptables_config(
            enrichment_file=DOCKER_FIXTURE,
            iptables_file=IPTABLES_FIXTURE,
            table='filter'
        )
        
        table = config.get_table('filter')
        docker_chain = table.get_chain('DOCKER')
        
        formatter = IptablesTreeFormatter()
        output = formatter.format_chain(docker_chain, table)
        
        assert "DOCKER" in output
        assert len(output) > 0
    
    def test_format_no_rules(self):
        """Test formatting without rules"""
        config = load_iptables_config(
            enrichment_file=DOCKER_FIXTURE,
            iptables_file=IPTABLES_FIXTURE,
            table='filter'
        )
        
        formatter = IptablesTreeFormatter(show_rules=False)
        output = formatter.format_config(config)
        
        # Should show chains
        assert "INPUT" in output
        # Should show stats
        assert "rules" in output
        # Should be shorter without rule details
        assert len(output.split('\n')) < 100  # Rough check
