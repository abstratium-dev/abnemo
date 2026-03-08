#!/usr/bin/env python3
"""
Tests for iptables model classes
"""

import pytest
from src.iptables.model import (
    IptablesConfig, Table, Chain, Rule,
    DockerEnrichedField, Policy
)


class TestDockerEnrichedField:
    """Test DockerEnrichedField class"""
    
    def test_create_without_enrichment(self):
        """Test creating field without Docker enrichment"""
        field = DockerEnrichedField(original='eth0')
        
        assert field.original == 'eth0'
        assert not field.is_docker_related
        assert field.docker_name is None
        assert field.docker_type is None
        assert str(field) == 'eth0'
    
    def test_create_with_container_enrichment(self):
        """Test creating field with container enrichment"""
        docker_info = {
            'type': 'container',
            'container_name': 'test-app',
            'network': 'bridge',
            'label': '🐳 test-app'
        }
        field = DockerEnrichedField(original='172.17.0.2', docker_info=docker_info)
        
        assert field.original == '172.17.0.2'
        assert field.is_docker_related
        assert field.docker_name == 'test-app'
        assert field.docker_type == 'container'
        assert field.label == '🐳 test-app'
    
    def test_create_with_network_enrichment(self):
        """Test creating field with network enrichment"""
        docker_info = {
            'type': 'docker_interface',
            'network': 'maxant',
            'label': '🐋 maxant'
        }
        field = DockerEnrichedField(original='br-134df6656aef', docker_info=docker_info)
        
        assert field.is_docker_related
        assert field.docker_name == 'maxant'
        assert field.docker_type == 'docker_interface'


class TestRule:
    """Test Rule class"""
    
    def test_create_basic_rule(self):
        """Test creating a basic rule"""
        rule = Rule(
            pkts=100,
            bytes=5000,
            target='ACCEPT',
            prot='tcp',
            opt='--',
            in_interface=DockerEnrichedField('eth0'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('192.168.1.100'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        assert rule.pkts == 100
        assert rule.bytes == 5000
        assert rule.target == 'ACCEPT'
        assert rule.prot == 'tcp'
        assert not rule.is_docker_related
    
    def test_docker_related_rule(self):
        """Test rule with Docker enrichment"""
        docker_info = {
            'type': 'container',
            'container_name': 'my-app',
            'label': '🐳 my-app'
        }
        
        rule = Rule(
            pkts=50,
            bytes=2500,
            target='ACCEPT',
            prot='tcp',
            opt='--',
            in_interface=DockerEnrichedField('docker0', {'type': 'docker_interface'}),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('172.17.0.2', docker_info),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        assert rule.is_docker_related
    
    def test_bytes_human_readable(self):
        """Test human-readable byte formatting"""
        rule = Rule(
            pkts=1,
            bytes=500,
            target='ACCEPT',
            prot='tcp',
            opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        assert rule.bytes_human == '500B'
        
        rule.bytes = 5000
        assert rule.bytes_human == '4.9K'
        
        rule.bytes = 5000000
        assert rule.bytes_human == '4.8M'
        
        rule.bytes = 5000000000
        assert rule.bytes_human == '4.7G'
    
    def test_flow_description(self):
        """Test flow description generation"""
        docker_info = {
            'type': 'container',
            'container_name': 'web-app',
            'label': '🐳 web-app'
        }
        
        rule = Rule(
            pkts=100,
            bytes=5000,
            target='ACCEPT',
            prot='tcp',
            opt='--',
            in_interface=DockerEnrichedField('docker0', {'type': 'docker_interface', 'label': '🐋 bridge'}),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('172.17.0.2', docker_info),
            destination=DockerEnrichedField('192.168.1.1')
        )
        
        flow = rule.get_flow_description()
        assert '🐳 web-app' in flow
        assert '🐋 bridge' in flow


class TestChain:
    """Test Chain class"""
    
    def test_create_builtin_chain(self):
        """Test creating a built-in chain"""
        chain = Chain(
            name='INPUT',
            policy=Policy.DROP,
            packet_count=1000,
            byte_count=50000
        )
        
        assert chain.name == 'INPUT'
        assert chain.policy == Policy.DROP
        assert chain.is_builtin
        assert not chain.is_docker_chain
    
    def test_create_custom_chain(self):
        """Test creating a custom chain"""
        chain = Chain(name='DOCKER')
        
        assert chain.name == 'DOCKER'
        assert chain.policy is None
        assert not chain.is_builtin
        assert chain.is_docker_chain
    
    def test_add_rules(self):
        """Test adding rules to chain"""
        chain = Chain(name='INPUT')
        
        rule1 = Rule(
            pkts=100, bytes=5000, target='ACCEPT', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        rule2 = Rule(
            pkts=50, bytes=2500, target='DROP', prot='udp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        chain.add_rule(rule1)
        chain.add_rule(rule2)
        
        assert len(chain.rules) == 2
        assert chain.get_rules_by_target('ACCEPT') == [rule1]
        assert chain.get_rules_by_target('DROP') == [rule2]
    
    def test_docker_rules_count(self):
        """Test counting Docker-related rules"""
        chain = Chain(name='DOCKER')
        
        # Add Docker-related rule
        docker_rule = Rule(
            pkts=100, bytes=5000, target='ACCEPT', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('docker0', {'type': 'docker_interface'}),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        # Add non-Docker rule
        normal_rule = Rule(
            pkts=50, bytes=2500, target='DROP', prot='udp', opt='--',
            in_interface=DockerEnrichedField('eth0'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        chain.add_rule(docker_rule)
        chain.add_rule(normal_rule)
        
        assert chain.docker_rules_count == 1
        assert len(chain.get_docker_rules()) == 1


class TestTable:
    """Test Table class"""
    
    def test_create_table(self):
        """Test creating a table"""
        table = Table(name='filter')
        
        assert table.name == 'filter'
        assert len(table.chains) == 0
    
    def test_add_chains(self):
        """Test adding chains to table"""
        table = Table(name='filter')
        
        input_chain = Chain(name='INPUT', policy=Policy.DROP)
        docker_chain = Chain(name='DOCKER')
        
        table.add_chain(input_chain)
        table.add_chain(docker_chain)
        
        assert len(table.chains) == 2
        assert table.get_chain('INPUT') == input_chain
        assert table.get_chain('DOCKER') == docker_chain
    
    def test_get_builtin_chains(self):
        """Test getting built-in chains"""
        table = Table(name='filter')
        
        table.add_chain(Chain(name='INPUT', policy=Policy.DROP))
        table.add_chain(Chain(name='OUTPUT', policy=Policy.ACCEPT))
        table.add_chain(Chain(name='DOCKER'))
        
        builtin = table.get_builtin_chains()
        assert len(builtin) == 2
        assert all(c.is_builtin for c in builtin)
    
    def test_get_docker_chains(self):
        """Test getting Docker chains"""
        table = Table(name='filter')
        
        table.add_chain(Chain(name='INPUT'))
        table.add_chain(Chain(name='DOCKER'))
        table.add_chain(Chain(name='DOCKER-USER'))
        
        docker_chains = table.get_docker_chains()
        assert len(docker_chains) == 2
        assert all('DOCKER' in c.name for c in docker_chains)


class TestIptablesConfig:
    """Test IptablesConfig class"""
    
    def test_create_config(self):
        """Test creating configuration"""
        config = IptablesConfig()
        
        assert len(config.tables) == 0
        assert config.total_rules == 0
    
    def test_add_tables(self):
        """Test adding tables"""
        config = IptablesConfig()
        
        filter_table = Table(name='filter')
        nat_table = Table(name='nat')
        
        config.add_table(filter_table)
        config.add_table(nat_table)
        
        assert len(config.tables) == 2
        assert config.get_table('filter') == filter_table
        assert config.get_table('nat') == nat_table
    
    def test_total_rules(self):
        """Test total rules count"""
        config = IptablesConfig()
        
        table = Table(name='filter')
        chain = Chain(name='INPUT')
        
        rule = Rule(
            pkts=100, bytes=5000, target='ACCEPT', prot='tcp', opt='--',
            in_interface=DockerEnrichedField('*'),
            out_interface=DockerEnrichedField('*'),
            source=DockerEnrichedField('0.0.0.0/0'),
            destination=DockerEnrichedField('0.0.0.0/0')
        )
        
        chain.add_rule(rule)
        chain.add_rule(rule)  # Add same rule twice
        table.add_chain(chain)
        config.add_table(table)
        
        assert config.total_rules == 2
