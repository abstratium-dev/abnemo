#!/usr/bin/env python3
"""
Tests for iptables parser
"""

import pytest
import os
from src.iptables.parser import IptablesParser, load_iptables_config
from src.docker_enrichment import DockerEnricher


# Get the path to fixture files
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures')
DOCKER_FIXTURE = os.path.join(FIXTURES_DIR, 'docker-extract.txt')
IPTABLES_FIXTURE = os.path.join(FIXTURES_DIR, 'iptables-extract.txt')


class TestIptablesParser:
    """Test IptablesParser class"""
    
    @pytest.fixture
    def docker_enricher(self):
        """Create a DockerEnricher from fixture data"""
        with open(DOCKER_FIXTURE, 'r') as f:
            enrichment_data = f.read()
        return DockerEnricher(enrichment_data=enrichment_data)
    
    @pytest.fixture
    def parser(self, docker_enricher):
        """Create a parser with Docker enrichment"""
        return IptablesParser(docker_enricher=docker_enricher)
    
    @pytest.fixture
    def iptables_output(self):
        """Load iptables output from fixture"""
        with open(IPTABLES_FIXTURE, 'r') as f:
            return f.read()
    
    def test_parser_creation(self, parser):
        """Test creating a parser"""
        assert parser is not None
        assert parser.docker_enricher is not None
    
    def test_parse_output(self, parser, iptables_output):
        """Test parsing iptables output"""
        config = parser.parse_output(iptables_output, table_name='filter')
        
        assert config is not None
        assert len(config.tables) == 1
        
        filter_table = config.get_table('filter')
        assert filter_table is not None
        assert len(filter_table.chains) > 0
    
    def test_parse_builtin_chains(self, parser, iptables_output):
        """Test parsing built-in chains"""
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        # Check INPUT chain
        input_chain = filter_table.get_chain('INPUT')
        assert input_chain is not None
        assert input_chain.is_builtin
        assert input_chain.policy is not None
        assert input_chain.packet_count > 0
        
        # Check FORWARD chain
        forward_chain = filter_table.get_chain('FORWARD')
        assert forward_chain is not None
        assert forward_chain.is_builtin
        
        # Check OUTPUT chain
        output_chain = filter_table.get_chain('OUTPUT')
        assert output_chain is not None
        assert output_chain.is_builtin
    
    def test_parse_custom_chains(self, parser, iptables_output):
        """Test parsing custom chains"""
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        # Check DOCKER chain
        docker_chain = filter_table.get_chain('DOCKER')
        assert docker_chain is not None
        assert not docker_chain.is_builtin
        assert docker_chain.is_docker_chain
        assert docker_chain.policy is None
    
    def test_parse_rules(self, parser, iptables_output):
        """Test parsing rules"""
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        input_chain = filter_table.get_chain('INPUT')
        assert len(input_chain.rules) > 0
        
        # Check first rule
        first_rule = input_chain.rules[0]
        assert first_rule.target is not None
        assert first_rule.prot is not None
        assert first_rule.pkts >= 0
        assert first_rule.bytes >= 0
    
    def test_docker_enrichment(self, parser, iptables_output):
        """Test Docker enrichment in parsed rules"""
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        # Check DOCKER chain for enriched rules
        docker_chain = filter_table.get_chain('DOCKER')
        assert docker_chain is not None
        
        # Find rules with Docker enrichment
        docker_rules = docker_chain.get_docker_rules()
        assert len(docker_rules) > 0
        
        # Check that at least one rule has container enrichment
        has_container = False
        for rule in docker_rules:
            if rule.destination.docker_type == 'container':
                has_container = True
                assert rule.destination.docker_name is not None
                break
        
        assert has_container, "Should have at least one rule with container enrichment"
    
    def test_parse_byte_counts(self, parser):
        """Test parsing byte counts with suffixes"""
        assert parser._parse_byte_count('100') == 100
        assert parser._parse_byte_count('5K') == 5000
        assert parser._parse_byte_count('2M') == 2000000
        assert parser._parse_byte_count('1G') == 1000000000
        assert parser._parse_byte_count('0') == 0
        assert parser._parse_byte_count('--') == 0
    
    def test_parse_packet_counts(self, parser):
        """Test parsing packet counts"""
        assert parser._parse_count('515K') == 515000
        assert parser._parse_count('91M') == 91000000
        assert parser._parse_count('1G') == 1000000000
    
    def test_chain_references(self, parser, iptables_output):
        """Test that rules with chain targets are parsed correctly"""
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        # INPUT chain should have rules targeting other chains
        input_chain = filter_table.get_chain('INPUT')
        
        # Find rules that target other chains
        chain_target_rules = [r for r in input_chain.rules if r.target in filter_table.chains]
        assert len(chain_target_rules) > 0
        
        # Verify the target chains exist
        for rule in chain_target_rules:
            target_chain = filter_table.get_chain(rule.target)
            assert target_chain is not None, f"Target chain {rule.target} should exist"


class TestLoadIptablesConfig:
    """Test the convenience function"""
    
    def test_load_from_files(self):
        """Test loading from files"""
        config = load_iptables_config(
            enrichment_file=DOCKER_FIXTURE,
            iptables_file=IPTABLES_FIXTURE,
            table='filter'
        )
        
        assert config is not None
        assert len(config.tables) == 1
        
        filter_table = config.get_table('filter')
        assert filter_table is not None
        assert len(filter_table.chains) > 0


class TestDockerEnrichmentIntegration:
    """Test Docker enrichment integration"""
    
    def test_container_ip_enrichment(self):
        """Test that container IPs are enriched"""
        with open(DOCKER_FIXTURE, 'r') as f:
            enrichment_data = f.read()
        
        enricher = DockerEnricher(enrichment_data=enrichment_data)
        parser = IptablesParser(docker_enricher=enricher)
        
        with open(IPTABLES_FIXTURE, 'r') as f:
            iptables_output = f.read()
        
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        docker_chain = filter_table.get_chain('DOCKER')
        
        # Find a rule with a known container IP (from fixtures)
        # 172.19.0.7 should be maxant-victoriametrics
        for rule in docker_chain.rules:
            if rule.destination.original == '172.19.0.7':
                assert rule.destination.is_docker_related
                assert rule.destination.docker_type == 'container'
                assert rule.destination.docker_name == 'maxant-victoriametrics'
                break
    
    def test_network_interface_enrichment(self):
        """Test that Docker network interfaces are enriched"""
        with open(DOCKER_FIXTURE, 'r') as f:
            enrichment_data = f.read()
        
        enricher = DockerEnricher(enrichment_data=enrichment_data)
        parser = IptablesParser(docker_enricher=enricher)
        
        with open(IPTABLES_FIXTURE, 'r') as f:
            iptables_output = f.read()
        
        config = parser.parse_output(iptables_output, table_name='filter')
        filter_table = config.get_table('filter')
        
        docker_chain = filter_table.get_chain('DOCKER')
        
        # Find a rule with a known Docker interface
        # br-134df6656aef should be the maxant network
        for rule in docker_chain.rules:
            if 'br-134df6656aef' in rule.out_interface.original:
                assert rule.out_interface.is_docker_related
                assert rule.out_interface.docker_type == 'docker_interface'
                assert rule.out_interface.docker_name == 'maxant'
                break
    
    def test_flow_description_with_docker(self):
        """Test flow descriptions include Docker information"""
        config = load_iptables_config(
            enrichment_file=DOCKER_FIXTURE,
            iptables_file=IPTABLES_FIXTURE,
            table='filter'
        )
        
        filter_table = config.get_table('filter')
        docker_chain = filter_table.get_chain('DOCKER')
        
        # Find Docker-related rules and check flow descriptions
        docker_rules = docker_chain.get_docker_rules()
        
        for rule in docker_rules[:5]:  # Check first 5
            flow = rule.get_flow_description()
            # Flow should contain some information
            assert flow != "any → any" or not rule.is_docker_related
