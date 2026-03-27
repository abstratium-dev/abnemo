#!/usr/bin/env python3
"""
Tests for ISP Lookup Module
"""

import json
import os
import time
import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from urllib.error import URLError

from src.isp_lookup import ISPLookup


class TestISPLookupInit:
    """Test ISPLookup initialization"""
    
    def test_init_default(self, tmp_path):
        """Test initialization with default parameters"""
        cache_file = tmp_path / "test_cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        assert lookup.cache_file == str(cache_file)
        assert lookup.cache == {}
        assert lookup.api_key is None
        assert lookup.cache_ttl_hours == 72
        assert lookup.min_request_interval == 1.5  # Free tier
    
    def test_init_with_api_key(self, tmp_path):
        """Test initialization with API key"""
        cache_file = tmp_path / "test_cache.json"
        lookup = ISPLookup(cache_file=str(cache_file), api_key="test_key")
        
        assert lookup.api_key == "test_key"
        assert lookup.min_request_interval == 0.1  # Pro tier
    
    def test_init_with_custom_ttl(self, tmp_path):
        """Test initialization with custom TTL"""
        cache_file = tmp_path / "test_cache.json"
        lookup = ISPLookup(cache_file=str(cache_file), cache_ttl_hours=24)
        
        assert lookup.cache_ttl_hours == 24


class TestCacheLoading:
    """Test cache loading functionality"""
    
    def test_load_cache_no_file(self, tmp_path):
        """Test loading when cache file doesn't exist"""
        cache_file = tmp_path / "nonexistent.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        assert lookup.cache == {}
    
    def test_load_cache_valid(self, tmp_path):
        """Test loading valid cache file"""
        cache_file = tmp_path / "cache.json"
        cache_data = {
            "8.8.8.8": {
                "data": {
                    "isp": "Google LLC",
                    "org": "Google LLC",
                    "country": "US"
                },
                "cached_at": time.time()
            }
        }
        cache_file.write_text(json.dumps(cache_data))
        
        lookup = ISPLookup(cache_file=str(cache_file))
        
        assert "8.8.8.8" in lookup.cache
        assert lookup.cache["8.8.8.8"]["data"]["isp"] == "Google LLC"
    
    def test_load_cache_expired_entries(self, tmp_path):
        """Test that expired entries are removed"""
        cache_file = tmp_path / "cache.json"
        old_time = time.time() - (100 * 3600)  # 100 hours ago
        cache_data = {
            "8.8.8.8": {
                "data": {"isp": "Google LLC"},
                "cached_at": old_time
            },
            "1.1.1.1": {
                "data": {"isp": "Cloudflare"},
                "cached_at": time.time()
            }
        }
        cache_file.write_text(json.dumps(cache_data))
        
        lookup = ISPLookup(cache_file=str(cache_file), cache_ttl_hours=72)
        
        # Expired entry should be removed
        assert "8.8.8.8" not in lookup.cache
        # Fresh entry should remain
        assert "1.1.1.1" in lookup.cache
    
    def test_load_cache_old_format(self, tmp_path):
        """Test handling of old cache format without timestamp"""
        cache_file = tmp_path / "cache.json"
        cache_data = {
            "8.8.8.8": {
                "isp": "Google LLC",
                "org": "Google LLC"
            }
        }
        cache_file.write_text(json.dumps(cache_data))
        
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Old format entries should be expired
        assert "8.8.8.8" not in lookup.cache
    
    def test_load_cache_invalid_json(self, tmp_path):
        """Test handling of invalid JSON"""
        cache_file = tmp_path / "cache.json"
        cache_file.write_text("invalid json{")
        
        lookup = ISPLookup(cache_file=str(cache_file))
        
        assert lookup.cache == {}


class TestCacheSaving:
    """Test cache saving functionality"""
    
    def test_save_cache(self, tmp_path):
        """Test saving cache to file"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        lookup.cache["8.8.8.8"] = {
            "data": {"isp": "Google LLC"},
            "cached_at": time.time()
        }
        lookup.save_cache()
        
        assert cache_file.exists()
        with open(cache_file) as f:
            saved_data = json.load(f)
        assert "8.8.8.8" in saved_data
    
    def test_save_cache_error(self, tmp_path):
        """Test handling of save errors"""
        cache_file = tmp_path / "readonly" / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        lookup.cache["8.8.8.8"] = {"data": {"isp": "Test"}, "cached_at": time.time()}
        
        # Should not raise exception
        lookup.save_cache()


class TestLookupISP:
    """Test ISP lookup functionality"""
    
    def test_lookup_special_ips(self, tmp_path):
        """Test that special IPs are skipped"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        special_ips = ['0.0.0.0', '255.255.255.255', '::', 'ff02::1', 'ff02::2']
        for ip in special_ips:
            result = lookup.lookup_isp(ip)
            assert result is None
    
    def test_lookup_cache_hit(self, tmp_path):
        """Test lookup with cache hit"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Pre-populate cache
        lookup.cache["8.8.8.8"] = {
            "data": {
                "isp": "Google LLC",
                "org": "Google LLC",
                "country": "US"
            },
            "cached_at": time.time()
        }
        
        result = lookup.lookup_isp("8.8.8.8")
        
        assert result is not None
        assert result["isp"] == "Google LLC"
    
    def test_lookup_cache_hit_old_format(self, tmp_path):
        """Test lookup with old format cache entry"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Old format without 'data' wrapper
        lookup.cache["8.8.8.8"] = {
            "isp": "Google LLC",
            "org": "Google LLC"
        }
        
        result = lookup.lookup_isp("8.8.8.8")
        
        assert result is not None
        assert result["isp"] == "Google LLC"
    
    def test_lookup_cache_reload(self, tmp_path):
        """Test cache reload when file is modified"""
        cache_file = tmp_path / "cache.json"
        
        # Create initial cache
        initial_cache = {
            "1.1.1.1": {
                "data": {"isp": "Cloudflare"},
                "cached_at": time.time()
            }
        }
        cache_file.write_text(json.dumps(initial_cache))
        
        lookup = ISPLookup(cache_file=str(cache_file))
        assert "1.1.1.1" in lookup.cache
        
        # Modify cache file externally
        time.sleep(0.1)  # Ensure mtime changes
        updated_cache = {
            "8.8.8.8": {
                "data": {"isp": "Google LLC"},
                "cached_at": time.time()
            }
        }
        cache_file.write_text(json.dumps(updated_cache))
        
        # Lookup should trigger reload
        result = lookup.lookup_isp("8.8.8.8")
        assert "8.8.8.8" in lookup.cache
    
    @patch('urllib.request.urlopen')
    def test_lookup_api_success_free_tier(self, mock_urlopen, tmp_path):
        """Test successful API lookup with free tier"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Mock API response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "status": "success",
            "isp": "Google LLC",
            "org": "Google LLC",
            "as": "AS15169",
            "asname": "GOOGLE",
            "country": "United States",
            "countryCode": "US"
        }).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        result = lookup.lookup_isp("8.8.8.8")
        
        assert result is not None
        assert result["isp"] == "Google LLC"
        assert result["org"] == "Google LLC"
        assert result["country"] == "United States"
        assert result["country_code"] == "US"
        
        # Should be cached
        assert "8.8.8.8" in lookup.cache
    
    @patch('urllib.request.urlopen')
    def test_lookup_api_success_pro_tier(self, mock_urlopen, tmp_path):
        """Test successful API lookup with pro tier"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file), api_key="test_key")
        
        # Mock API response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "status": "success",
            "isp": "Cloudflare",
            "org": "Cloudflare, Inc.",
            "as": "AS13335",
            "asname": "CLOUDFLARENET",
            "country": "Australia",
            "countryCode": "AU"
        }).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        result = lookup.lookup_isp("1.1.1.1")
        
        assert result is not None
        assert result["isp"] == "Cloudflare"
        
        # Verify pro API URL was used
        call_args = mock_urlopen.call_args[0][0]
        assert "pro.ip-api.com" in call_args.full_url
        assert "key=test_key" in call_args.full_url
    
    @patch('urllib.request.urlopen')
    def test_lookup_api_failure(self, mock_urlopen, tmp_path):
        """Test API returning failure status"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Mock API error response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "status": "fail",
            "message": "reserved range"
        }).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        result = lookup.lookup_isp("192.168.1.1")
        
        assert result is None
        
        # Failure should be cached
        assert "192.168.1.1" in lookup.cache
        assert lookup.cache["192.168.1.1"]["data"] is None
    
    @patch('urllib.request.urlopen')
    def test_lookup_network_error(self, mock_urlopen, tmp_path):
        """Test handling of network errors"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Mock network error
        mock_urlopen.side_effect = URLError("Network unreachable")
        
        result = lookup.lookup_isp("8.8.8.8")
        
        assert result is None
        
        # Error should be cached
        assert "8.8.8.8" in lookup.cache
        assert lookup.cache["8.8.8.8"]["data"] is None
    
    @patch('urllib.request.urlopen')
    def test_lookup_unexpected_error(self, mock_urlopen, tmp_path):
        """Test handling of unexpected errors"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Mock unexpected error
        mock_urlopen.side_effect = Exception("Unexpected error")
        
        result = lookup.lookup_isp("8.8.8.8")
        
        assert result is None
        
        # Error should be cached
        assert "8.8.8.8" in lookup.cache
    
    @patch('time.sleep')
    @patch('urllib.request.urlopen')
    def test_rate_limiting(self, mock_urlopen, mock_sleep, tmp_path):
        """Test rate limiting between requests"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        # Mock successful response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "status": "success",
            "isp": "Test ISP",
            "org": "Test Org",
            "country": "US",
            "countryCode": "US"
        }).encode()
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        # First request
        lookup.lookup_isp("1.1.1.1")
        
        # Second request immediately after
        lookup.lookup_isp("8.8.8.8")
        
        # Should have slept to enforce rate limit
        assert mock_sleep.called


class TestGetISPName:
    """Test get_isp_name method"""
    
    def test_get_isp_name_success(self, tmp_path):
        """Test getting ISP name"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        lookup.cache["8.8.8.8"] = {
            "data": {
                "isp": "Google LLC",
                "org": "Google Public DNS",
                "country_code": "US"
            },
            "cached_at": time.time()
        }
        
        result = lookup.get_isp_name("8.8.8.8")
        
        assert result == "Google Public DNS (US)"
    
    def test_get_isp_name_no_info(self, tmp_path):
        """Test getting ISP name when lookup returns None"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        result = lookup.get_isp_name("0.0.0.0")
        
        assert result is None
    
    def test_get_isp_name_no_country(self, tmp_path):
        """Test getting ISP name without country code"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        lookup.cache["8.8.8.8"] = {
            "data": {
                "isp": "Google LLC",
                "org": "Google LLC"
            },
            "cached_at": time.time()
        }
        
        result = lookup.get_isp_name("8.8.8.8")
        
        assert result == "Google LLC"


class TestGetDisplayName:
    """Test get_display_name method"""
    
    def test_get_display_name_with_domain(self, tmp_path):
        """Test display name when domain is provided"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        result = lookup.get_display_name("8.8.8.8", domain="dns.google")
        
        assert result == "dns.google"
    
    def test_get_display_name_with_isp(self, tmp_path):
        """Test display name falls back to ISP"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        lookup.cache["8.8.8.8"] = {
            "data": {
                "isp": "Google LLC",
                "org": "Google LLC",
                "country_code": "US"
            },
            "cached_at": time.time()
        }
        
        result = lookup.get_display_name("8.8.8.8", domain="unknown")
        
        assert result == "Google LLC (US)"
    
    def test_get_display_name_fallback_unknown(self, tmp_path):
        """Test display name falls back to unknown"""
        cache_file = tmp_path / "cache.json"
        lookup = ISPLookup(cache_file=str(cache_file))
        
        result = lookup.get_display_name("0.0.0.0", domain="unknown")
        
        assert result == "unknown"
