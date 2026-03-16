#!/usr/bin/env python3
"""
ISP Lookup Module - Retrieves ISP/organization information for IP addresses
Uses ip-api.com free API with caching
"""

import json
import os
import time
import urllib.request
import urllib.error
import logging

logger = logging.getLogger(__name__)


class ISPLookup:
    def __init__(self, cache_file="isp_cache.json", api_key=None, cache_ttl_hours=72):
        self.cache_file = cache_file
        self.cache = {}
        self.api_key = api_key
        self.cache_ttl_hours = cache_ttl_hours
        self.cache_mtime = 0  # Track cache file modification time
        self.load_cache()
        self.last_request_time = 0
        # Rate limit depends on tier: free=45/min, pro=unlimited
        self.min_request_interval = 0.1 if api_key else 1.5
        
        logger.debug(f"ISPLookup initialized: cache_file={cache_file}, api_key={'set' if api_key else 'not set'}, cache_ttl={cache_ttl_hours}h")
        logger.debug(f"Loaded {len(self.cache)} entries from cache")
    
    def load_cache(self):
        """Load ISP cache from file and clean expired entries"""
        if os.path.exists(self.cache_file):
            try:
                # Track file modification time
                self.cache_mtime = os.path.getmtime(self.cache_file)
                
                with open(self.cache_file, 'r') as f:
                    raw_cache = json.load(f)
                
                # Clean expired entries
                current_time = time.time()
                self.cache = {}
                expired_count = 0
                
                for ip, entry in raw_cache.items():
                    # Check if entry has timestamp and is not expired
                    if isinstance(entry, dict) and 'cached_at' in entry:
                        age_hours = (current_time - entry['cached_at']) / 3600
                        if age_hours < self.cache_ttl_hours:
                            self.cache[ip] = entry
                        else:
                            expired_count += 1
                            logger.debug(f"Expired cache entry for {ip} (age: {age_hours:.1f}h)")
                    else:
                        # Old format without timestamp - expire it
                        expired_count += 1
                        logger.debug(f"Removing old-format cache entry for {ip}")
                
                if expired_count > 0:
                    logger.info(f"Cleaned {expired_count} expired cache entries")
                    self.save_cache()  # Save cleaned cache
                    
            except Exception as e:
                logger.warning(f"Could not load ISP cache: {e}")
                self.cache = {}
    
    def save_cache(self):
        """Save ISP cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            # Update our mtime tracker
            self.cache_mtime = os.path.getmtime(self.cache_file)
            logger.debug(f"Saved cache to {self.cache_file} ({len(self.cache)} entries)")
        except Exception as e:
            logger.warning(f"Could not save ISP cache: {e}")
            logger.debug("ISP cache save error details:", exc_info=True)
    
    def lookup_isp(self, ip_address):
        """
        Lookup ISP information for an IP address
        Returns dict with 'isp', 'org', 'as' (AS number), 'country', etc.
        """
        # Skip special/reserved IPs that will never have ISP info
        if ip_address in ('0.0.0.0', '255.255.255.255', '::', 'ff02::1', 'ff02::2'):
            logger.debug(f"Skipping special IP: {ip_address}")
            return None
        
        # Check if cache file was modified by another instance and reload if needed
        if os.path.exists(self.cache_file):
            current_mtime = os.path.getmtime(self.cache_file)
            if current_mtime > self.cache_mtime:
                logger.debug(f"Cache file was updated by another instance, reloading...")
                self.load_cache()
        
        # Check cache first
        if ip_address in self.cache:
            logger.debug(f"Cache HIT for {ip_address}")
            # Return the data part (without cached_at timestamp)
            cached_entry = self.cache[ip_address]
            if isinstance(cached_entry, dict) and 'data' in cached_entry:
                return cached_entry['data']
            else:
                # Old format - return as-is but will be updated on next lookup
                return cached_entry
        
        logger.debug(f"Cache MISS for {ip_address} - making API request")
        logger.debug(f"Current cache has {len(self.cache)} entries")
        
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        
        try:
            # Use ip-api.com API (pro if key provided, otherwise free)
            # Fields: 66842623 includes status, message, country, countryCode, isp, org, as, asname
            if self.api_key:
                url = f"https://pro.ip-api.com/json/{ip_address}?fields=66842623&key={self.api_key}"
            else:
                url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,isp,org,as,asname"
            
            # Create request with headers
            req = urllib.request.Request(url)
            req.add_header('Origin', 'https://members.ip-api.com')
            req.add_header('Referer', 'https://members.ip-api.com/')
            req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
            
            self.last_request_time = time.time()
            
            if data.get('status') == 'success':
                result = {
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', ''),
                    'asname': data.get('asname', ''),
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', '')
                }
                
                # Cache the result with timestamp
                cache_entry = {
                    'data': result,
                    'cached_at': time.time()
                }
                self.cache[ip_address] = cache_entry
                self.save_cache()
                
                logger.debug(f"Cached SUCCESS for {ip_address}: {result.get('org', 'Unknown')}")
                
                return result
            else:
                # API returned an error - cache the failure to avoid repeated lookups
                error_msg = data.get('message', 'Unknown error')
                logger.debug(f"API error for {ip_address}: {error_msg}")
                
                # Cache the failure (with None as data)
                cache_entry = {
                    'data': None,
                    'cached_at': time.time(),
                    'error': error_msg
                }
                self.cache[ip_address] = cache_entry
                self.save_cache()
                
                logger.debug(f"Cached FAILURE for {ip_address} to avoid retries")
                
                return None
                
        except urllib.error.URLError as e:
            logger.debug(f"Network error for {ip_address}: {e}")
            # Cache network failures too (might be temporary, but avoid hammering)
            cache_entry = {
                'data': None,
                'cached_at': time.time(),
                'error': str(e)
            }
            self.cache[ip_address] = cache_entry
            self.save_cache()
            return None
        except Exception as e:
            logger.debug(f"Unexpected error for {ip_address}: {e}")
            # Cache unexpected errors too
            cache_entry = {
                'data': None,
                'cached_at': time.time(),
                'error': str(e)
            }
            self.cache[ip_address] = cache_entry
            self.save_cache()
            return None
    
    def get_isp_name(self, ip_address):
        """Get a simple ISP name string for an IP address"""
        info = self.lookup_isp(ip_address)
        if not info:
            return None
        
        # Prefer org over isp as it's usually more specific
        isp_name = info.get('org') or info.get('isp') or 'Unknown'
        
        # Add country code if available
        if info.get('country_code'):
            isp_name = f"{isp_name} ({info['country_code']})"
        
        return isp_name
    
    def get_display_name(self, ip_address, domain=None):
        """
        Get the best display name for an IP address
        Priority: domain name > ISP name > IP address
        """
        if domain and domain != "unknown":
            return domain
        
        isp = self.get_isp_name(ip_address)
        if isp:
            return isp
        
        return "unknown"
