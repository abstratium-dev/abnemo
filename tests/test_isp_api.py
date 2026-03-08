#!/usr/bin/env python3
"""
Test script for ISP lookup API
"""

from src.isp_lookup import ISPLookup

# Test with free tier
print("Testing Free Tier API:")
print("=" * 60)
isp_free = ISPLookup()
result = isp_free.lookup_isp('8.8.8.8')
print(f"IP: 8.8.8.8")
print(f"Result: {result}")
print()

# Test with pro tier (will fail without valid key, but shows the format)
print("Testing Pro Tier API (requires valid key):")
print("=" * 60)
print("To test with pro API, run:")
print("  export IPAPI_KEY=your_key_here")
print("  python3 test_isp_api.py")
print()
print("Or with command line:")
print("  ./abnemo.sh monitor --isp-api-key your_key_here")
