#!/usr/bin/env python3
"""
Test script to demonstrate the new display format
"""

# Simulate the new output format
print("\n" + "="*80)
print("[11:33:24] Periodic Summary (last 30s)")
print("="*80)
print("IPs: 8 | Bytes: 35,729 | Packets: 112")
print("\nTop 5 destinations:")
print("-" * 80)

# Example 1: IP with domain
print("\n1. IP: 35.223.238.178 [public]")
print("   Domain: 178.238.223.35.bc.googleusercontent.com")
print("   ISP: Google LLC (US)")
print("   Ports: 443 (HTTPS)")
print("   Traffic: 33,265 bytes, 98 packets")

# Example 2: Multicast with domain
print("\n2. IP: 239.255.255.250 [multicast]")
print("   Domain: no domain name known")
print("   ISP: ISP lookup pending...")
print("   Ports: 1900 (SSDP (UPnP Discovery))")
print("   Traffic: 860 bytes, 8 packets")

# Example 3: IP with domain and ISP
print("\n3. IP: 208.95.112.1 [public]")
print("   Domain: ip-api.com")
print("   ISP: Zenlayer Inc (US)")
print("   Ports: 80 (HTTP)")
print("   Traffic: 535 bytes, 3 packets")

# Example 4: IP without domain, with ISP
print("\n4. IP: 216.86.161.201 [public]")
print("   Domain: no domain name known")
print("   ISP: Crusoe Energy Systems LLC (US)")
print("   Ports: 443 (HTTPS)")
print("   Traffic: 288 bytes, 2 packets")

# Example 5: IP with domain
print("\n5. IP: 192.34.20.166 [public]")
print("   Domain: 192.34.20.166.static.coresite.com")
print("   ISP: CoreSite LLC (US)")
print("   Ports: 443 (HTTPS), 80 (HTTP)")
print("   Traffic: 288 bytes, 2 packets")

print("\n" + "="*80 + "\n")
