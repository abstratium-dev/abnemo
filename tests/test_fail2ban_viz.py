#!/usr/bin/env python3
"""Test script to demonstrate improved fail2ban visualization"""

from fail2ban_visualizer import Fail2banParser, Fail2banMermaidGenerator

# Read sample fail2ban output
with open('__NO_COMMIT__fail2ban.txt', 'r') as f:
    sample_output = f.read()

# Parse the output
parser = Fail2banParser()
data = parser.parse_output(sample_output)

print("Parsed Data:")
print("=" * 80)
print(f"Global settings: {len(data.get('global_settings', {}))} items")
print(f"Jails: {len(data.get('jails', {}))} jails")
print()

for jail_name, jail_data in data.get('jails', {}).items():
    print(f"Jail: {jail_name}")
    print(f"  Backend: {jail_data.get('backend', 'N/A')}")
    print(f"  Settings: {len(jail_data.get('settings', {}))} items")
    settings = jail_data.get('settings', {})
    for key in ['maxretry', 'findtime', 'bantime', 'logpath', 'port', 'filter']:
        if key in settings:
            print(f"    {key}: {settings[key]}")
    print(f"  Failregex patterns: {len(jail_data.get('failregex', []))}")
    print(f"  Actions: {list(jail_data.get('actions', {}).keys())}")
    print(f"  Started: {jail_data.get('started', False)}")
    print()

# Generate Mermaid diagram
generator = Fail2banMermaidGenerator(data)
mermaid_code = generator.generate(simplified=True)

print("Generated Mermaid Diagram (first 100 lines):")
print("=" * 80)
lines = mermaid_code.split('\n')
for line in lines[:100]:
    print(line)
print("=" * 80)
print(f"\nTotal lines: {len(lines)}")
print("\nThe diagram now shows detailed information for each jail including:")
print("- Backend (systemd, polling, etc.)")
print("- Log path being monitored")
print("- Port being protected")
print("- Filter being used")
print("- Max retries, findtime, and bantime")
print("- Number of fail patterns")
print("- Actions configured")
print("- Whitelisted IPs")
print("- All in smaller, more readable font sizes (11px for jails)")
