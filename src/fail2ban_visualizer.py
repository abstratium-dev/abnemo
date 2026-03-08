#!/usr/bin/env python3
"""
fail2ban Visualizer - Parse fail2ban configuration and generate Mermaid diagrams
"""

import subprocess
import re
import ast
from typing import Dict, List, Optional


class Fail2banParser:
    """Parse fail2ban --dp output into structured data"""
    
    def __init__(self):
        self.global_settings = {}
        self.jails = {}
        
    def parse_output(self, output: str) -> Dict:
        """Parse the full fail2ban --dp output"""
        lines = output.strip().split('\n')
        
        current_jail = None
        
        for line in lines:
            line = line.rstrip()
            if not line or line.startswith('#'):
                continue
            
            # Parse the Python list/array format
            try:
                parsed = ast.literal_eval(line)
            except (ValueError, SyntaxError):
                continue
            
            if not isinstance(parsed, list) or len(parsed) < 2:
                continue
            
            command = parsed[0]
            
            if command == 'set' and len(parsed) >= 3:
                # Global setting or jail setting
                if len(parsed) == 3:
                    # Global setting: ['set', 'key', 'value']
                    self.global_settings[parsed[1]] = parsed[2]
                elif len(parsed) >= 4:
                    # Jail setting: ['set', 'jail_name', 'key', 'value']
                    jail_name = parsed[1]
                    key = parsed[2]
                    value = parsed[3] if len(parsed) == 4 else parsed[3:]
                    
                    if jail_name not in self.jails:
                        self.jails[jail_name] = {
                            'name': jail_name,
                            'settings': {},
                            'failregex': [],
                            'actions': {},
                            'ignoreips': []
                        }
                    
                    self.jails[jail_name]['settings'][key] = value
            
            elif command == 'add' and len(parsed) >= 3:
                # Add jail: ['add', 'jail_name', 'backend']
                jail_name = parsed[1]
                backend = parsed[2]
                
                if jail_name not in self.jails:
                    self.jails[jail_name] = {
                        'name': jail_name,
                        'settings': {},
                        'failregex': [],
                        'actions': {},
                        'ignoreips': []
                    }
                
                self.jails[jail_name]['backend'] = backend
            
            elif command == 'multi-set' and len(parsed) >= 4:
                # Multi-set for actions or failregex
                jail_name = parsed[1]
                subcommand = parsed[2]
                
                if jail_name not in self.jails:
                    continue
                
                if subcommand == 'addfailregex' and len(parsed) >= 4:
                    # Add fail regex patterns
                    patterns = parsed[3] if isinstance(parsed[3], list) else [parsed[3]]
                    self.jails[jail_name]['failregex'].extend(patterns)
                
                elif subcommand == 'action' and len(parsed) >= 5:
                    # Action configuration: ['multi-set', 'jail', 'action', 'action_name', [...]]
                    action_name = parsed[3]
                    action_config = parsed[4] if len(parsed) >= 5 else []
                    
                    if action_name not in self.jails[jail_name]['actions']:
                        self.jails[jail_name]['actions'][action_name] = {}
                    
                    # Parse action config
                    if isinstance(action_config, list):
                        for item in action_config:
                            if isinstance(item, list) and len(item) >= 2:
                                key = item[0]
                                value = item[1] if len(item) == 2 else item[1:]
                                self.jails[jail_name]['actions'][action_name][key] = value
            
            elif command == 'start' and len(parsed) >= 2:
                # Mark jail as started
                jail_name = parsed[1]
                if jail_name in self.jails:
                    self.jails[jail_name]['started'] = True
        
        # Process addignoreip settings
        for jail_name, jail_data in self.jails.items():
            if 'addignoreip' in jail_data['settings']:
                ignore_val = jail_data['settings']['addignoreip']
                if isinstance(ignore_val, list):
                    jail_data['ignoreips'] = ignore_val
                else:
                    jail_data['ignoreips'] = [ignore_val]
        
        return {
            'global_settings': self.global_settings,
            'jails': self.jails
        }


class Fail2banMermaidGenerator:
    """Generate Mermaid flowchart from fail2ban data"""
    
    def __init__(self, data: Dict):
        self.data = data
        self.node_counter = 0
        self.node_map = {}
        
    def generate(self, simplified: bool = True) -> str:
        """Generate complete Mermaid diagram
        
        Args:
            simplified: If True, use simplified view with summary
        """
        lines = ['flowchart TD']
        lines.append('    %% fail2ban Configuration Visualization')
        lines.append('')
        
        if simplified:
            lines.extend(self._generate_simplified_view())
        else:
            lines.extend(self._generate_detailed_view())
        
        # Add styling
        lines.extend(self._generate_styles())
        
        return '\n'.join(lines)
    
    def _generate_simplified_view(self) -> List[str]:
        """Generate a simplified, beginner-friendly view"""
        lines = []
        
        # Create a start node
        lines.append('    START(["🛡️ fail2ban Protection"]):::startNode')
        lines.append('')
        
        jails = self.data.get('jails', {})
        
        # Show active jails
        active_jails = {name: jail for name, jail in jails.items() if jail.get('started', False)}
        
        if not active_jails:
            no_jails_node = self._get_node_id('no_jails')
            lines.append(f'    {no_jails_node}["⚠️ No Active Jails"]:::warningNode')
            lines.append(f'    START --> {no_jails_node}')
            return lines
        
        # Summary node
        summary_node = self._get_node_id('summary')
        lines.append(f'    {summary_node}["📊 {len(active_jails)} Active Jails<br/>Monitoring for attacks"]:::summaryNode')
        lines.append(f'    START --> {summary_node}')
        lines.append('')
        
        prev_node = summary_node
        
        # Show each jail
        for jail_name, jail_data in sorted(active_jails.items()):
            jail_node = self._get_node_id(f'jail_{jail_name}')
            
            # Get key settings
            settings = jail_data.get('settings', {})
            maxretry = settings.get('maxretry', '?')
            findtime = settings.get('findtime', '?')
            bantime = settings.get('bantime', '?')
            
            # Count fail patterns
            failregex_count = len(jail_data.get('failregex', []))
            
            # Get action names
            actions = jail_data.get('actions', {})
            action_names = list(actions.keys())
            
            # Create detailed jail description
            jail_desc = f"🔒 {jail_name}<br/>"
            jail_desc += f"Max Retries: {maxretry} in {findtime}<br/>"
            jail_desc += f"Ban Time: {bantime}<br/>"
            
            # Add backend if available
            if 'backend' in jail_data:
                jail_desc += f"Backend: {jail_data['backend']}<br/>"
            
            # Add logpath if available
            settings = jail_data.get('settings', {})
            if 'logpath' in settings:
                logpath = settings['logpath']
                # Shorten long paths
                if isinstance(logpath, str) and len(logpath) > 35:
                    logpath = "..." + logpath[-32:]
                jail_desc += f"Log: {logpath}<br/>"
            
            # Add port if available (check settings first, then actions)
            port = None
            if 'port' in settings:
                port = settings['port']
            else:
                # Check if port is defined in any action
                for action_name, action_config in actions.items():
                    if 'port' in action_config:
                        port = action_config['port']
                        break
            
            if port:
                jail_desc += f"Port: {port}<br/>"
            
            # Add filter if available
            if 'filter' in settings:
                jail_desc += f"Filter: {settings['filter']}<br/>"
            
            # Add action name if available
            if 'addaction' in settings:
                jail_desc += f"Action: {settings['addaction']}<br/>"
            
            jail_desc += f"{failregex_count} fail patterns"
            
            lines.append(f'    {jail_node}["{jail_desc}"]:::jailNode')
            lines.append(f'    {prev_node} --> {jail_node}')
            
            # Show actions
            if action_names:
                action_node = self._get_node_id(f'{jail_name}_actions')
                action_text = "⚡ Actions:<br/>" + "<br/>".join(action_names[:3])
                if len(action_names) > 3:
                    action_text += f"<br/>... +{len(action_names) - 3} more"
                
                lines.append(f'    {action_node}["{action_text}"]:::actionNode')
                lines.append(f'    {jail_node} --> {action_node}')
            
            # Show ignore IPs if present
            ignore_ips = jail_data.get('ignoreips', [])
            if ignore_ips:
                ignore_node = self._get_node_id(f'{jail_name}_ignore')
                ignore_text = f"✅ Whitelisted IPs:<br/>{', '.join(ignore_ips[:3])}"
                if len(ignore_ips) > 3:
                    ignore_text += f"<br/>... +{len(ignore_ips) - 3} more"
                
                lines.append(f'    {ignore_node}["{ignore_text}"]:::ignoreNode')
                lines.append(f'    {jail_node} -.-> {ignore_node}')
            
            lines.append('')
        
        return lines
    
    def _generate_detailed_view(self) -> List[str]:
        """Generate detailed view with all settings"""
        lines = []
        
        # Global settings
        global_settings = self.data.get('global_settings', {})
        if global_settings:
            global_node = self._get_node_id('global')
            lines.append(f'    {global_node}["⚙️ Global Settings"]:::globalNode')
            lines.append('')
        
        # Jails
        jails = self.data.get('jails', {})
        for jail_name, jail_data in sorted(jails.items()):
            jail_node = self._get_node_id(f'jail_{jail_name}')
            
            status = "🟢 Active" if jail_data.get('started', False) else "⚪ Inactive"
            lines.append(f'    {jail_node}["{status} {jail_name}"]:::jailNode')
            
            # Settings
            settings = jail_data.get('settings', {})
            for key, value in sorted(settings.items())[:5]:  # Limit to 5 settings
                setting_node = self._get_node_id(f'{jail_name}_{key}')
                value_str = str(value)[:30]
                lines.append(f'    {setting_node}["{key}: {value_str}"]:::settingNode')
                lines.append(f'    {jail_node} --> {setting_node}')
            
            lines.append('')
        
        return lines
    
    def _get_node_id(self, identifier: str) -> str:
        """Get or create a unique node ID"""
        if identifier not in self.node_map:
            self.node_counter += 1
            self.node_map[identifier] = f'node{self.node_counter}'
        return self.node_map[identifier]
    
    def _sanitize_label(self, text: str, max_length: int = 40) -> str:
        """Sanitize text for Mermaid labels"""
        text = text.replace('"', "'")
        # Don't replace <br/> tags - they're intentional for multi-line labels
        # Don't truncate if we have line breaks - they help with readability
        if '<br/>' not in text and len(text) > max_length:
            text = text[:max_length-3] + '...'
        return text
    
    def _generate_styles(self) -> List[str]:
        """Generate Mermaid style definitions"""
        return [
            '    %% Styling',
            '    classDef startNode fill:#9B59B6,stroke:#6C3483,stroke-width:3px,color:#fff,font-size:14px',
            '    classDef summaryNode fill:#34495E,stroke:#2C3E50,stroke-width:2px,color:#fff,font-size:12px',
            '    classDef jailNode fill:#3498DB,stroke:#2874A6,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef actionNode fill:#E74C3C,stroke:#C0392B,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef ignoreNode fill:#27AE60,stroke:#1E8449,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef warningNode fill:#F39C12,stroke:#D68910,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef globalNode fill:#95A5A6,stroke:#7F8C8D,stroke-width:2px,color:#fff,font-size:12px',
            '    classDef settingNode fill:#ECF0F1,stroke:#BDC3C7,stroke-width:1px,color:#333,font-size:10px',
        ]


def get_fail2ban_output() -> str:
    """Execute fail2ban-client --dp and return output"""
    try:
        result = subprocess.run(
            ['fail2ban-client', '--dp'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"fail2ban-client command failed: {result.stderr}")
        
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError("fail2ban-client command timed out")
    except FileNotFoundError:
        raise RuntimeError("fail2ban-client command not found")


def generate_html_visualization(mermaid_code: str, config_text: str = "") -> str:
    """Generate HTML page with Mermaid visualization"""
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>fail2ban Configuration Visualization</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 30px;
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        .subtitle {{
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }}
        .help-box {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 4px;
        }}
        .help-box h3 {{
            margin-top: 0;
            color: #856404;
        }}
        .help-box ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .help-box li {{
            margin: 8px 0;
            color: #856404;
        }}
        .legend {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            border-left: 4px solid #3498DB;
        }}
        .legend h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        .legend-items {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .legend-color {{
            width: 30px;
            height: 30px;
            border-radius: 5px;
            border: 2px solid #333;
        }}
        .color-jail {{ background: #3498DB; }}
        .color-action {{ background: #E74C3C; }}
        .color-ignore {{ background: #27AE60; }}
        .color-summary {{ background: #34495E; }}
        #diagram {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            overflow-x: auto;
        }}
        .controls {{
            text-align: center;
            margin-bottom: 20px;
        }}
        button {{
            background: #3498DB;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            margin: 0 5px;
            transition: background 0.3s;
        }}
        button:hover {{
            background: #2874A6;
        }}
        .info {{
            background: #e8f4f8;
            border-left: 4px solid #3498DB;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .info p {{
            margin: 5px 0;
            color: #2c3e50;
        }}
        .config-section {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .config-section h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        .config-section textarea {{
            width: 100%;
            min-height: 200px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            resize: vertical;
        }}
        .nav-links {{
            text-align: center;
            margin-bottom: 20px;
        }}
        .nav-links a {{
            color: #3498DB;
            text-decoration: none;
            margin: 0 15px;
            font-weight: 600;
        }}
        .nav-links a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ fail2ban Configuration Visualization</h1>
        <p class="subtitle">Intrusion Prevention System Overview</p>
        
        <div class="nav-links">
            <a href="/">← Back to Traffic Monitor</a> | 
            <a href="/api/iptables/visualize">View iptables Rules</a>
        </div>
        
        <div class="help-box">
            <h3>📖 Understanding fail2ban</h3>
            <ul>
                <li><strong>Jails</strong> monitor log files for suspicious activity (like failed login attempts)</li>
                <li><strong>Max Retries</strong> is how many failures are allowed before banning</li>
                <li><strong>Find Time</strong> is the time window to count failures</li>
                <li><strong>Ban Time</strong> is how long an IP address is blocked</li>
                <li><strong>Actions</strong> define what happens when an IP is banned (usually firewall rules)</li>
            </ul>
        </div>
        
        <div class="legend">
            <h3>🎨 Color Guide</h3>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-color color-jail"></div>
                    <span>Jail (Protection Rule)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-action"></div>
                    <span>Action (Ban Method)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-ignore"></div>
                    <span>Whitelisted IPs</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-summary"></div>
                    <span>Summary Information</span>
                </div>
            </div>
        </div>
        
        <div class="controls">
            <button onclick="location.reload()">🔄 Refresh</button>
            <button onclick="downloadSVG()">💾 Download SVG</button>
        </div>
        
        <div id="diagram">
            <pre class="mermaid" id="mermaidDiagram">
{mermaid_code}
            </pre>
        </div>
        
        <div class="info" style="margin-top: 30px;">
            <p><strong>💡 Pro Tip:</strong> fail2ban works together with your firewall (iptables/nftables) to automatically block attackers. When someone tries to break in too many times, fail2ban adds a firewall rule to block their IP address.</p>
        </div>
    </div>
    
    <script>
        mermaid.initialize({{ 
            startOnLoad: true,
            theme: 'default',
            flowchart: {{
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis',
                padding: 20
            }}
        }});
        
        function downloadSVG() {{
            const svg = document.querySelector('#diagram svg');
            if (!svg) {{
                alert('Please wait for the diagram to load');
                return;
            }}
            
            const svgData = new XMLSerializer().serializeToString(svg);
            const blob = new Blob([svgData], {{ type: 'image/svg+xml' }});
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'fail2ban-diagram.svg';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>'''
    return html


def main():
    """Main function for command-line usage"""
    import sys
    import argparse
    
    parser_args = argparse.ArgumentParser(
        description='Generate fail2ban configuration visualization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate visualization from live fail2ban
  fail2ban-client --dp | python3 fail2ban_visualizer.py
  
  # Generate from saved config file
  python3 fail2ban_visualizer.py -i fail2ban_config.txt
        '''
    )
    parser_args.add_argument(
        '-i', '--input',
        help='Input file with fail2ban --dp output (default: read from fail2ban-client)'
    )
    parser_args.add_argument(
        '-o', '--output',
        default='fail2ban_visualization.html',
        help='Output HTML file (default: fail2ban_visualization.html)'
    )
    args = parser_args.parse_args()
    
    # Get fail2ban output
    if args.input:
        print(f"Reading fail2ban config from {args.input}...")
        try:
            with open(args.input, 'r') as f:
                fail2ban_output = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Fetching fail2ban configuration...")
        try:
            fail2ban_output = get_fail2ban_output()
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Parse the output
    print("Parsing configuration...")
    parser = Fail2banParser()
    data = parser.parse_output(fail2ban_output)
    
    print(f"Found {len(data['jails'])} jails")
    
    # Generate Mermaid diagram
    print("Generating Mermaid diagram...")
    generator = Fail2banMermaidGenerator(data)
    mermaid_code = generator.generate(simplified=True)
    
    # Generate HTML
    print("Creating HTML visualization...")
    html = generate_html_visualization(mermaid_code)
    
    # Save to file
    output_file = args.output
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"✅ Visualization saved to {output_file}")
    print(f"   Open it in your browser to view the diagram")


if __name__ == '__main__':
    main()
