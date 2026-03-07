#!/usr/bin/env python3
"""
iptables Visualizer - Parse iptables output and generate Mermaid diagrams
"""

import subprocess
import re
from typing import Dict, List, Tuple, Optional

try:
    from docker_enrichment import DockerEnricher
    DOCKER_ENRICHMENT_AVAILABLE = True
except ImportError:
    DOCKER_ENRICHMENT_AVAILABLE = False
    DockerEnricher = None


class IptablesParser:
    """Parse iptables -L -v -n output into structured data"""
    
    def __init__(self):
        self.chains = {}
        self.current_chain = None
        
    def parse_output(self, output: str) -> Dict:
        """Parse the full iptables output"""
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.rstrip()
            if not line:
                continue
                
            # Check if this is a chain header
            chain_match = re.match(r'^Chain\s+(\S+)\s+\(policy\s+(\S+)(?:\s+(\d+)\s+packets?,\s+(\d+)\s+bytes?)?\)', line)
            if chain_match:
                chain_name = chain_match.group(1)
                policy = chain_match.group(2)
                policy_pkts = chain_match.group(3) or '0'
                policy_bytes = chain_match.group(4) or '0'
                
                self.current_chain = chain_name
                self.chains[chain_name] = {
                    'policy': policy,
                    'policy_pkts': policy_pkts,
                    'policy_bytes': policy_bytes,
                    'rules': []
                }
                continue
            
            # Check if this is the column header line
            if line.strip().startswith('pkts') or line.strip().startswith('target'):
                continue
            
            # Parse rule line
            if self.current_chain and line.strip():
                rule = self._parse_rule_line(line)
                if rule:
                    self.chains[self.current_chain]['rules'].append(rule)
        
        return self.chains
    
    def _parse_rule_line(self, line: str) -> Optional[Dict]:
        """Parse a single rule line"""
        # Split by whitespace, but this is tricky due to variable spacing
        parts = line.split()
        
        if len(parts) < 9:
            return None
        
        try:
            rule = {
                'pkts': parts[0],
                'bytes': parts[1],
                'target': parts[2],
                'prot': parts[3],
                'opt': parts[4],
                'in': parts[5],
                'out': parts[6],
                'source': parts[7],
                'destination': parts[8],
                'extra': ' '.join(parts[9:]) if len(parts) > 9 else ''
            }
            return rule
        except (IndexError, ValueError):
            return None


class MermaidGenerator:
    """Generate Mermaid flowchart from iptables data"""
    
    def __init__(self, chains: Dict, enable_docker_enrichment: bool = True, enrichment_data: Optional[str] = None):
        self.chains = chains
        self.node_counter = 0
        self.node_map = {}
        self.docker_enricher = None
        
        # Initialize Docker enrichment if available and enabled
        if enable_docker_enrichment and DOCKER_ENRICHMENT_AVAILABLE:
            try:
                self.docker_enricher = DockerEnricher(enrichment_data=enrichment_data)
            except Exception:
                self.docker_enricher = None
        
    def generate(self, simplified: bool = True, max_rules_per_type: int = 5) -> str:
        """Generate complete Mermaid diagram
        
        Args:
            simplified: If True, use simplified view with main chains only
            max_rules_per_type: Maximum number of rules to show per type (ACCEPT, DROP, etc.)
                               Set to 0 or negative to show all rules
        """
        lines = ['flowchart TD']
        lines.append('    %% iptables Firewall Rules Visualization')
        lines.append('')
        
        if simplified:
            # Simplified view: only show main chains with summary
            lines.extend(self._generate_simplified_view(max_rules_per_type))
        else:
            # Full view: show all chains
            main_chains = ['INPUT', 'FORWARD', 'OUTPUT']
            for chain_name in main_chains:
                if chain_name in self.chains:
                    lines.extend(self._generate_chain(chain_name, is_main=True))
                    lines.append('')
            
            # Add custom chains
            for chain_name in sorted(self.chains.keys()):
                if chain_name not in main_chains:
                    lines.extend(self._generate_chain(chain_name, is_main=False))
                    lines.append('')
        
        # Add styling
        lines.extend(self._generate_styles())
        
        return '\n'.join(lines)
    
    def _generate_docker_chain_flow(self, chain_name: str, parent_node: str, max_depth: int = 3, visited: Optional[set] = None) -> List[str]:
        """Generate UML activity diagram style flow for a Docker chain
        
        Args:
            chain_name: Name of the chain to visualize
            parent_node: Node ID of the parent that jumps to this chain
            max_depth: Maximum recursion depth to prevent infinite loops
            visited: Set of already visited chains to prevent cycles
        
        Returns:
            List of Mermaid diagram lines
        """
        if visited is None:
            visited = set()
        
        if chain_name in visited or max_depth <= 0:
            return []
        
        if chain_name not in self.chains:
            return []
        
        visited.add(chain_name)
        lines = []
        chain_data = self.chains[chain_name]
        
        # Create chain node
        chain_node = self._get_node_id(f'chain_{chain_name}')
        lines.append(f'    {chain_node}{{{{"⚙️ {chain_name}"}}}}:::dockerChain')
        lines.append(f'    {parent_node} --> {chain_node}')
        
        prev_node = chain_node
        
        # Group rules by type for better visualization
        for idx, rule in enumerate(chain_data['rules']):
            # Build condition description
            conditions = []
            if rule.get('in') and rule['in'] != '*':
                in_iface = rule['in']
                # Enrich interface name
                if self.docker_enricher:
                    in_info = self.docker_enricher.enrich_interface(in_iface.lstrip('!'))
                    if in_info.get('label'):
                        in_label = in_info['label']
                    else:
                        in_label = in_iface
                else:
                    in_label = in_iface
                
                if in_iface.startswith('!'):
                    conditions.append(f"in≠{in_label.lstrip('!')}")
                else:
                    conditions.append(f"in={in_label}")
            
            if rule.get('out') and rule['out'] != '*':
                out_iface = rule['out']
                # Enrich interface name
                if self.docker_enricher:
                    out_info = self.docker_enricher.enrich_interface(out_iface.lstrip('!'))
                    if out_info.get('label'):
                        out_label = out_info['label']
                    else:
                        out_label = out_iface
                else:
                    out_label = out_iface
                
                if out_iface.startswith('!'):
                    conditions.append(f"out≠{out_label.lstrip('!')}")
                else:
                    conditions.append(f"out={out_label}")
            
            if rule.get('source') and rule['source'] not in ['0.0.0.0/0', 'anywhere']:
                conditions.append(f"src={rule['source']}")
            
            if rule.get('destination') and rule['destination'] not in ['0.0.0.0/0', 'anywhere']:
                conditions.append(f"dst={rule['destination']}")
            
            # Create rule node
            rule_node = self._get_node_id(f'{chain_name}_rule_{idx}')
            target = rule['target']
            
            # Format the rule based on target
            if target in ['ACCEPT', 'DROP', 'REJECT']:
                # Terminal action
                action_emoji = '✅' if target == 'ACCEPT' else '❌'
                if conditions:
                    cond_str = ', '.join(conditions[:2])  # Limit to 2 conditions for readability
                    if len(conditions) > 2:
                        cond_str += '...'
                    desc = f"{action_emoji} {target}<br/>{cond_str}"
                else:
                    desc = f"{action_emoji} {target}"
                
                style = ':::acceptRule' if target == 'ACCEPT' else ':::dropRule'
                lines.append(f'    {rule_node}("{desc}"){style}')
                lines.append(f'    {prev_node} -->|{"if " + ", ".join(conditions[:1]) if conditions else "always"}| {rule_node}')
            
            elif target == 'RETURN':
                # Return to parent chain
                desc = "↩️ RETURN"
                lines.append(f'    {rule_node}["{desc}"]:::returnRule')
                lines.append(f'    {prev_node} --> {rule_node}')
            
            elif target in self.chains:
                # Jump to another chain - create decision diamond
                if conditions:
                    cond_str = ', '.join(conditions[:2])
                    if len(conditions) > 2:
                        cond_str += '...'
                    desc = f"❓ {cond_str}"
                else:
                    desc = f"→ {target}"
                
                lines.append(f'    {rule_node}{{{{{desc}}}}}:::conditionNode')
                lines.append(f'    {prev_node} --> {rule_node}')
                
                # Recursively generate the target chain
                if max_depth > 1:
                    sub_lines = self._generate_docker_chain_flow(target, rule_node, max_depth - 1, visited.copy())
                    lines.extend(sub_lines)
            
            else:
                # Unknown target or LOG
                desc = f"📝 {target}"
                if conditions:
                    desc += f"<br/>{''.join(conditions[:1])}"
                lines.append(f'    {rule_node}["{desc}"]:::logRule')
                lines.append(f'    {prev_node} --> {rule_node}')
            
            prev_node = rule_node
        
        return lines
    
    def _generate_simplified_view(self, max_rules_per_type: int = 5) -> List[str]:
        """Generate a simplified, beginner-friendly view
        
        Args:
            max_rules_per_type: Maximum rules to show per type. 0 or negative = show all
        """
        lines = []
        
        # Create a start node
        lines.append('    START(["📦 Incoming Packet"]):::startNode')
        lines.append('')
        
        # Show main chains as decision points
        main_chains = ['INPUT', 'FORWARD', 'OUTPUT']
        
        for idx, chain_name in enumerate(main_chains):
            if chain_name not in self.chains:
                continue
            
            chain_data = self.chains[chain_name]
            chain_node = self._get_node_id(f'chain_{chain_name}')
            
            # Create chain header with explanation
            explanation = {
                'INPUT': 'Traffic TO this machine',
                'FORWARD': 'Traffic THROUGH this machine',
                'OUTPUT': 'Traffic FROM this machine'
            }.get(chain_name, '')
            
            lines.append(f'    {chain_node}{{{{"🔍 {chain_name}<br/>{explanation}<br/>Default: {chain_data["policy"]}"}}}}:::mainChain')
            
            if idx == 0:
                lines.append(f'    START --> {chain_node}')
            
            # Count rule types
            accept_count = sum(1 for r in chain_data['rules'] if r['target'] == 'ACCEPT')
            drop_count = sum(1 for r in chain_data['rules'] if r['target'] in ['DROP', 'REJECT'])
            jump_count = sum(1 for r in chain_data['rules'] if r['target'] not in ['ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN'])
            
            # Show summary
            summary_node = self._get_node_id(f'{chain_name}_summary')
            summary_text = f"📊 {accept_count} ACCEPT rules<br/>{drop_count} DROP/REJECT rules"
            if jump_count > 0:
                summary_text += f"<br/>{jump_count} custom chains"
            
            lines.append(f'    {summary_node}["{summary_text}"]:::summaryNode')
            lines.append(f'    {chain_node} --> {summary_node}')
            
            # Determine how many rules to show
            all_accept_rules = [r for r in chain_data['rules'] if r['target'] == 'ACCEPT']
            all_drop_rules = [r for r in chain_data['rules'] if r['target'] in ['DROP', 'REJECT']]
            all_jump_rules = [r for r in chain_data['rules'] if r['target'] not in ['ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN']]
            
            # If max_rules_per_type <= 0, show all rules
            if max_rules_per_type <= 0:
                accept_rules = all_accept_rules
                drop_rules = all_drop_rules
            else:
                accept_rules = all_accept_rules[:max_rules_per_type]
                drop_rules = all_drop_rules[:max_rules_per_type]
            
            prev_node = summary_node
            
            # Show important custom chain jumps (like DOCKER, DOCKER-USER, etc.) with UML flow
            important_chains = ['DOCKER', 'DOCKER-USER', 'DOCKER-FORWARD', 'DOCKER-ISOLATION', 'DOCKER-CT', 'DOCKER-BRIDGE']
            important_jumps = [r for r in all_jump_rules if r['target'] in important_chains]
            
            if important_jumps and self.docker_enricher and self.docker_enricher.docker_available:
                # Use UML activity diagram style for Docker chains
                for rule in important_jumps[:3]:  # Limit to 3 to avoid clutter
                    # Create a decision node
                    decision_node = self._get_node_id(f'{chain_name}_decision_{id(rule)}')
                    
                    # Build condition
                    conditions = []
                    if rule.get('in') and rule['in'] != '*':
                        in_iface = rule['in'].lstrip('!')
                        if self.docker_enricher:
                            in_info = self.docker_enricher.enrich_interface(in_iface)
                            in_label = in_info.get('label', in_iface)
                        else:
                            in_label = in_iface
                        conditions.append(f"in={in_label}")
                    
                    if rule.get('out') and rule['out'] != '*':
                        out_iface = rule['out'].lstrip('!')
                        if self.docker_enricher:
                            out_info = self.docker_enricher.enrich_interface(out_iface)
                            out_label = out_info.get('label', out_iface)
                        else:
                            out_label = out_iface
                        conditions.append(f"out={out_label}")
                    
                    if conditions:
                        cond_str = ', '.join(conditions[:2])
                        lines.append(f'    {decision_node}{{{{{cond_str}?}}}}:::conditionNode')
                    else:
                        lines.append(f'    {decision_node}{{{{→ {rule["target"]}}}}}:::conditionNode')
                    
                    lines.append(f'    {prev_node} --> {decision_node}')
                    
                    # Generate the Docker chain flow (limited depth)
                    docker_flow = self._generate_docker_chain_flow(rule['target'], decision_node, max_depth=2)
                    lines.extend(docker_flow)
                    
                    prev_node = decision_node
            elif important_jumps:
                # Fallback to simple jump visualization
                for rule in important_jumps[:5]:  # Limit to 5 important jumps
                    jump_node = self._get_node_id(f'{chain_name}_jump_{id(rule)}')
                    desc = f"→ {rule['target']}"
                    if rule.get('in') and rule['in'] != '*':
                        desc += f"<br/>in: {rule['in']}"
                    if rule.get('out') and rule['out'] != '*':
                        desc += f"<br/>out: {rule['out']}"
                    lines.append(f'    {jump_node}("{desc}"):::jumpRule')
                    lines.append(f'    {prev_node} --> {jump_node}')
                    prev_node = jump_node
            
            if accept_rules:
                for rule in accept_rules:
                    rule_node = self._get_node_id(f'{chain_name}_accept_{id(rule)}')
                    desc = self._format_simple_rule(rule)
                    lines.append(f'    {rule_node}("{desc}"):::acceptRule')
                    lines.append(f'    {prev_node} --> {rule_node}')
                    prev_node = rule_node
                
                # Show "more rules" indicator if there are more (only when limiting)
                if max_rules_per_type > 0 and len(all_accept_rules) > max_rules_per_type:
                    more_node = self._get_node_id(f'{chain_name}_more_accept')
                    remaining = len(all_accept_rules) - max_rules_per_type
                    lines.append(f'    {more_node}["... {remaining} more ACCEPT rules ..."]:::moreRules')
                    lines.append(f'    {prev_node} --> {more_node}')
                    prev_node = more_node
            
            if drop_rules:
                for rule in drop_rules:
                    rule_node = self._get_node_id(f'{chain_name}_drop_{id(rule)}')
                    desc = self._format_simple_rule(rule)
                    lines.append(f'    {rule_node}("{desc}"):::dropRule')
                    lines.append(f'    {prev_node} --> {rule_node}')
                    prev_node = rule_node
                
                # Show "more rules" indicator if there are more (only when limiting)
                if max_rules_per_type > 0 and len(all_drop_rules) > max_rules_per_type:
                    more_node = self._get_node_id(f'{chain_name}_more_drop')
                    remaining = len(all_drop_rules) - max_rules_per_type
                    # Check if these are boring banned IPs (ufw-user-input pattern)
                    if self._is_boring_ban_chain(chain_name, all_drop_rules):
                        lines.append(f'    {more_node}["... {remaining} more banned IPs ..."]:::moreRules')
                    else:
                        lines.append(f'    {more_node}["... {remaining} more DROP/REJECT rules ..."]:::moreRules')
                    lines.append(f'    {prev_node} --> {more_node}')
                    prev_node = more_node
            
            # Show policy
            if chain_data['policy'] != 'ACCEPT':
                policy_node = self._get_node_id(f'{chain_name}_policy')
                lines.append(f'    {policy_node}["❌ Default: {chain_data["policy"]}<br/>(if no rule matches)"]:::policyNode')
                lines.append(f'    {prev_node} --> {policy_node}')
            else:
                policy_node = self._get_node_id(f'{chain_name}_policy')
                lines.append(f'    {policy_node}["✅ Default: ACCEPT<br/>(if no rule matches)"]:::policyNode')
                lines.append(f'    {prev_node} --> {policy_node}')
            
            lines.append('')
        
        return lines
    
    def _is_boring_ban_chain(self, chain_name: str, drop_rules: List[Dict]) -> bool:
        """Check if this is a boring chain that just bans IPs (like ufw-user-input)
        
        Returns True if:
        - Chain name contains 'user-input' or 'blacklist' or 'banlist'
        - All rules are simple source IP blocks with no other criteria
        """
        # Check chain name patterns
        boring_patterns = ['user-input', 'blacklist', 'banlist', 'banned']
        if any(pattern in chain_name.lower() for pattern in boring_patterns):
            # Check if all rules are simple IP bans
            for rule in drop_rules:
                # If rule has anything other than source IP, it's not boring
                if (rule.get('destination') and rule['destination'] not in ['0.0.0.0/0', 'anywhere'] or
                    rule.get('in') and rule['in'] != '*' or
                    rule.get('out') and rule['out'] != '*' or
                    rule.get('prot') and rule['prot'] not in ['0', 'all'] or
                    rule.get('extra')):
                    return False
            return True
        return False
    
    def _format_simple_rule(self, rule: Dict) -> str:
        """Format rule in a simple, beginner-friendly way with full details"""
        lines = []
        
        # Start with action (main line)
        action = rule['target']
        if action == 'ACCEPT':
            action_text = '✅ Allow'
        elif action in ['DROP', 'REJECT']:
            action_text = '❌ Block'
        else:
            action_text = f'→ {action}'
        
        # Build detailed description
        details = []
        
        # Add protocol
        prot_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '0': 'all', 'all': 'all'}
        prot = prot_map.get(rule['prot'], rule['prot'])
        if prot and prot != 'all':
            details.append(f"proto: {prot}")
        
        # Add source with Docker enrichment
        if rule.get('source') and rule['source'] != '0.0.0.0/0' and rule['source'] != 'anywhere':
            source_text = f"from: {rule['source']}"
            if self.docker_enricher:
                source_info = self.docker_enricher.enrich_ip(rule['source'])
                if source_info.get('label'):
                    source_text = f"from: {source_info['label']}"
                elif source_info.get('type') == 'private':
                    source_text = f"from: {rule['source']} {source_info.get('label', '')}"
            details.append(source_text)
        
        # Add destination with Docker enrichment
        if rule.get('destination') and rule['destination'] != '0.0.0.0/0' and rule['destination'] != 'anywhere':
            dest_text = f"to: {rule['destination']}"
            if self.docker_enricher:
                dest_info = self.docker_enricher.enrich_ip(rule['destination'])
                if dest_info.get('label'):
                    dest_text = f"to: {dest_info['label']}"
                elif dest_info.get('type') == 'private':
                    dest_text = f"to: {rule['destination']} {dest_info.get('label', '')}"
            details.append(dest_text)
        
        # Add input interface with Docker enrichment
        if rule.get('in') and rule['in'] != '*':
            in_text = f"in: {rule['in']}"
            if self.docker_enricher:
                in_info = self.docker_enricher.enrich_interface(rule['in'])
                if in_info.get('label'):
                    in_text = f"in: {in_info['label']}"
            # Handle negation (!)
            if rule['in'].startswith('!'):
                in_text = f"in: NOT {rule['in'][1:]}"
                if self.docker_enricher:
                    in_info = self.docker_enricher.enrich_interface(rule['in'][1:])
                    if in_info.get('label'):
                        in_text = f"in: NOT {in_info['label']}"
            details.append(in_text)
        
        # Add output interface with Docker enrichment
        if rule.get('out') and rule['out'] != '*':
            out_text = f"out: {rule['out']}"
            if self.docker_enricher:
                out_info = self.docker_enricher.enrich_interface(rule['out'])
                if out_info.get('label'):
                    out_text = f"out: {out_info['label']}"
            # Handle negation (!)
            if rule['out'].startswith('!'):
                out_text = f"out: NOT {rule['out'][1:]}"
                if self.docker_enricher:
                    out_info = self.docker_enricher.enrich_interface(rule['out'][1:])
                    if out_info.get('label'):
                        out_text = f"out: NOT {out_info['label']}"
            details.append(out_text)
        
        # Add port if present (destination port)
        extra = rule.get('extra', '')
        port_match = re.search(r'dpt:(\d+)', extra)
        if port_match:
            port = port_match.group(1)
            port_names = {'22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '53': 'DNS', '25': 'SMTP', 
                         '3306': 'MySQL', '5432': 'PostgreSQL', '6379': 'Redis', '27017': 'MongoDB'}
            if port in port_names:
                details.append(f"dport: {port} ({port_names[port]})")
            else:
                details.append(f"dport: {port}")
        
        # Add source port if present
        sport_match = re.search(r'spt:(\d+)', extra)
        if sport_match:
            details.append(f"sport: {sport_match.group(1)}")
        
        # Add connection state if present
        if 'ctstate' in extra or 'state' in extra:
            if 'ESTABLISHED,RELATED' in extra or 'RELATED,ESTABLISHED' in extra:
                details.append("state: ESTABLISHED,RELATED")
            elif 'ESTABLISHED' in extra:
                details.append("state: ESTABLISHED")
            elif 'NEW' in extra:
                details.append("state: NEW")
            elif 'RELATED' in extra:
                details.append("state: RELATED")
        
        # Add other common matches
        if 'limit:' in extra:
            limit_match = re.search(r'limit: avg (\S+)', extra)
            if limit_match:
                details.append(f"limit: {limit_match.group(1)}")
        
        if 'DOCKER' in rule.get('target', ''):
            details.append("(Docker)")
        
        # Format the result with line breaks for readability
        if details:
            # Combine action with first few details on first line, rest on second line
            result = action_text + "<br/>" + ", ".join(details)
        else:
            result = action_text + "<br/>(all traffic)"
        
        return self._sanitize_label(result, max_length=80)
    
    def _get_node_id(self, identifier: str) -> str:
        """Get or create a unique node ID"""
        if identifier not in self.node_map:
            self.node_counter += 1
            self.node_map[identifier] = f'node{self.node_counter}'
        return self.node_map[identifier]
    
    def _sanitize_label(self, text: str, max_length: int = 35) -> str:
        """Sanitize text for Mermaid labels"""
        # Replace problematic characters
        text = text.replace('"', "'")
        # Don't replace <br/> tags - they're intentional
        # Don't truncate if we have line breaks - they help with readability
        if '<br/>' not in text and len(text) > max_length:
            text = text[:max_length-3] + '...'
        return text
    
    def _generate_chain(self, chain_name: str, is_main: bool = False) -> List[str]:
        """Generate Mermaid nodes for a single chain"""
        lines = []
        chain_data = self.chains[chain_name]
        
        # Create chain start node
        chain_node = self._get_node_id(f'chain_{chain_name}')
        if is_main:
            lines.append(f'    {chain_node}["{chain_name}<br/>Policy: {chain_data["policy"]}"]:::mainChain')
        else:
            lines.append(f'    {chain_node}["{chain_name}"]:::customChain')
        
        # Process rules
        prev_node = chain_node
        for idx, rule in enumerate(chain_data['rules']):
            rule_node = self._get_node_id(f'{chain_name}_rule_{idx}')
            
            # Create rule description
            rule_desc = self._format_rule_description(rule)
            
            # Determine node style based on target
            target = rule['target']
            if target == 'ACCEPT':
                style = ':::acceptRule'
                shape = f'{rule_node}("{rule_desc}")'
            elif target in ['DROP', 'REJECT']:
                style = ':::dropRule'
                shape = f'{rule_node}("{rule_desc}")'
            elif target == 'LOG':
                style = ':::logRule'
                shape = f'{rule_node}["{rule_desc}"]'
            elif target == 'RETURN':
                style = ':::returnRule'
                shape = f'{rule_node}["{rule_desc}"]'
            else:
                # Jump to another chain
                style = ':::jumpRule'
                shape = f'{rule_node}["{rule_desc}"]'
            
            lines.append(f'    {shape}{style}')
            lines.append(f'    {prev_node} --> {rule_node}')
            
            # If this is a jump to another chain, create connection
            if target not in ['ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN'] and target in self.chains:
                target_chain_node = self._get_node_id(f'chain_{target}')
                lines.append(f'    {rule_node} -.->|jump| {target_chain_node}')
            
            prev_node = rule_node
        
        # Add policy node
        if chain_data['policy'] != 'ACCEPT':
            policy_node = self._get_node_id(f'{chain_name}_policy')
            if chain_data['policy'] == 'DROP':
                lines.append(f'    {policy_node}["Policy: DROP"]:::dropRule')
            else:
                lines.append(f'    {policy_node}["Policy: {chain_data["policy"]}"]:::returnRule')
            lines.append(f'    {prev_node} --> {policy_node}')
        
        return lines
    
    def _format_rule_description(self, rule: Dict) -> str:
        """Format rule into a readable description"""
        parts = []
        
        # Add target
        parts.append(f"{rule['target']}")
        
        # Add protocol if not all
        if rule['prot'] != '0':
            prot_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
            prot = prot_map.get(rule['prot'], rule['prot'])
            parts.append(prot)
        
        # Add port (most important for understanding)
        port_match = re.search(r'dpt:(\d+)', rule.get('extra', ''))
        if port_match:
            parts.append(f"port {port_match.group(1)}")
        
        # Add connection state if present
        if 'ctstate' in rule.get('extra', ''):
            if 'ESTABLISHED' in rule['extra']:
                parts.append('established')
            elif 'NEW' in rule['extra']:
                parts.append('new')
        
        result = ' '.join(parts)
        return self._sanitize_label(result, max_length=35)
    
    def _generate_styles(self) -> List[str]:
        """Generate Mermaid style definitions"""
        return [
            '    %% Styling',
            '    classDef startNode fill:#9B59B6,stroke:#6C3483,stroke-width:3px,color:#fff,font-size:14px',
            '    classDef mainChain fill:#4A90E2,stroke:#2E5C8A,stroke-width:3px,color:#fff,font-size:13px',
            '    classDef summaryNode fill:#34495E,stroke:#2C3E50,stroke-width:2px,color:#fff,font-size:12px',
            '    classDef customChain fill:#7B68EE,stroke:#4B0082,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef dockerChain fill:#2C3E50,stroke:#1ABC9C,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef conditionNode fill:#F39C12,stroke:#D68910,stroke-width:2px,color:#000,font-size:10px',
            '    classDef acceptRule fill:#27AE60,stroke:#1E8449,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef dropRule fill:#E74C3C,stroke:#C0392B,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef logRule fill:#F39C12,stroke:#D68910,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef returnRule fill:#95A5A6,stroke:#7F8C8D,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef jumpRule fill:#3498DB,stroke:#2874A6,stroke-width:2px,color:#fff,font-size:11px',
            '    classDef policyNode fill:#E67E22,stroke:#CA6F1E,stroke-width:3px,color:#fff,font-size:12px',
            '    classDef moreRules fill:#95A5A6,stroke:#7F8C8D,stroke-width:2px,stroke-dasharray:5 5,color:#fff,font-style:italic,font-size:11px',
        ]


def get_iptables_output() -> str:
    """Execute iptables -L -v -n and return output"""
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-L', '-v', '-n'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"iptables command failed: {result.stderr}")
        
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError("iptables command timed out")
    except FileNotFoundError:
        raise RuntimeError("iptables command not found")


def generate_html_visualization(mermaid_code: str) -> str:
    """Generate HTML page with Mermaid visualization"""
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iptables Firewall Visualization</title>
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
        .help-box strong {{
            color: #533f03;
        }}
        .legend {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            border-left: 4px solid #4A90E2;
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
        .color-accept {{ background: #27AE60; }}
        .color-drop {{ background: #E74C3C; }}
        .color-policy {{ background: #E67E22; }}
        .color-main {{ background: #4A90E2; }}
        .color-summary {{ background: #34495E; }}
        .color-docker {{ background: #2C3E50; border: 2px solid #1ABC9C; }}
        .color-condition {{ background: #F39C12; }}
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
            background: #4A90E2;
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
            background: #357ABD;
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
        .chain-explanation {{
            background: #f0f8ff;
            border: 1px solid #b8daff;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .chain-explanation h4 {{
            margin-top: 0;
            color: #004085;
        }}
        .chain-explanation p {{
            margin: 8px 0;
            color: #004085;
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 iptables Firewall Visualization</h1>
        <p class="subtitle">Beginner-Friendly Firewall Rules Diagram</p>
        
        <div class="help-box">
            <h3>📖 How to Read This Diagram</h3>
            <ul>
                <li><strong>Follow the arrows from top to bottom</strong> - Each packet flows through rules in order</li>
                <li><strong>Green boxes (✅)</strong> = Traffic is ALLOWED through the firewall</li>
                <li><strong>Red boxes (❌)</strong> = Traffic is BLOCKED by the firewall</li>
                <li><strong>Orange boxes</strong> = Default policy (what happens if no rule matches)</li>
                <li><strong>⚠️ This is a SUMMARY view</strong> - Only the first 5 rules of each type are shown. Gray dashed boxes indicate additional hidden rules.</li>
            </ul>
        </div>
        
        <div class="chain-explanation">
            <h4>🔍 Understanding the Three Chains</h4>
            <p><strong>INPUT:</strong> Controls traffic coming TO this computer (e.g., someone accessing your web server)</p>
            <p><strong>FORWARD:</strong> Controls traffic passing THROUGH this computer (e.g., routing between networks, Docker containers)</p>
            <p><strong>OUTPUT:</strong> Controls traffic going FROM this computer (e.g., when you browse the web)</p>
        </div>
        
        <div class="legend">
            <h3>🎨 Color Guide</h3>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-color color-main"></div>
                    <span>Chain Name (INPUT/FORWARD/OUTPUT)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-summary"></div>
                    <span>Rule Summary (Total Count)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-docker"></div>
                    <span>⚙️ Docker Chain (DOCKER-*)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-condition"></div>
                    <span>❓ Condition (if/then decision)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-accept"></div>
                    <span>✅ ACCEPT (Allow Traffic)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-drop"></div>
                    <span>❌ DROP/REJECT (Block Traffic)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color color-policy"></div>
                    <span>Default Policy (Fallback Action)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #95A5A6; border-style: dashed;"></div>
                    <span>... Additional Hidden Rules ...</span>
                </div>
            </div>
        </div>
        
        <div class="controls">
            <label style="display: inline-flex; align-items: center; gap: 10px; margin-right: 20px; cursor: pointer;">
                <input type="checkbox" id="showAllRules" onchange="toggleDetailLevel()" style="width: 20px; height: 20px; cursor: pointer;">
                <span style="font-size: 16px; color: #2c3e50;">Show All Rules (may be very long)</span>
            </label>
            <button onclick="location.reload()">🔄 Refresh</button>
            <button onclick="downloadSVG()">💾 Download SVG</button>
        </div>
        
        <div id="diagram">
            <pre class="mermaid" id="mermaidDiagram">
{mermaid_code}
            </pre>
        </div>
        
        <div class="info" style="margin-top: 30px;">
            <p><strong>💡 Pro Tip:</strong> The "Default Policy" at the bottom of each chain is what happens when a packet doesn't match any of the rules above it. A "DROP" policy means unmatched traffic is blocked (more secure).</p>
        </div>
    </div>
    
    <script>
        // Check URL parameter and set checkbox state
        const urlParams = new URLSearchParams(window.location.search);
        const showAll = urlParams.get('show_all') === 'true';
        document.getElementById('showAllRules').checked = showAll;
        
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
        
        function toggleDetailLevel() {{
            const checkbox = document.getElementById('showAllRules');
            const url = new URL(window.location);
            if (checkbox.checked) {{
                url.searchParams.set('show_all', 'true');
            }} else {{
                url.searchParams.delete('show_all');
            }}
            window.location.href = url.toString();
        }}
        
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
            link.download = 'iptables-diagram.svg';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>'''
    return html


def parse_combined_input(input_text: str) -> Tuple[str, str]:
    """Parse combined input containing Docker enrichment data and iptables output
    
    Returns:
        Tuple of (enrichment_data, iptables_output)
    """
    enrichment_data = ""
    iptables_output = ""
    
    # Check if input contains Docker enrichment data
    if '=== DOCKER ENRICHMENT DATA ===' in input_text:
        # Split at the end marker
        parts = input_text.split('=== END DOCKER ENRICHMENT DATA ===')
        if len(parts) >= 2:
            # Include the markers in enrichment data
            enrichment_data = parts[0] + '=== END DOCKER ENRICHMENT DATA ==='
            # Everything after is iptables output
            iptables_output = parts[1].strip()
            # Remove the "Now run" instruction lines
            lines = iptables_output.split('\n')
            iptables_lines = []
            for line in lines:
                if not line.startswith('# Now run:') and not line.startswith('# Copy everything'):
                    iptables_lines.append(line)
            iptables_output = '\n'.join(iptables_lines).strip()
    else:
        # No enrichment data, just iptables output
        iptables_output = input_text
    
    return enrichment_data, iptables_output


def main():
    """Main function for command-line usage"""
    import sys
    import argparse
    
    # Parse command-line arguments
    parser_args = argparse.ArgumentParser(
        description='Generate iptables firewall visualization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate simplified view (first 5 rules of each type)
  sudo python3 iptables_visualizer.py
  
  # Generate detailed view (all rules)
  sudo python3 iptables_visualizer.py --show-all
  
  # Read from stdin (with Docker enrichment data)
  cat combined_output.txt | python3 iptables_visualizer.py --stdin
        '''
    )
    parser_args.add_argument(
        '--show-all', 
        action='store_true',
        help='Show all rules instead of just the first 5 of each type'
    )
    parser_args.add_argument(
        '-o', '--output',
        default='iptables_visualization.html',
        help='Output HTML file (default: iptables_visualization.html)'
    )
    parser_args.add_argument(
        '--stdin',
        action='store_true',
        help='Read iptables output (and optional Docker enrichment data) from stdin'
    )
    args = parser_args.parse_args()
    
    enrichment_data = None
    
    # Get iptables output
    if args.stdin:
        print("Reading from stdin...")
        input_text = sys.stdin.read()
        enrichment_data, iptables_output = parse_combined_input(input_text)
        if enrichment_data:
            print("Found Docker enrichment data")
    else:
        print("Fetching iptables rules...")
        try:
            iptables_output = get_iptables_output()
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Parse the output
    print("Parsing rules...")
    parser = IptablesParser()
    chains = parser.parse_output(iptables_output)
    
    print(f"Found {len(chains)} chains")
    
    # Generate Mermaid diagram
    if args.show_all:
        print("Generating detailed Mermaid diagram (all rules)...")
        max_rules = 0  # 0 means unlimited
    else:
        print("Generating simplified Mermaid diagram (first 5 rules of each type)...")
        max_rules = 5
    
    generator = MermaidGenerator(chains, enrichment_data=enrichment_data)
    mermaid_code = generator.generate(simplified=True, max_rules_per_type=max_rules)
    
    # Generate HTML
    print("Creating HTML visualization...")
    html = generate_html_visualization(mermaid_code)
    
    # Save to file
    output_file = args.output
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"✅ Visualization saved to {output_file}")
    print(f"   Open it in your browser to view the diagram")
    if not args.show_all:
        print(f"   💡 Tip: Use --show-all to see all rules")


if __name__ == '__main__':
    main()
