#!/usr/bin/env python3
"""
Tree visualization for iptables model

Converts iptables configuration into a text-based tree representation.
"""

from typing import Optional, Set, List, Tuple
from src.iptables.model import IptablesConfig, Table, Chain, Rule


class IptablesTreeFormatter:
    """Format iptables configuration as a text tree"""
    
    def __init__(self, show_docker_only: bool = False, show_rules: bool = True, inline_chains: bool = True, max_depth: int = 10, compress_same_target: bool = True):
        """
        Initialize tree formatter.
        
        Args:
            show_docker_only: Only show Docker-related chains and rules
            show_rules: Include rules in the tree
            inline_chains: Show referenced chains inline instead of separately
            max_depth: Maximum depth for inline chain expansion (prevents infinite loops)
            compress_same_target: Compress chains where all rules have the same target into OR conditions
        """
        self.show_docker_only = show_docker_only
        self.show_rules = show_rules
        self.inline_chains = inline_chains
        self.max_depth = max_depth
        self.compress_same_target = compress_same_target
    
    def format_config(self, config: IptablesConfig) -> str:
        """Format entire configuration as tree"""
        lines = []
        lines.append("📋 iptables Configuration")
        lines.append(f"   Total rules: {config.total_rules}")
        lines.append("")
        
        for table_name, table in sorted(config.tables.items()):
            lines.extend(self._format_table(table, prefix=""))
        
        return "\n".join(lines)
    
    def format_table(self, table: Table) -> str:
        """Format a single table as tree"""
        lines = self._format_table(table, prefix="")
        return "\n".join(lines)
    
    def format_chain(self, chain: Chain, table: Optional[Table] = None) -> str:
        """Format a single chain as tree"""
        if self.inline_chains and table:
            visited = set()
            lines = self._format_chain_inline(chain, prefix="", is_last=True, table=table, visited=visited, depth=0)
        else:
            lines = self._format_chain(chain, prefix="", is_last=True, table=table)
        return "\n".join(lines)
    
    def _format_table(self, table: Table, prefix: str) -> list:
        """Format table with chains"""
        lines = []
        
        # Table header
        lines.append(f"{prefix}📁 Table: {table.name}")
        lines.append(f"{prefix}   Chains: {len(table.chains)}, Rules: {table.total_rules}")
        
        if self.inline_chains:
            # Only show built-in chains at top level, others will be shown inline
            chains = [c for c in table.chains.values() if c.is_builtin]
            if self.show_docker_only:
                chains = [c for c in chains if c.is_docker_chain or c.docker_rules_count > 0]
            chains.sort(key=lambda c: c.name)
            
            # Format each chain with inline expansion
            for i, chain in enumerate(chains):
                is_last = (i == len(chains) - 1)
                visited = set()
                lines.extend(self._format_chain_inline(chain, prefix + "   ", is_last, table, visited, depth=0))
        else:
            # Original behavior: show all chains separately
            chains = list(table.chains.values())
            if self.show_docker_only:
                chains = [c for c in chains if c.is_docker_chain or c.docker_rules_count > 0]
            chains.sort(key=lambda c: (not c.is_builtin, c.name))
            
            for i, chain in enumerate(chains):
                is_last = (i == len(chains) - 1)
                lines.extend(self._format_chain(chain, prefix + "   ", is_last, table))
        
        return lines

    def _format_chain(self, chain: Chain, prefix: str, is_last: bool, table: Optional[Table] = None) -> list:
        """Format chain with rules (non-inline mode)"""
        lines = []
        
        # Chain connector
        connector = "└── " if is_last else "├── "
        continuation = "    " if is_last else "│   "
        
        # Chain icon
        if chain.is_docker_chain:
            icon = "🐋"
        elif chain.is_builtin:
            icon = "⛓️"
        else:
            icon = "🔗"
        
        # Chain header
        policy_str = f" (policy: {chain.policy.value})" if chain.policy else ""
        lines.append(f"{prefix}{connector}{icon} {chain.name}{policy_str}")
        
        # Chain stats (without packet/byte counts)
        stats_parts = [f"{len(chain.rules)} rules"]
        if chain.docker_rules_count > 0:
            stats_parts.append(f"🐳 {chain.docker_rules_count} Docker")
        lines.append(f"{prefix}{continuation}   {', '.join(stats_parts)}")
        
        # Show referenced chains
        if table:
            referenced = chain.get_referenced_chain_names()
            if referenced:
                ref_chains = [name for name in referenced if name in table.chains]
                if ref_chains:
                    lines.append(f"{prefix}{continuation}   → References: {', '.join(ref_chains[:5])}")
        
        # Show rules if enabled - ALL rules, no limits
        if self.show_rules and chain.rules:
            rules_to_show = chain.rules
            if self.show_docker_only:
                rules_to_show = chain.get_docker_rules()
            
            for j, rule in enumerate(rules_to_show):
                is_last_rule = (j == len(rules_to_show) - 1)
                lines.extend(self._format_rule(rule, prefix + continuation, is_last_rule, table=None))
        
        return lines
    
    def _can_compress_chain(self, chain: Chain) -> Tuple[bool, Optional[str], int]:
        """
        Check if a chain can be compressed (consecutive rules with same target).
        
        Returns:
            Tuple of (can_compress, target_name, num_rules_to_compress)
        """
        if not self.compress_same_target or not chain.rules or len(chain.rules) < 2:
            return False, None, 0
        
        # Find the longest sequence of consecutive rules with the same chain target
        # starting from the beginning
        first_target = chain.rules[0].target
        if not chain.rules[0].is_chain_target:
            return False, None, 0
        
        count = 1
        for i in range(1, len(chain.rules)):
            if chain.rules[i].target == first_target and chain.rules[i].is_chain_target:
                count += 1
            else:
                break
        
        # Compress if we have at least 2 consecutive rules with same target
        if count >= 2:
            return True, first_target, count
        
        return False, None, 0
    
    def _format_compressed_chain(self, chain: Chain, target_chain_name: str, num_compressed: int, prefix: str, is_last: bool, table: Table, visited: Set[str], depth: int) -> list:
        """
        Format a chain with compressed rules (consecutive rules with same target) as OR node.
        
        Args:
            num_compressed: Number of rules from the start that are compressed
        """
        lines = []
        
        connector = "└── " if is_last else "├── "
        continuation = "    " if is_last else "│   "
        
        # Chain icon
        if chain.is_docker_chain:
            icon = "🐋"
        elif chain.is_builtin:
            icon = "⛓️"
        else:
            icon = "🔗"
        
        # Show compressed chain header with special icon
        lines.append(f"{prefix}{connector}{icon} {chain.name} 🗜️ (compressed)")
        
        # Chain stats (without packet/byte counts)
        stats_parts = [f"{num_compressed}/{len(chain.rules)} rules → {target_chain_name}"]
        if chain.docker_rules_count > 0:
            stats_parts.append(f"🐳 {chain.docker_rules_count} Docker")
        lines.append(f"{prefix}{continuation}   {', '.join(stats_parts)}")
        
        # Show OR conditions (only the compressed rules) - ALL of them, no limits
        compressed_rules = chain.rules[:num_compressed]
        rules_to_show = compressed_rules
        if self.show_docker_only:
            rules_to_show = [r for r in compressed_rules if r.is_docker_related]
        
        # Build table data for aligned formatting
        table_rows = []
        for rule in rules_to_show:
            # Extract components for table formatting
            container = ""
            port = ""
            interface_in = ""
            interface_out = ""
            
            # Get container name (prefer network name over ID)
            if rule.destination.is_docker_related:
                container = rule.destination.docker_name or rule.destination.original
            elif rule.source.is_docker_related:
                container = rule.source.docker_name or rule.source.original
            
            # Extract port from extra field
            if rule.extra:
                import re
                port_match = re.search(r'dpt:(\d+)', rule.extra)
                if port_match:
                    port = port_match.group(1)
            
            # Get interface info (prefer network name)
            if rule.in_interface.original not in ['*', 'any']:
                if rule.in_interface.is_docker_related and rule.in_interface.docker_name:
                    interface_in = rule.in_interface.docker_name
                else:
                    interface_in = rule.in_interface.original
            
            if rule.out_interface.original not in ['*', 'any']:
                if rule.out_interface.is_docker_related and rule.out_interface.docker_name:
                    interface_out = rule.out_interface.docker_name
                else:
                    interface_out = rule.out_interface.original
            
            # Build condition parts
            condition_parts = []
            if interface_in:
                condition_parts.append(f"in:{interface_in}")
            if interface_out:
                condition_parts.append(f"out:{interface_out}")
            
            condition = ' '.join(condition_parts) if condition_parts else "any"
            
            table_rows.append({
                'condition': condition,
                'container': container,
                'port': port,
                'protocol': rule.prot if rule.prot != '0' else ''
            })
        
        # Calculate column widths
        max_condition = max((len(row['condition']) for row in table_rows), default=0)
        max_container = max((len(row['container']) for row in table_rows), default=0)
        max_protocol = max((len(row['protocol']) for row in table_rows), default=0)
        
        # Display conditions with OR logic as aligned table
        lines.append(f"{prefix}{continuation}   ⚡ Matches if ANY of:")
        for i, row in enumerate(table_rows):
            is_last_condition = (i == len(table_rows) - 1)
            cond_connector = "└── " if is_last_condition else "├── "
            
            # Format row with alignment
            condition_str = row['condition'].ljust(max_condition)
            container_str = row['container'].ljust(max_container) if row['container'] else ''
            protocol_str = row['protocol'].ljust(max_protocol) if row['protocol'] else ''
            port_str = f":{row['port']}" if row['port'] else ''
            
            # Build formatted line
            parts = [condition_str]
            if container_str:
                parts.append(f"🐳 {container_str}")
            if protocol_str:
                parts.append(protocol_str)
            if port_str:
                parts.append(port_str.rjust(6))  # Right-justify port
            
            formatted_line = '  '.join(p for p in parts if p)
            lines.append(f"{prefix}{continuation}   {cond_connector}{formatted_line}")
        
        # Now expand the target chain inline
        if target_chain_name in table.chains:
            target_chain = table.get_chain(target_chain_name)
            lines.append(f"{prefix}{continuation}   ↓ Then forward to:")
            # Recursively format the target chain
            target_lines = self._format_chain_inline(target_chain, prefix + continuation + "   ", True, table, visited, depth + 1)
            lines.extend(target_lines)
        
        # Show remaining rules (non-compressed) if any
        remaining_rules = chain.rules[num_compressed:]
        if remaining_rules:
            lines.append(f"{prefix}{continuation}   🔗 Other rules in {chain.name}:")
            for j, rule in enumerate(remaining_rules):
                is_last_remaining = (j == len(remaining_rules) - 1)
                rule_lines = self._format_rule_inline(rule, prefix + continuation + "   ", is_last_remaining, table, visited, depth)
                lines.extend(rule_lines)
        
        return lines
    
    def _format_chain_inline(self, chain: Chain, prefix: str, is_last: bool, table: Table, visited: Set[str], depth: int) -> list:
        """Format chain with inline expansion of referenced chains"""
        lines = []
        
        # Prevent infinite recursion
        if depth > self.max_depth:
            return lines
        
        # Check if we've already visited this chain in this path
        if chain.name in visited:
            # Show reference but don't expand
            connector = "└── " if is_last else "├── "
            icon = "🔁"  # Circular reference icon
            lines.append(f"{prefix}{connector}{icon} {chain.name} (already shown above)")
            return lines
        
        # Mark as visited for this path
        visited = visited | {chain.name}
        
        # Check if this chain can be compressed
        can_compress, target_name, num_compressed = self._can_compress_chain(chain)
        if can_compress and target_name and num_compressed > 0:
            return self._format_compressed_chain(chain, target_name, num_compressed, prefix, is_last, table, visited, depth)
        
        # Chain connector
        connector = "└── " if is_last else "├── "
        continuation = "    " if is_last else "│   "
        
        # Chain icon
        if chain.is_docker_chain:
            icon = "🐋"
        elif chain.is_builtin:
            icon = "⛓️"
        else:
            icon = "🔗"
        
        # Chain header
        policy_str = f" (policy: {chain.policy.value})" if chain.policy else ""
        lines.append(f"{prefix}{connector}{icon} {chain.name}{policy_str}")
        
        # Chain stats (without packet/byte counts)
        stats_parts = [f"{len(chain.rules)} rules"]
        if chain.docker_rules_count > 0:
            stats_parts.append(f"🐳 {chain.docker_rules_count} Docker")
        lines.append(f"{prefix}{continuation}   {', '.join(stats_parts)}")
        
        # Show rules if enabled - ALL rules, no limits
        if self.show_rules and chain.rules:
            rules_to_show = chain.rules
            if self.show_docker_only:
                rules_to_show = chain.get_docker_rules()
            
            for j, rule in enumerate(rules_to_show):
                is_last_item = (j == len(rules_to_show) - 1)
                lines.extend(self._format_rule_inline(rule, prefix + continuation, is_last_item, table, visited, depth))
        
        return lines
    
    def _format_rule(self, rule: Rule, prefix: str, is_last: bool, table: Optional[Table] = None) -> list:
        """Format a single rule (non-inline mode)"""
        lines = []
        
        connector = "└── " if is_last else "├── "
        
        # Rule icon based on target
        if rule.target == 'ACCEPT':
            icon = "✅"
        elif rule.target == 'DROP':
            icon = "🚫"
        elif rule.target == 'REJECT':
            icon = "⛔"
        elif rule.is_chain_target:
            icon = "➡️"
        else:
            icon = "🔧"
        
        # Docker indicator
        docker_marker = "🐳 " if rule.is_docker_related else ""
        
        # Rule summary
        flow = rule.get_flow_description()
        if flow == "any → any":
            flow = f"{rule.prot}"
        
        summary = f"{docker_marker}{icon} {rule.target}: {flow}"
        lines.append(f"{prefix}{connector}{summary}")
        
        # Rule details
        details = "   "
        if rule.extra:
            details += f"    {rule.extra}"
        if details.strip():
            lines.append(f"{prefix}{'    ' if is_last else '│   '}{details}")
        
        return lines
    
    def _format_rule_inline(self, rule: Rule, prefix: str, is_last: bool, table: Table, visited: Set[str], depth: int) -> list:
        """Format a single rule with inline chain expansion"""
        lines = []
        
        connector = "└── " if is_last else "├── "
        continuation = "    " if is_last else "│   "
        
        # Check if this rule targets a chain
        if rule.is_chain_target and rule.target in table.chains:
            # This is a chain reference - expand it inline
            target_chain = table.get_chain(rule.target)
            
            # Docker indicator
            docker_marker = "🐳 " if rule.is_docker_related else ""
            
            # Rule summary with flow
            flow = rule.get_flow_description()
            if flow == "any → any":
                flow = f"{rule.prot}"
            
            # Show rule details if present
            if rule.extra:
                details_parts = []
                if rule.extra:
                    details_parts.append(rule.extra)
                rule_details = f" [{flow}] [" + " | ".join(details_parts) + "]"
            else:
                rule_details = f" [{flow}]" if flow != rule.prot else ""
            
            # Show the rule with its details before expanding the chain
            connector = "└── " if is_last else "├── "
            icon = "➡️"
            docker_marker = "🐳 " if rule.is_docker_related else ""
            summary = f"{docker_marker}{icon} {rule.target}{rule_details}"
            lines.append(f"{prefix}{connector}{summary}")
            
            # Format the inline chain with rule context
            continuation = "    " if is_last else "│   "
            lines.extend(self._format_chain_inline(target_chain, prefix + continuation, True, table, visited, depth + 1))
            
        else:
            # Terminal rule (ACCEPT, DROP, etc.)
            # Rule icon based on target
            if rule.target == 'ACCEPT':
                icon = "✅"
            elif rule.target == 'DROP':
                icon = "🚫"
            elif rule.target == 'REJECT':
                icon = "⛔"
            else:
                icon = "🔧"
            
            # Docker indicator
            docker_marker = "🐳 " if rule.is_docker_related else ""
            
            # Rule summary
            flow = rule.get_flow_description()
            if flow == "any → any":
                flow = f"{rule.prot}"
            
            summary = f"{docker_marker}{icon} {rule.target}: {flow}"
            
            # Rule details (counters)
            details = f""
            if rule.extra:
                details += f" {rule.extra}"

            lines.append(f"{prefix}{connector}{summary}{details}")

        return lines


def format_tree(
    config: IptablesConfig,
    show_docker_only: bool = False,
    show_rules: bool = True
) -> str:
    """
    Convenience function to format iptables config as tree.
    
    Args:
        config: IptablesConfig to format
        show_docker_only: Only show Docker-related items
        show_rules: Include rules in output
    
    Returns:
        Formatted tree string
    """
    formatter = IptablesTreeFormatter(
        show_docker_only=show_docker_only,
        show_rules=show_rules
    )
    return formatter.format_config(config)


def main():
    """Command-line interface for tree visualization"""
    import argparse
    from src.iptables.parser import load_iptables_config
    
    parser = argparse.ArgumentParser(description='Visualize iptables configuration as tree')
    parser.add_argument(
        '--file', '-f',
        help='Path to iptables output file'
    )
    parser.add_argument(
        '--enrichment', '-e',
        help='Path to Docker enrichment data file'
    )
    parser.add_argument(
        '--table', '-t',
        default='filter',
        help='Table to visualize (default: filter)'
    )
    parser.add_argument(
        '--docker-only', '-d',
        action='store_true',
        help='Show only Docker-related chains and rules'
    )
    parser.add_argument(
        '--no-rules', '-n',
        action='store_true',
        help='Hide rules, show only chains'
    )
    parser.add_argument(
        '--chain', '-c',
        help='Show only a specific chain'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_iptables_config(
            enrichment_file=args.enrichment,
            iptables_file=args.file,
            table=args.table,
            use_sudo=not args.file
        )
    except Exception as e:
        print(f"Error loading iptables configuration: {e}")
        return 1
    
    # Format as tree
    formatter = IptablesTreeFormatter(
        show_docker_only=args.docker_only,
        show_rules=not args.no_rules
    )
    
    if args.chain:
        # Show specific chain
        table = config.get_table(args.table)
        if not table:
            print(f"Table '{args.table}' not found")
            return 1
        
        chain = table.get_chain(args.chain)
        if not chain:
            print(f"Chain '{args.chain}' not found in table '{args.table}'")
            return 1
        
        print(formatter.format_chain(chain, table))
    else:
        # Show full config
        print(formatter.format_config(config))
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
