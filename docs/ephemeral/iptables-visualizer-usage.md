# iptables Visualizer Usage Guide

This guide explains how to use the iptables visualization tools that have been added to the project.

## Overview

The iptables visualizer provides three ways to visualize your firewall rules:

1. **Standalone Python Script** - Generate HTML visualization files
2. **Web Server Endpoint** - View live iptables rules through the web interface
3. **Documentation** - Learn about iptables output format

## 1. Standalone Usage

### Running the Script

The `iptables_visualizer.py` script can be run directly to generate a visualization:

**Simplified view (default - first 5 rules of each type):**
```bash
sudo python3 iptables_visualizer.py
```

**Detailed view (all rules):**
```bash
sudo python3 iptables_visualizer.py --show-all
```

**Custom output file:**
```bash
sudo python3 iptables_visualizer.py -o my_firewall.html
```

This will:
1. Execute `sudo iptables -L -v -n` to get current firewall rules
2. Parse the output into structured data
3. Generate a Mermaid flowchart diagram
4. Create an HTML file (default: `iptables_visualization.html`)

### Opening the Visualization

Simply open the generated HTML file in your web browser:

```bash
firefox iptables_visualization.html
# or
google-chrome iptables_visualization.html
# or
xdg-open iptables_visualization.html
```

### Features of the Visualization

- **Interactive Flowchart**: Shows how packets flow through firewall chains
- **Color-Coded Rules**: Different colors for ACCEPT, DROP, REJECT, LOG, etc.
- **Packet Statistics**: Displays packet counts for active rules
- **Chain Navigation**: Follow jumps between chains with dotted lines
- **Download Option**: Export the diagram as SVG

## 2. Web Server Integration

### Accessing the Endpoint

If you're running the web server (from `web_server.py`), you can access the iptables visualization at:

```
http://your-server:port/api/iptables/visualize
```

For example, if running locally on port 8080:

```
http://localhost:8080/api/iptables/visualize
```

### Authentication

The endpoint respects the same authentication settings as the rest of the web server:
- If OAuth is enabled, you must be authenticated
- If OAuth is disabled, the endpoint is publicly accessible

### Real-Time Updates

Simply refresh the page to see the current state of your firewall rules. The visualization is generated on-demand each time you access the endpoint.

### Viewing All Rules

By default, the visualization shows only the **first 5 ACCEPT rules** and **first 5 DROP/REJECT rules** for each chain to keep the diagram manageable.

To see **all rules**:
1. Check the **"Show All Rules"** checkbox at the top of the page
2. The page will reload and display every single rule
3. Uncheck to return to the simplified view

**Note**: If you have many rules (e.g., 50+ rules per chain), the "Show All" view can be very long. Use it when you need to see specific rules that aren't in the first 5.

## 3. Understanding the Visualization

### Color Legend

- **Blue (Main Chain)**: INPUT, FORWARD, OUTPUT chains
- **Purple (Custom Chain)**: User-defined or tool-created chains (UFW, Docker, etc.)
- **Green (ACCEPT)**: Rules that allow traffic
- **Red (DROP/REJECT)**: Rules that block traffic
- **Orange (LOG)**: Rules that log traffic
- **Gray (RETURN)**: Rules that return to the calling chain
- **Light Blue (JUMP)**: Rules that jump to another chain

### Reading the Diagram

1. **Start at Main Chains**: Begin with INPUT, FORWARD, or OUTPUT
2. **Follow Arrows**: Solid arrows show rule sequence
3. **Dotted Lines**: Show jumps to other chains
4. **Rule Details**: Each node shows:
   - Target action (ACCEPT, DROP, etc.)
   - Protocol (TCP, UDP, ICMP)
   - Source/destination (if specified)
   - Ports (if specified)
   - Packet count (if non-zero)

### Example Flow

```
INPUT Chain
  ↓
Accept loopback traffic
  ↓
Accept established connections
  ↓
Jump to ufw-user-input
  ⋯→ ufw-user-input Chain
      ↓
    Accept port 80 (HTTP)
      ↓
    Accept port 443 (HTTPS)
      ↓
    Return to INPUT
  ↓
Policy: DROP
```

## 4. Documentation

For a detailed explanation of iptables output format, see:

```
docs/iptables-explained.md
```

This document covers:
- How to read `iptables -L -v -n` output
- Understanding chains and policies
- Interpreting packet counters
- Common firewall patterns
- Security best practices

## Troubleshooting

### "iptables command not found"

Install iptables:
```bash
sudo apt-get install iptables  # Debian/Ubuntu
sudo yum install iptables       # RHEL/CentOS
```

### "Permission denied"

The script needs sudo privileges to read iptables rules:
```bash
sudo python3 iptables_visualizer.py
```

### "Module not found" when accessing web endpoint

Ensure `iptables_visualizer.py` is in the same directory as `web_server.py`, or add it to your Python path.

### Diagram not rendering

- Check browser console for JavaScript errors
- Ensure you have internet connection (Mermaid.js loads from CDN)
- Try a different browser

### Empty or incomplete diagram

- Verify iptables rules exist: `sudo iptables -L -v -n`
- Check that the parser can handle your rule format
- Look for error messages in the console/logs

## Advanced Usage

### Customizing the Visualization

You can modify `iptables_visualizer.py` to:

1. **Change colors**: Edit the `_generate_styles()` method
2. **Filter chains**: Modify which chains are included
3. **Adjust layout**: Change Mermaid flowchart options
4. **Add more details**: Extend `_format_rule_description()`

### Integrating with Monitoring

The web endpoint can be embedded in dashboards or monitoring systems:

```html
<iframe src="http://your-server:8080/api/iptables/visualize" 
        width="100%" height="800px"></iframe>
```

### Automated Reports

Generate periodic snapshots:

```bash
#!/bin/bash
# Save daily iptables visualization
DATE=$(date +%Y-%m-%d)
sudo python3 iptables_visualizer.py
mv iptables_visualization.html "iptables_${DATE}.html"
```

## Security Considerations

⚠️ **Important**: The iptables visualization reveals your firewall configuration, which is sensitive security information.

- **Restrict Access**: Use authentication on the web endpoint
- **Don't Share Publicly**: Never post visualizations online
- **Audit Access**: Monitor who views the visualization
- **Use HTTPS**: Encrypt the connection when accessing remotely

## Requirements

- Python 3.6+
- iptables installed on the system
- sudo privileges (for reading iptables rules)
- Modern web browser (for viewing visualizations)
- Internet connection (for Mermaid.js CDN)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review `docs/iptables-explained.md` for iptables basics
3. Examine the source code in `iptables_visualizer.py`
4. Check web server logs for endpoint errors
