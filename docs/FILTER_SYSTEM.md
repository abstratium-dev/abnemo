# Filter System Documentation

## Overview

Abnemo provides two types of filters for managing network traffic monitoring:

1. **Accept-List Filters** - Hide matching traffic from the web interface
2. **Warn-List Filters** - Highlight matching traffic and trigger email notifications

## Accept-List Filters

### Purpose
Accept-list filters allow you to hide traffic that matches specific patterns from the web interface. This is useful for:
- Filtering out known-good traffic (e.g., local network traffic)
- Hiding routine connections (e.g., DNS queries, NTP)
- Reducing noise in the monitoring interface

### Behavior
- Traffic matching accept-list patterns is automatically hidden from the web interface
- Accept-list filters use regular expressions to match against:
  - IP addresses
  - Domain names
  - ISP names
  - Port numbers
  - Process names

### Important: Accept-List Takes Precedence
**If traffic matches BOTH the warn-list AND the accept-list, it will NOT trigger email notifications.**

The accept-list acts as a whitelist that overrides warn-list matches. This allows you to:
1. Create broad warn-list patterns for suspicious traffic
2. Use accept-list patterns to exclude known-good traffic that might match the warn-list

## Warn-List Filters

### Purpose
Warn-list filters highlight suspicious or important traffic and trigger email notifications. This is useful for:
- Monitoring connections to known malicious domains
- Tracking unusual port usage
- Alerting on specific process activity

### Behavior
- Traffic matching warn-list patterns is **highlighted** in the web interface
- Email notifications are sent when warn-list traffic is detected
- **Email notifications are NOT sent if the traffic also matches any accept-list filter**

### Email Notification Behavior
When traffic matches a warn-list filter:
1. The system checks if the traffic also matches any accept-list filter
2. If it matches an accept-list filter, **no email is sent**
3. If it does NOT match any accept-list filter, an email notification is sent

This ensures you only receive notifications for traffic that is:
- Suspicious (matches warn-list)
- Not known-good (does not match accept-list)

## Pattern Syntax

Both filter types use regular expressions (regex) for pattern matching.

### Common Pattern Examples

**Match specific IP address:**
```
^192\.168\.1\.100$
```

**Match IP range:**
```
^192\.168\.1\..*
```

**Match domain:**
```
example\.com
```

**Match subdomain:**
```
.*\.example\.com
```

**Match port:**
```
^443$
```

**Match process name:**
```
chrome
```

### Pattern Matching Fields

Patterns are tested against all of the following fields:
- IP address
- Domain name(s)
- ISP name
- Port number(s)
- Process name(s)

If the pattern matches ANY of these fields, the filter applies.

## Configuration Files

Filters are stored in JSON files:
- Accept-list: `accept_list_filters.json`
- Warn-list: `warnlist_filters.json`

Default location: Project root directory
Custom location: Set `ABNEMO_CONFIG_DIR` environment variable

## Email Notification Configuration

To enable email notifications for warn-list matches, configure these environment variables:

```bash
export ABNEMO_SMTP_HOST=smtp.example.com
export ABNEMO_SMTP_PORT=587
export ABNEMO_SMTP_USERNAME=your_username
export ABNEMO_SMTP_PASSWORD=your_password
export ABNEMO_SMTP_FROM=abnemo@example.com
export ABNEMO_SMTP_TO=admin@example.com
export ABNEMO_SMTP_TLS=true
```

## Example Use Cases

### Use Case 1: Monitor External Traffic Only

**Goal:** Hide all local network traffic, only show external connections

**Accept-List Filters:**
```
^192\.168\..*
^10\..*
^172\.(1[6-9]|2[0-9]|3[01])\..*
^127\..*
```

### Use Case 2: Alert on Suspicious Domains, Except Known CDNs

**Warn-List Filter:**
```
(malicious|suspicious|phishing)
```

**Accept-List Filters:**
```
cloudflare\.com
amazonaws\.com
googleusercontent\.com
```

**Result:** You'll be alerted about suspicious domains, but not if they're hosted on known CDN providers.

### Use Case 3: Monitor Specific Port, Except for Trusted IPs

**Warn-List Filter:**
```
^22$
```
(Matches SSH port 22)

**Accept-List Filter:**
```
^203\.0\.113\..*
```
(Matches your trusted IP range)

**Result:** Email notifications for SSH connections, except from your trusted IP range.

## Best Practices

1. **Start with Accept-List**
   - First, create accept-list filters to hide routine traffic
   - This reduces noise and makes warn-list matches more meaningful

2. **Use Specific Patterns**
   - Avoid overly broad patterns that might match unintended traffic
   - Test patterns before deploying

3. **Document Your Filters**
   - Always add descriptions to your filters
   - Explain why the filter was created and what it's meant to catch

4. **Review Regularly**
   - Periodically review your filters
   - Remove outdated filters
   - Update patterns as your network changes

5. **Test Email Notifications**
   - Verify email configuration works before relying on it
   - Use `--log-level DEBUG` to see email sending details

## Troubleshooting

### Emails Not Being Sent

1. Check email configuration environment variables
2. Verify SMTP credentials are correct
3. Check logs with `--log-level DEBUG` to see email sending attempts
4. Ensure traffic matches warn-list but NOT accept-list

### Filter Not Matching Expected Traffic

1. Verify regex pattern syntax
2. Check which fields the pattern is matching against
3. Use the "View Hits" button in the web interface to see what traffic matches
4. Remember: patterns are tested against ALL fields (IP, domain, ISP, ports, processes)

### Accept-List Not Hiding Traffic

1. Check the pattern matches the intended traffic
2. Verify regex pattern syntax is correct
3. Refresh the web interface after adding/modifying filters

## API Endpoints

### Accept-List Filters
- `GET /api/accept-list-filters` - List all accept-list filters
- `POST /api/accept-list-filters` - Create new accept-list filter
- `PUT /api/accept-list-filters/<id>` - Update accept-list filter
- `DELETE /api/accept-list-filters/<id>` - Delete accept-list filter

### Warn-List Filters
- `GET /api/warnlist-filters` - List all warn-list filters
- `POST /api/warnlist-filters` - Create new warn-list filter
- `PUT /api/warnlist-filters/<id>` - Update warn-list filter
- `DELETE /api/warnlist-filters/<id>` - Delete warn-list filter
