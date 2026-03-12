# Rules Format Documentation

Learn how to create, modify, and manage Heimdall IDS rules.

## Table of Contents

- [Rule Basics](#rule-basics)
- [JSON Rules](#json-rules)
- [YAML Rules](#yaml-rules)
- [Field Reference](#field-reference)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Rule Basics

A rule is a detection signature that matches network traffic against criteria:

- **Protocol:** TCP, UDP, ICMP, IP, or "any"
- **Network addresses:** Source and destination IP
- **Ports:** Source and destination port
- **Payload:** Content matching in packet data
- **Priority:** Alert severity (1=critical, 4=informational)

When a packet matches all rule criteria, an alert is generated.

## JSON Rules

JSON is the recommended format for rules.

### Rule File Structure

```json
[
  {
    "id": 100001,
    "rev": 1,
    "enabled": true,
    "action": "alert",
    "msg": "Rule message describing the threat",
    "proto": "tcp",
    "src": "any",
    "src_port": "any",
    "dst": "any",
    "dst_port": 80,
    "content": "suspicious_pattern",
    "priority": 2,
    "classtype": "web-application-attack"
  },
  {
    "id": 100002,
    ...
  }
]
```

### Field Descriptions

| Field       | Type       | Required | Description                                          |
| ----------- | ---------- | -------- | ---------------------------------------------------- |
| `id`        | integer    | Yes      | Unique rule identifier (recommend 100000+)           |
| `rev`       | integer    | No       | Rule revision number (default: 1)                    |
| `enabled`   | boolean    | No       | Enable/disable rule without removing (default: true) |
| `action`    | string     | No       | Action on match: "alert" (default), "log", "drop"    |
| `msg`       | string     | Yes      | Human-readable alert message                         |
| `proto`     | string     | Yes      | Protocol: "tcp", "udp", "icmp", "ip", "any"          |
| `src`       | string     | Yes      | Source IP address or "any"                           |
| `src_port`  | int/string | Yes      | Source port number or "any"                          |
| `dst`       | string     | Yes      | Destination IP address or "any"                      |
| `dst_port`  | int/string | Yes      | Destination port number or "any"                     |
| `content`   | string     | Yes      | Payload content to match (empty string = "any")      |
| `priority`  | integer    | Yes      | Alert priority (1=critical, 2=high, 3=medium, 4=low) |
| `classtype` | string     | No       | Threat classifier (e.g., "web-application-attack")   |

## YAML Rules

Alternatively, use YAML format (requires PyYAML):

```bash
pip install pyyaml
```

### YAML Rule File Structure

```yaml
- id: 100001
  rev: 1
  enabled: true
  action: alert
  msg: "Suspicious pattern detection"
  proto: tcp
  src: any
  src_port: any
  dst: any
  dst_port: 80
  content: "suspicious_content"
  priority: 2
  classtype: "web-application-attack"

- id: 100002
  rev: 1
  enabled: true
  action: alert
  msg: "SSH brute force attempt"
  proto: tcp
  src: any
  src_port: any
  dst: any
  dst_port: 22
  content: ""
  priority: 2
  classtype: "attempted-recon"
```

## Field Reference

### `id` (Required)

Unique identifier for each rule. Use ranges to organize:

- `1000-9999` — Internal/test rules
- `100000+` — Production rules

**Example:**

```json
{
  "id": 100001,
  ...
}
```

### `rev` (Optional)

Revision number when updating a rule. Helps track modifications.

**Example:**

```json
{
  "id": 100001,
  "rev": 3,  // Updated twice
  ...
}
```

### `enabled` (Optional)

Boolean to enable/disable rule without deletion. Default: `true`

**Example:**

```json
{
  "enabled": false,  // Disabled rule
  ...
}
```

### `msg` (Required)

Clear description of what the rule detects. Used in alerts.

**Example:**

```json
{
  "msg": "Potential SQL injection in HTTP POST data",
  ...
}
```

### `proto` (Required)

Network protocol to match:

- `"tcp"` — TCP (Transmission Control Protocol)
- `"udp"` — UDP (User Datagram Protocol)
- `"icmp"` — ICMP (ping, traceroute)
- `"ip"` — Any IP protocol
- `"any"` — Any protocol

**Example:**

```json
{
  "proto": "tcp",
  ...
}
```

### `src` & `dst` (Required)

Source and destination IP addresses:

- `"any"` — Match any IP
- `"192.168.1.100"` — Specific IP
- `"10.0.0.0/8"` — CIDR range (future enhancement)

**Example:**

```json
{
  "src": "any",
  "dst": "192.168.1.50",
  ...
}
```

### `src_port` & `dst_port` (Required)

Source and destination ports:

- `"any"` — Match any port
- `80` or `"80"` — Specific port (0-65535)
- Port ranges (future enhancement)

**Example:**

```json
{
  "src_port": "any",
  "dst_port": 443,  // HTTPS
  ...
}
```

### `content` (Required)

Payload content to match (substring search):

- Empty string `""` — Any payload (port-based detection)
- `"cmd.exe"` — Exact substring match
- Case-insensitive matching

**Example:**

```json
{
  "content": "union select",  // SQL injection
  ...
}
```

### `priority` (Required)

Alert severity level:

- `1` — Critical (exploit, active threat)
- `2` — High (suspicious activity)
- `3` — Medium (policy violation)
- `4` — Low (informational)

**Example:**

```json
{
  "priority": 1,  // Critical
  ...
}
```

### `classtype` (Optional)

Threat category for organization:

- `"web-application-attack"` — Web-based attacks
- `"attempted-recon"` — Reconnaissance
- `"trojan-activity"` — Malware behavior
- `"bad-unknown-traffic"` — Suspicious traffic
- Custom values allowed

**Example:**

```json
{
  "classtype": "web-application-attack",
  ...
}
```

## Examples

### HTTP Web Attack Detection

```json
{
  "id": 100001,
  "rev": 1,
  "enabled": true,
  "action": "alert",
  "msg": "HTTP request contains cmd.exe execution",
  "proto": "tcp",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": 80,
  "content": "cmd.exe",
  "priority": 1,
  "classtype": "web-application-attack"
}
```

### SQL Injection Detection

```json
{
  "id": 100002,
  "rev": 2,
  "enabled": true,
  "action": "alert",
  "msg": "Possible SQL injection - UNION SELECT detected",
  "proto": "tcp",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": 80,
  "content": "union select",
  "priority": 1,
  "classtype": "web-application-attack"
}
```

### SSH Reconnaissance

```json
{
  "id": 100003,
  "rev": 1,
  "enabled": true,
  "action": "alert",
  "msg": "SSH connection attempt - possible brute force",
  "proto": "tcp",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": 22,
  "content": "",
  "priority": 3,
  "classtype": "attempted-recon"
}
```

### HTTPS Traffic Monitoring

```json
{
  "id": 100004,
  "rev": 1,
  "enabled": true,
  "action": "alert",
  "msg": "HTTPS connection to suspicious domain",
  "proto": "tcp",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": 443,
  "content": "",
  "priority": 4,
  "classtype": "suspicious-traffic"
}
```

### ICMP Ping Flood Detection

```json
{
  "id": 100005,
  "rev": 1,
  "enabled": true,
  "action": "alert",
  "msg": "Potential ICMP ping flood",
  "proto": "icmp",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": "any",
  "content": "",
  "priority": 3,
  "classtype": "denial-of-service"
}
```

### DNS Query to Suspicious Domain

```json
{
  "id": 100006,
  "rev": 1,
  "enabled": true,
  "action": "alert",
  "msg": "DNS query for known malware domain",
  "proto": "udp",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": 53,
  "content": "malware-domain.com",
  "priority": 2,
  "classtype": "trojan-activity"
}
```

## Best Practices

### 1. Organize Rules by Category

Group related rules in the same JSON file:

```json
[
  // Web Application Attacks (100000-100099)
  { "id": 100001, "msg": "HTTP attack 1", ... },
  { "id": 100002, "msg": "HTTP attack 2", ... },

  // Reconnaissance (100100-100199)
  { "id": 100101, "msg": "SSH brute force", ... },
  { "id": 100102, "msg": "Port scan", ... }
]
```

### 2. Use Meaningful IDs

- `100000-109999` — Production rules
- `10000-19999` — Organization-specific rules
- `1000-9999` — Test/development rules
- `1-999` — Reserved

### 3. Clear, Descriptive Messages

Include:

- Type of attack
- Protocol/service
- Specific pattern detected

**Good:** `"SQL injection attempt - UNION SELECT in HTTP POST"`  
**Bad:** `"Suspicious traffic"`

### 4. Set Appropriate Priorities

- `priority: 1` → Exploit attempts, active threats only
- `priority: 2` → Suspicious activity, confirmed malware
- `priority: 3` → Policy violations, potential threats
- `priority: 4` → Informational, monitoring only

### 5. Test Rules Before Deployment

```bash
# Test on live interface or PCAP file
python -m heimdall detector --rules rules/rules.json -i eth0 --alert-format json
```

### 6. Avoid Overly Broad Rules

Instead of:

```json
{
  "proto": "any",
  "src": "any",
  "src_port": "any",
  "dst": "any",
  "dst_port": "any",
  "content": "",
  "msg": "Log all traffic"
}
```

Use specific rules:

```json
{
  "proto": "tcp",
  "dst": "any",
  "dst_port": 22,
  "content": "",
  "msg": "Monitor SSH connections"
}
```

### 7. Document Custom Rules

Add comments in YAML format:

```yaml
# HTTP Attacks - IDs 100000-100099
- id: 100001
  rev: 1
  msg: "Custom web shell upload detection"
  # Updated: 2026-03-12 - Added new web shell pattern
  ...
```

## Validation

Rules are validated on load:

- ✅ All required fields present
- ✅ ID is unique
- ✅ Port values are 0-65535
- ✅ Priority is >= 1
- ✅ Protocol is valid
- ✅ ID is integer

**Load rules and check validity:**

```bash
python -m heimdall detector --rules rules/rules.json -i eth0 -n 1
```

Errors will be displayed if validation fails.

## Performance Considerations

- **Rule count:** Each packet is evaluated against all enabled rules (O(n) complexity)
- **Content matching:** Simple substring search is fast but not regex-based
- **Optimization:** Disable unused rules with `"enabled": false`

For high traffic:

1. Disable low-priority rules
2. Use specific protocols/ports
3. Use BPF filters to reduce packet volume

## Future Enhancements

Planned features:

- [ ] Regex pattern support
- [ ] CIDR range matching for IPs
- [ ] Port ranges (e.g., `1024-2048`)
- [ ] Negation operators (e.g., `!22`)
- [ ] Content modifiers (case-insensitive, offset, etc.)
- [ ] Multiple content matching
- [ ] Payload processing (decode, decompress)

---

For questions, check [README.md](README.md) or open an issue on GitHub.
