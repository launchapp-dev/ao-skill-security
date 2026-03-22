# SSRF (Server-Side Request Forgery) Scanner

Scan source code for Server-Side Request Forgery (SSRF) vulnerabilities, unsanitized URL inputs, and internal resource access attempts using static analysis and pattern detection.

## Overview

This skill performs comprehensive static analysis to detect SSRF vulnerabilities before they reach production. It identifies dangerous URL handling patterns, unsafe external resource fetching, and common security misconfigurations that could lead to SSRF attacks against internal services, cloud metadata endpoints, and sensitive infrastructure.

## Capabilities

- **Pattern Detection**: Identify dangerous URL construction patterns in HTTP requests
- **Input Flow Analysis**: Trace user input to HTTP request operations
- **Metadata Endpoint Detection**: Identify access to cloud provider metadata services
- **Private Network Detection**: Detect access to internal IP ranges and localhost
- **Protocol Injection Detection**: Identify dangerous URL schemes (file://, dict://, gopher://)
- **Framework Detection**: Support for Express, Fastify, NestJS, Django, Flask, Rails, Go net/http
- **Severity Classification**: Rank findings by exploitability and impact
- **Structured Reports**: Output JSON findings with location, severity, and remediation

## Scan Targets

### High Priority
- Direct user input in fetch/axios/requests calls
- User-controlled URLs passed to HTTP client methods
- Access to cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Internal network access attempts (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Protocol injection (file://, dict://, gopher://, sftp://)

### Medium Priority
- Insufficient URL validation or weak allowlists
- Open redirect chains leading to SSRF
- Custom header injection with user input
- Timeout configuration abuse vectors

### Low Priority
- Complex request building patterns (manual review required)
- Third-party library usage patterns
- CDN/image proxy configurations

## Supported Languages

- TypeScript/JavaScript (Node.js) - fetch, axios, node-fetch, got, needle
- Python (requests, urllib, urllib3, httpx)
- Ruby (net/http, faraday, HTTParty)
- Go (net/http, fasthttp, req)
- Java (java.net.http, Apache HttpClient, OkHttp)
- PHP (curl, file_get_contents, Guzzle)

## Detection Patterns

### 1. Direct User Input in HTTP Requests

**JavaScript/TypeScript:**
```javascript
// DANGEROUS
const response = await fetch(req.body.targetUrl);
const result = await axios.get(userProvidedUrl);
const data = await fetch(params.url);

// SAFE - with validation
const allowedDomains = ['trusted.com', 'cdn.example.com'];
const url = new URL(userInput);
if (!allowedDomains.includes(url.hostname)) {
  throw new Error('Invalid domain');
}
const response = await fetch(url.toString());
```

**Python:**
```python
# DANGEROUS
response = requests.get(user_provided_url)
data = urllib.request.urlopen(req.form['url'])

# SAFE - with validation
ALLOWED_HOSTS = ['api.trusted.com', 'cdn.example.com']
parsed = urlparse(user_input)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError('Invalid domain')
response = requests.get(user_input, timeout=5)
```

### 2. Cloud Metadata Endpoint Access

**JavaScript/TypeScript:**
```javascript
// DANGEROUS - AWS metadata access
const metadata = await fetch('http://169.254.169.254/latest/meta-data/');

// DANGEROUS - GCP metadata access
const project = await fetch('http://metadata.google.internal/computeMetadata/v1/project/project-id');

// SAFE - block metadata endpoints
const BLOCKED_HOSTS = [
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.azure.com'
];
```

### 3. Internal Network Access

```javascript
// DANGEROUS - internal service access
await fetch('http://10.0.0.5:6379/'); // Redis
await fetch('http://192.168.1.100:9200/'); // Elasticsearch
await fetch('http://localhost:5432/'); // PostgreSQL
await fetch('http://127.0.0.1:2375/'); // Docker API

// DANGEROUS - private IP ranges
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
await fetch(`http://${attackerControlledIP}/`);
```

### 4. Protocol Injection

```javascript
// DANGEROUS - file protocol
await fetch('file:///etc/passwd');

// DANGEROUS - dict protocol (Redis)
await fetch('dict://localhost:11211/stats');

// DANGEROUS - gopher protocol
await fetch('gopher://localhost:6379/_INFO');

// DANGEROUS - sftp protocol
await fetch('sftp://attacker.com/data');
```

### 5. URL Parsing Confusion

```javascript
// DANGEROUS - URL parsing confusion attacks
await fetch('http://trusted.com@evil.com/');
await fetch('http://trusted.com.evil.com/');
await fetch('http://169.254.169.254?.trusted.com/');

// SAFE - proper URL validation
const validateUrl = (input) => {
  try {
    const url = new URL(input);
    // Block internal and dangerous hosts
    if (url.hostname === 'localhost' || 
        url.hostname.startsWith('169.254.') ||
        PRIVATE_IP_REGEX.test(url.hostname)) {
      throw new Error('Invalid hostname');
    }
    // Block dangerous protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('Invalid protocol');
    }
    return true;
  } catch {
    return false;
  }
};
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct user input in HTTP request, access to metadata endpoints | `fetch(req.body.url)` |
| **CRITICAL** | Protocol injection (file://, dict://, gopher://) | `fetch('file:///etc/passwd')` |
| **HIGH** | Internal IP/private network access | `fetch('http://10.0.0.5:6379/')` |
| **HIGH** | URL parsing confusion bypass | `http://trusted.com@evil.com/` |
| **MEDIUM** | Weak or missing URL validation | Allowlist without scheme check |
| **LOW** | Complex patterns requiring manual review | Redirect following chains |
| **INFO** | Best practice suggestions | Missing timeout configuration |

## Output Format

```json
{
  "findings": [
    {
      "id": "SSRF-001",
      "severity": "CRITICAL",
      "title": "SSRF via User-Controlled URL",
      "description": "Direct use of req.query.url in fetch() call allows attacker to make requests to internal services or external targets. This could lead to access to cloud metadata, internal databases, or exfiltration of sensitive data.",
      "file": "src/services/image-resolver.ts",
      "line": 45,
      "column": 18,
      "snippet": "const response = await fetch(req.query.url);",
      "cwe": "CWE-918",
      "owasp": "A10:2021 - Server-Side Request Forgery",
      "remediation": "Implement URL allowlist validation: const allowedDomains = ['trusted.com']; const url = new URL(req.query.url); if (!allowedDomains.includes(url.hostname)) throw new Error('Invalid domain');",
      "references": [
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://portswigger.net/web-security/ssrf"
      ]
    },
    {
      "id": "SSRF-002",
      "severity": "CRITICAL",
      "title": "AWS Metadata Endpoint Access",
      "description": "Code attempts to access AWS EC2 metadata service which contains sensitive credentials. Attackers can exploit SSRF to steal IAM role credentials.",
      "file": "src/lib/aws-client.ts",
      "line": 23,
      "column": 27,
      "snippet": "const token = await fetch('http://169.254.169.254/latest/api/token');",
      "cwe": "CWE-918",
      "owasp": "A10:2021 - Server-Side Request Forgery",
      "remediation": "Remove metadata access code. If required, validate and restrict access to known EC2 instances only.",
      "references": [
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
        "https:// Rhino Security Labs Blog - EC2 Metadata SSRF"
      ]
    }
  ],
  "summary": {
    "total": 5,
    "critical": 2,
    "high": 1,
    "medium": 1,
    "low": 1,
    "info": 0
  },
  "scanned_files": 127,
  "scan_duration_ms": 2340
}
```

## Execution Steps

1. **Initialize Scanner**
   - Load language-specific pattern matchers
   - Configure target directories and file extensions
   - Set up URL validation rule sets
   - Define blocked hosts and protocols

2. **File Discovery**
   - Scan source directories for relevant files
   - Filter by language (ts, js, py, rb, go, java, php)
   - Skip test files, node_modules, vendor directories

3. **Pattern Analysis**
   - Parse source files into AST (when possible)
   - Run regex patterns for quick detection
   - Track variable assignments and data flow
   - Identify HTTP request construction patterns

4. **Vulnerability Detection**
   - Identify HTTP request patterns with user input
   - Trace user input sources to request sinks
   - Check for URL validation/sanitization
   - Identify internal endpoint access patterns
   - Validate parameterization in URL construction

5. **Severity Assignment**
   - Evaluate exploitability based on context
   - Consider authentication requirements
   - Assess target sensitivity and impact
   - Check for known exploitation vectors

6. **Generate Report**
   - Compile findings with metadata
   - Include code snippets and line numbers
   - Provide actionable remediation guidance
   - Categorize by severity

## Configuration

```yaml
ssrf_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - app
    - server
  
  exclude_patterns:
    - "**/*.test.{ts,js}"
    - "**/*.spec.{ts,js}"
    - "**/__tests__/**"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
  
  # Severity thresholds
  fail_on:
    - critical
    - high
  
  # Blocked patterns
  blocked_hosts:
    - "169.254.169.254"       # AWS metadata
    - "metadata.google.internal"  # GCP metadata
    - "metadata.azure.com"    # Azure metadata
    - "localhost"
    - "127.0.0.1"
    - "::1"
  
  blocked_protocols:
    - "file://"
    - "dict://"
    - "gopher://"
    - "sftp://"
    - "ldap://"
  
  blocked_ip_ranges:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "0.0.0.0/8"
    - "100.64.0.0/10"
    - "169.254.0.0/16"
  
  # Language-specific settings
  languages:
    typescript:
      enabled: true
      http_methods:
        - fetch
        - axios
        - node-fetch
        - got
        - needle
        - superagent
    javascript:
      enabled: true
    python:
      enabled: true
      http_methods:
        - requests.get
        - requests.post
        - urllib.request.urlopen
        - httpx.get
        - httpx.post
  
  # Custom patterns (regex)
  custom_patterns:
    - pattern: "fetch\\([^)]*\\+"
      severity: critical
      message: "String concatenation detected in fetch URL"
    - pattern: "requests\\.(get|post)\\([^)]*%"
      severity: critical
      message: "String formatting detected in requests URL"
```

## Integration

### With AO Workflow

```yaml
phases:
  ssrf-scan:
    mode: agent
    agent: ao.security.ssrf-scanner
    directive: "Scan codebase for SSRF vulnerabilities"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run SSRF scan before commit
ao skill run ao.security/ssrf-scan --staged
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: SSRF Scan
  run: ao skill run ao.security/ssrf-scan --output json > ssrf-report.json
  
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: ssrf-report
    path: ssrf-report.json
```

## Remediation Checklist

1. **URL Allowlisting**
   - [ ] Define explicit allowlist of permitted domains/IPs
   - [ ] Validate against allowlist before making requests
   - [ ] Support wildcards with caution and logging

2. **Input Validation**
   - [ ] Parse and validate all URL components
   - [ ] Block dangerous schemes (file://, dict://, gopher://)
   - [ ] Block internal IP ranges
   - [ ] Block cloud metadata endpoints

3. **Safe URL Construction**
   - [ ] Use URL parsers instead of string concatenation
   - [ ] Validate host after parsing
   - [ ] Reject URLs with credentials or unusual ports

4. **Request Restrictions**
   - [ ] Set reasonable timeouts
   - [ ] Limit response size
   - [ ] Disable redirect following for untrusted URLs
   - [ ] Use dedicated network interfaces

5. **Response Handling**
   - [ ] Validate response Content-Type
   - [ ] Sanitize displayed content
   - [ ] Log all outbound requests

## Best Practices

1. **Never Trust User Input**: Always validate and sanitize any URL provided by users
2. **Use Allowlists**: Prefer allowlists over blocklists for URL validation
3. **Parse Before Use**: Use URL parsing libraries to extract and validate components
4. **Block Dangerous Endpoints**: Prevent access to cloud metadata and internal services
5. **Apply Network Segmentation**: Isolate request-forwarding services from sensitive infrastructure
6. **Log Everything**: Monitor and log all outbound requests for forensic analysis
7. **Defense in Depth**: Implement multiple layers of validation and restriction

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [AWS SSRF Prevention](https://aws.amazon.com/blogs/security/defense-in-depth-design-for-mitigating-ssrf/)
- [PortSwigger SSRF Filter Bypass](https://portswigger.net/web-security/ssrf/blind)
- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [HackerOne SSRF Bible](https://github.com/cujanovic/SSRF-Testing)
