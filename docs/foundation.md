# Security Scanner Foundation Framework

Documentation for the core security scanner framework that provides common interfaces, shared data models, base patterns, and utilities for all security scanners.

## Overview

The foundation framework establishes consistent patterns and structures that enable all security scanners to be implemented uniformly. This ensures:

- **Consistent Output**: All scanners produce reports in the same format
- **Shared Data Models**: Common Finding, Severity, and Report structures
- **Pattern Framework**: Reusable detection patterns and taint tracking
- **Configuration Standards**: Unified configuration management
- **Extensibility**: Easy to add new scanners following the established patterns

## Quick Start

### For Scanner Developers

1. **Read the Foundation** (`skills/foundation.md`) to understand the data models
2. **Follow the Patterns** - Use the defined interfaces for findings and reports
3. **Implement Your Scanner** - Using the base patterns for detection
4. **Test Against Examples** - Include both dangerous and safe code examples

### For Users

1. **Run a Scan** - Select the appropriate scanner workflow
2. **Review the Report** - JSON output with findings by severity
3. **Apply Fixes** - Use remediation guidance for each finding
4. **Re-scan** - Verify fixes resolve the issues

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AO Security Pack                     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│  │   SQLi      │  │    XSS     │  │   SSRF     │      │
│  │  Scanner    │  │  Scanner    │  │  Scanner   │      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘      │
│         │                │                │             │
│  ┌──────┴────────────────┴────────────────┴──────┐    │
│  │         FOUNDATION FRAMEWORK                    │    │
│  │  ┌─────────────┐  ┌─────────────────────────┐   │    │
│  │  │ Data Models │  │   Pattern Engine        │   │    │
│  │  │ • Finding   │  │   • Regex patterns      │   │    │
│  │  │ • Severity  │  │   • Taint tracking      │   │    │
│  │  │ • Report    │  │   • Data flow           │   │    │
│  │  └─────────────┘  └─────────────────────────┘   │    │
│  │  ┌─────────────┐  ┌─────────────────────────┐   │    │
│  │  │   Config    │  │   Output Formatter      │   │    │
│  │  │   Manager   │  │   • JSON format        │   │    │
│  │  │   • YAML    │  │   • SARIF format       │   │    │
│  │  │   • ENV     │  │   • Exit codes         │   │    │
│  │  └─────────────┘  └─────────────────────────┘   │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## Data Models

### Finding

The core unit of security findings:

```typescript
interface Finding {
  id: string;                    // Unique: SQLI-001, XSS-001
  severity: Severity;           // CRITICAL | HIGH | MEDIUM | LOW | INFO
  title: string;                // Brief title
  description: string;          // Detailed explanation
  
  file: string;                 // File path
  line: number;                 // Line number
  column?: number;              // Column (optional)
  
  snippet: string;              // The problematic code
  context?: string[];           // Surrounding lines
  
  cwe: string;                  // CWE identifier
  owasp?: string;               // OWASP category
  
  remediation: string;           // How to fix
  fix_example?: string;         // Code showing fix
  
  references?: string[];         // Documentation links
  confidence: 'high' | 'medium' | 'low';
  false_positive_risk: 'high' | 'medium' | 'low';
}
```

### SecurityReport

The output structure for scan results:

```typescript
interface SecurityReport {
  schema: string;               // "ao.security.report.v1"
  
  metadata: {
    scanner: string;            // Scanner name
    version: string;            // Scanner version
    generated_at: string;       // ISO timestamp
    scan_duration_ms: number;   // Scan time
    files_scanned: number;      // Total files
    files_affected: number;      // Files with issues
  };
  
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  
  findings: Finding[];
  
  compliance?: {
    owasp_top_10_2021?: Record<string, number>;
    [key: string]: any;
  };
}
```

### Severity Levels

| Level | Numeric | Description | Exit Code |
|-------|---------|-------------|-----------|
| critical | 4 | Trivially exploitable | 10 |
| high | 3 | Easily exploitable | 8 |
| medium | 2 | Conditional exploit | 6 |
| low | 1 | Limited impact | 4 |
| info | 0 | Best practices | 0 |

## Pattern Framework

### Pattern Structure

```typescript
interface Pattern {
  id: string;                   // Unique identifier
  name: string;                // Human-readable name
  severity: Severity;           // Base severity
  
  regex: string;                // Detection pattern
  languages?: string[];        // Applicable languages
  frameworks?: string[];       // Applicable frameworks
  
  examples: {
    dangerous: string[];       // Should match
    safe?: string[];           // Should not match
  };
  
  remediation: string;          // Fix guidance
  cwe?: string;                // CWE reference
  owasp?: string;              // OWASP reference
}
```

### Pattern Categories

1. **Injection Patterns** - SQL, Command, Code injection
2. **XSS Patterns** - DOM manipulation, template injection
3. **Path Patterns** - Directory traversal, file inclusion
4. **Secret Patterns** - Hardcoded credentials, API keys
5. **Config Patterns** - Security misconfigurations

## Configuration

### Standard Configuration

```yaml
scanner:
  targets:
    directories: [src/, lib/, app/]
    extensions: [.ts, .js, .py, .java]
    exclude_patterns:
      - "**/test/**"
      - "**/node_modules/**"
  
  rules:
    severity_threshold: info
    enable_all_rules: true
  
  output:
    format: json
    include_snippets: true
    max_findings: 1000
  
  performance:
    max_file_size_kb: 1024
    parallel_files: 4
    timeout_seconds: 300
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AO_SCANNER_SEVERITY_THRESHOLD` | Minimum severity to report | info |
| `AO_SCANNER_TARGETS` | Directories to scan | src/, lib/ |
| `AO_SCANNER_OUTPUT_FORMAT` | Output format | json |
| `AO_SCANNER_DISABLED_RULES` | Rule IDs to skip | (none) |

## Output Formats

### JSON Output

Standard machine-readable format:

```json
{
  "schema": "ao.security.report.v1",
  "metadata": {
    "scanner": "sqli-scanner",
    "version": "0.1.0",
    "generated_at": "2024-01-15T10:30:00Z",
    "scan_duration_ms": 1234,
    "files_scanned": 156,
    "files_affected": 12
  },
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "info": 0
  },
  "findings": [
    {
      "id": "SQLI-001",
      "severity": "CRITICAL",
      "title": "SQL Injection via User Input",
      "description": "...",
      "file": "src/routes/users.ts",
      "line": 42,
      "snippet": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
      "cwe": "CWE-89",
      "remediation": "Use parameterized queries"
    }
  ]
}
```

### SARIF Output

Standard format for CI/CD tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "ao-security",
        "version": "0.1.0",
        "rules": []
      }
    },
    "results": []
  }]
}
```

## Workflows

### Scan Workflows

| Workflow | Description |
|----------|-------------|
| `ao.security/sqli-scan` | Scan for SQL injection |
| `ao.security/xss-scan` | Scan for XSS vulnerabilities |
| `ao.security/ssrf-scan` | Scan for SSRF vulnerabilities |
| `ao.security/command-injection-scan` | Scan for command injection |
| `ao.security/container-scan` | Scan container configs |
| `ao.security/deserialization-scan` | Scan for unsafe deserialization |

### Scan and Fix Workflows

| Workflow | Description |
|----------|-------------|
| `ao.security/sqli-scan-and-fix` | Scan and remediate SQL injection |
| `ao.security/xss-scan-and-fix` | Scan and remediate XSS |
| `ao.security/scan-and-report` | Run all scanners, generate report |
| `ao.security/full-audit` | Complete security audit |

## Integration

### CI/CD Integration

Add to GitHub Actions:

```yaml
- name: Security Scan
  uses: launchapp-dev/ao-skill-security@v0.1.0
  with:
    scanner: sqli-scan
    severity-threshold: medium
    output-format: sarif
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 4 | Low severity issues |
| 6 | Medium severity issues |
| 8 | High severity issues |
| 10 | Critical severity issues |

## Compliance Mapping

Reports include compliance mapping:

```json
{
  "compliance": {
    "owasp_top_10_2021": {
      "A03:2021 - Injection": 5,
      "A02:2021 - Cryptographic Failures": 2
    },
    "cwe_top_25": {
      "CWE-89": 3,
      "CWE-79": 2
    }
  }
}
```

## Best Practices

### For Scanner Developers

1. **Follow the Data Models** - Use exact interfaces defined in foundation
2. **Test Thoroughly** - Include dangerous AND safe code examples
3. **Document Patterns** - Explain what each pattern detects
4. **Handle Errors Gracefully** - Don't crash on malformed input
5. **Respect Configuration** - Honor file size limits, timeouts
6. **Be Specific** - Minimize false positives with context analysis

### For Report Consumers

1. **Prioritize by Severity** - Fix critical issues first
2. **Review Remediations** - Apply suggested fixes
3. **Check References** - Use linked documentation
4. **Re-scan After Fixes** - Verify issues are resolved
5. **Track Trends** - Monitor findings over time

## Related Documentation

- [SQL Injection Scanner](../skills/sqli-scanner.md)
- [XSS Scanner](../skills/xss-scanner.md)
- [SSRF Scanner](../skills/ssrf-scanner.md)
- [Command Injection Scanner](../skills/command-injection-scanner.md)
- [Container Security Scanner](../skills/container-security-scanner.md)
- [Dependency Auditor](../skills/dependency-auditor.md)
- [Security Report Generator](../skills/security-report.md)
