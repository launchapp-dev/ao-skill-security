# Security Scanner Foundation Framework

Core framework providing common interfaces, shared data models, base patterns, output formatting utilities, and configuration management for all security scanners in this pack.

## Overview

This foundation establishes consistent patterns, data structures, and utilities that enable all security scanners to be implemented uniformly. Scanners should inherit from these patterns to ensure consistent behavior, output formats, and extensibility.

## Shared Data Models

### Severity Levels

All scanners MUST use these severity levels consistently:

| Level | Numeric Value | Description | Exit Code Contribution |
|-------|---------------|-------------|------------------------|
| `critical` | 4 | Trivially exploitable with severe impact | 10 |
| `high` | 3 | Easily exploitable with significant impact | 8 |
| `medium` | 2 | Exploitable under specific conditions | 6 |
| `low` | 1 | Limited exploitability | 4 |
| `info` | 0 | Informational, best practices | 0 |

### Finding Model

Every security finding MUST include these fields:

```typescript
interface Finding {
  // Required fields
  id: string;                    // Unique ID: SCANNER-001 (e.g., SQLI-001, XSS-001)
  severity: Severity;            // CRITICAL | HIGH | MEDIUM | LOW | INFO
  title: string;                // Brief title describing the finding
  description: string;           // Detailed explanation of the vulnerability
  
  // Location
  file: string;                  // Relative path to the affected file
  line: number;                 // Line number where the issue occurs
  column?: number;              // Optional column number
  
  // Code context
  snippet: string;               // The problematic code line
  context?: string[];           // Lines before/after for context
  
  // Classification
  cwe: string;                  // CWE identifier (e.g., "CWE-89")
  owasp?: string;               // OWASP category (e.g., "A03:2021 - Injection")
  
  // Remediation
  remediation: string;           // How to fix the issue
  fix_example?: string;         // Code showing the fix
  
  // References
  references?: string[];         // Links to documentation, advisories
  
  // Metadata
  confidence: 'high' | 'medium' | 'low';  // Detection confidence
  false_positive_risk: 'high' | 'medium' | 'low';  // Likelihood of FP
}
```

### Scan Report Model

Every scanner output MUST include this structure:

```typescript
interface SecurityReport {
  // Schema version
  schema: string;               // "ao.security.report.v1"
  
  // Metadata
  metadata: {
    scanner: string;            // Scanner identifier (e.g., "sqli-scanner")
    version: string;            // Scanner version
    generated_at: string;       // ISO 8601 timestamp
    scan_duration_ms: number;   // Time taken for scan
    files_scanned: number;      // Total files analyzed
    files_affected: number;     // Files with findings
  };
  
  // Summary statistics
  summary: {
    total: number;              // Total findings count
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    by_category?: Record<string, number>;  // Findings by type
    by_file?: Record<string, number>;      // Findings by file
  };
  
  // Detailed findings
  findings: Finding[];
  
  // Compliance mapping (optional)
  compliance?: {
    owasp_top_10_2021?: Record<string, number>;
    cwe_top_25?: Record<string, number>;
    [key: string]: Record<string, number> | undefined;
  };
  
  // Configuration used
  config?: {
    rules_enabled: string[];
    rules_disabled: string[];
    custom_patterns?: string[];
  };
}
```

### Configuration Model

Scanner configuration follows this structure:

```typescript
interface ScannerConfig {
  // Scanning scope
  targets: {
    directories: string[];      // Directories to scan
    extensions: string[];       // File extensions to analyze
    exclude_patterns: string[];  // Glob patterns to exclude
  };
  
  // Rules
  rules: {
    enabled: string[];          // Rule IDs to enable
    disabled: string[];         // Rule IDs to disable
    severity_threshold: Severity;  // Minimum severity to report
  };
  
  // Output
  output: {
    format: 'json' | 'sarif' | 'both';
    include_snippets: boolean;
    include_fix_examples: boolean;
    max_findings: number;       // Cap on findings per scan
  };
  
  // Performance
  performance: {
    max_file_size_kb: number;
    parallel_files: number;
    timeout_seconds: number;
  };
}
```

## Base Scanner Interface

All scanners MUST implement this interface:

```typescript
interface BaseScanner {
  // Initialization
  initialize(config: ScannerConfig): Promise<void>;
  
  // Scanning
  scan(targets: string[]): Promise<SecurityReport>;
  scanFile(filePath: string): Promise<Finding[]>;
  
  // Analysis
  analyzeContent(content: string, filePath: string): Finding[];
  detectLanguage(filePath: string): string | null;
  
  // Pattern matching
  matchPatterns(content: string, patterns: Pattern[]): PatternMatch[];
  
  // Utilities
  calculateSeverity(vulnerability: VulnerabilityContext): Severity;
  generateFindingId(): string;
  formatReport(findings: Finding[]): SecurityReport;
}

interface Pattern {
  id: string;                   // Unique pattern identifier
  name: string;                 // Human-readable name
  severity: Severity;           // Base severity for matches
  description: string;         // What this pattern detects
  
  // Detection
  regex: string;                // Regex pattern to match
  languages?: string[];         // Applicable languages
  frameworks?: string[];       // Applicable frameworks
  
  // Context requirements
  requires_taint_tracking?: boolean;
  requires_data_flow?: boolean;
  
  // Examples
  examples: {
    dangerous: string[];        // Code that matches
    safe?: string[];            // Code that shouldn't match
  };
  
  // Remediation
  remediation: string;
  fix_example?: string;
  cwe?: string;
  owasp?: string;
}
```

## Output Formatting Utilities

### JSON Output Format

All scanners MUST produce valid JSON:

```json
{
  "schema": "ao.security.report.v1",
  "metadata": {
    "scanner": "scanner-name",
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
  "findings": []
}
```

### SARIF Output Format

For CI/CD integration, scanners SHOULD also support SARIF 2.1.0:

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

### Severity to SARIF Level Mapping

| Severity | SARIF Level |
|----------|-------------|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | none |

## Pattern Matching Framework

### Pattern Definition Format

Patterns should be defined in a consistent format:

```typescript
// Example pattern definition
const PATTERNS = [
  {
    id: "SQLI-001",
    name: "SQL String Concatenation",
    severity: "CRITICAL",
    description: "User input concatenated directly into SQL query",
    regex: /\b(?:query|execute|select|insert|update|delete).*[\+\`].*\$/gi,
    languages: ["javascript", "typescript", "python", "java"],
    examples: {
      dangerous: [
        "db.query(`SELECT * FROM users WHERE id = ${id}`)",
        "cursor.execute(\"SELECT * FROM users WHERE id = \" + id)"
      ]
    },
    remediation: "Use parameterized queries instead of string concatenation",
    fix_example: "db.query('SELECT * FROM users WHERE id = ?', [id])",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection"
  }
];
```

### Pattern Matching Rules

1. **Multi-pass Analysis**: Run patterns from high severity to low
2. **Context Awareness**: Consider surrounding code for false positive reduction
3. **Safe Pattern Exclusion**: Skip matches that are inside safe contexts (parameterized queries)
4. **Duplicate Detection**: Avoid reporting same issue multiple times
5. **Confidence Scoring**: Rate matches based on context quality

### Taint Tracking

For advanced scanners, track data flow:

```typescript
interface DataFlow {
  source: {
    type: 'user_input' | 'file' | 'environment' | 'config';
    location: string;  // e.g., "req.params.id", "process.env.SECRET"
  };
  sinks: {
    type: 'sql' | 'command' | 'file' | 'eval' | 'html';
    location: string;   // File and line of sink
  };
  sanitizers?: string[];  // Known sanitization functions
  validators?: string[];  // Known validation functions
  path: string[];         // Intermediate steps
}
```

## Configuration Management

### Default Configuration

```yaml
# Scanner defaults
scanner:
  version: "0.1.0"
  
  # Scan targets
  targets:
    directories:
      - src/
      - lib/
      - app/
    extensions:
      - .ts
      - .js
      - .py
      - .java
      - .go
      - .rb
      - .php
    exclude_patterns:
      - "**/node_modules/**"
      - "**/vendor/**"
      - "**/test/**"
      - "**/__tests__/**"
      - "**/*.test.*"
      - "**/*.spec.*"
      - "**/dist/**"
      - "**/build/**"
      - "**/.git/**"
  
  # Rules
  rules:
    severity_threshold: "info"
    enable_all_rules: true
  
  # Output
  output:
    format: "json"
    include_snippets: true
    include_fix_examples: true
    max_findings: 1000
  
  # Performance
  performance:
    max_file_size_kb: 1024
    parallel_files: 4
    timeout_seconds: 300
```

### Environment-based Configuration

Scanners SHOULD support environment variable overrides:

```bash
# Override severity threshold
AO_SCANNER_SEVERITY_THRESHOLD=high

# Override target directories
AO_SCANNER_TARGETS=src/:lib/

# Disable specific rules
AO_SCANNER_DISABLED_RULES=SQLI-002,XSS-003

# Set output format
AO_SCANNER_OUTPUT_FORMAT=sarif
```

## Common Patterns for All Scanners

### Input Source Detection

All scanners should recognize these common user input sources:

```typescript
const USER_INPUT_SOURCES = {
  javascript: {
    express: ['req.params', 'req.query', 'req.body', 'req.headers', 'req.cookies'],
    koa: ['ctx.params', 'ctx.query', 'ctx.request.body', 'ctx.headers'],
    generic: ['process.argv', 'process.env', 'readline']
  },
  python: {
    django: ['request.GET', 'request.POST', 'request.body', 'request.COOKIES'],
    flask: ['request.args', 'request.form', 'request.json', 'request.data'],
    fastapi: ['request.path_params', 'request.query_params', 'request.body'],
    generic: ['sys.argv', 'os.environ']
  },
  java: {
    servlet: ['request.getParameter', 'request.getHeader', 'request.getInputStream'],
    spring: ['@RequestParam', '@RequestBody', '@PathVariable', '@RequestHeader']
  }
};
```

### Dangerous Sink Patterns

All scanners should track these dangerous sinks:

```typescript
const DANGEROUS_SINKS = {
  sql: [
    'query(', 'execute(', 'select(', 'insert(', 'update(', 'delete(',
    'raw(', 'cursor.execute', 'connection.execute', 'Statement.execute'
  ],
  command: [
    'exec(', 'system(', 'popen(', 'spawn(', 'execFile(',
    'subprocess.run', 'subprocess.Popen', 'Runtime.exec',
    'ProcessBuilder', 'shell.exec'
  ],
  file: [
    'readFile(', 'writeFile(', 'open(', 'fopen(',
    'FileInputStream', 'FileOutputStream', 'createWriteStream'
  ],
  eval: [
    'eval(', 'Function(', 'setTimeout(', 'setInterval(',
    '__import__(\'os\')', 'exec(', 'compile('
  ],
  html: [
    'innerHTML', 'outerHTML', 'insertAdjacentHTML',
    'dangerouslySetInnerHTML', 'v-html', 'html_safe'
  ]
};
```

### Sanitization Functions

Known safe sanitization patterns:

```typescript
const SANITIZERS = {
  sql: [
    'param', 'bind', 'escape', 'quote',
    'preparedStatement', 'parameterized'
  ],
  command: [
    'escapeShellArg', 'escapeShellCmd', 'Shellwords.escape',
    'spawn', 'execFile', 'list argument form'
  ],
  html: [
    'DOMPurify.sanitize', 'sanitize-html', 'bleach.clean',
    'textContent', 'innerText', '{{variable}}'  // Template escaping
  ],
  path: [
    'path.resolve', 'path.normalize', 'realpath',
    'Path.resolve', 'Path.normalize'
  ]
};
```

## Implementation Checklist

When implementing a new scanner, ensure:

- [ ] **Data Models**: Implement Finding and Report interfaces exactly as specified
- [ ] **Severity Mapping**: Use the defined severity levels consistently
- [ ] **ID Generation**: Use scanner-prefixed IDs (e.g., SQLI-001, XSS-001)
- [ ] **Output Format**: Generate valid JSON matching the report schema
- [ ] **Pattern Format**: Define patterns using the standard pattern format
- [ ] **Configuration**: Support the standard configuration structure
- [ ] **Error Handling**: Gracefully handle parse errors, missing files, timeouts
- [ ] **Performance**: Respect file size limits and parallelization settings
- [ ] **Documentation**: Document all patterns, rules, and exceptions
- [ ] **Tests**: Include test cases for patterns (both dangerous and safe examples)

## CWE References

Common CWEs for security scanners:

| CWE | Name | Scanners |
|-----|------|----------|
| CWE-78 | OS Command Injection | command-injection, sql |
| CWE-79 | Cross-site Scripting | xss |
| CWE-89 | SQL Injection | sqli |
| CWE-90 | LDAP Injection | sqli |
| CWE-91 | XML Injection | sqli |
| CWE-94 | Code Injection | command-injection, deserialization |
| CWE-502 | Deserialization of Untrusted Data | deserialization |
| CWE-601 | Open Redirect | ssrf |
| CWE-918 | Server-Side Request Forgery | ssrf |
| CWE-798 | Use of Hard-coded Credentials | hardcoded-secrets |
| CWE-259 | Hard-coded Password | hardcoded-secrets |

## OWASP Top 10 2021 Mapping

| Category | Description | Relevant Scanners |
|----------|-------------|------------------|
| A01:2021 | Broken Access Control | hardcoded-secrets, container |
| A02:2021 | Cryptographic Failures | hardcoded-secrets |
| A03:2021 | Injection | sqli, xss, command-injection |
| A04:2021 | Insecure Design | all scanners |
| A05:2021 | Security Misconfiguration | container |
| A06:2021 | Vulnerable Components | dependency-auditor |
| A07:2021 | Auth Failures | hardcoded-secrets |
| A08:2021 | Software Integrity Failures | deserialization |
| A09:2021 | Security Logging Failures | all scanners |
| A10:2021 | SSRF | ssrf |

## Exit Codes

Scanners SHOULD return appropriate exit codes:

| Exit Code | Meaning | Trigger |
|-----------|---------|---------|
| 0 | Success, no issues | No findings at or above threshold |
| 4 | Low severity issues | Low severity findings only |
| 6 | Medium severity issues | Medium+ severity findings |
| 8 | High severity issues | High+ severity findings |
| 10 | Critical severity issues | Critical severity findings present |

Exit code is the maximum severity level found.
