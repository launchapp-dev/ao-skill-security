# Command Injection Scanner Documentation

## Overview

The Command Injection Scanner is a static analysis tool that detects OS command injection vulnerabilities in source code before they reach production. It identifies dangerous shell command construction patterns, unsafe subprocess calls, and other misconfigurations that could lead to command injection attacks.

Command injection allows attackers to execute arbitrary operating system commands on the host server, potentially gaining full system access, exfiltrating data, or compromising the entire infrastructure.

## Installation

The Command Injection Scanner is included in the `ao.security` skill pack. To use it:

```bash
# Install the skill pack
ao skill install ao.security

# Run command injection scan
ao workflow run ao.security/command-injection-scan
```

## Quick Start

### Basic Scan

```bash
# Scan current directory for command injection vulnerabilities
ao workflow run ao.security/command-injection-scan

# Scan specific directory
ao workflow run ao.security/command-injection-scan --input '{"path": "src/api"}'
```

### Scan and Fix

```bash
# Scan for vulnerabilities and automatically create fix tasks
ao workflow run ao.security/command-injection-scan-and-fix
```

## Detection Capabilities

### 1. Python subprocess with shell=True

Detects dangerous subprocess patterns:

```python
# ❌ DETECTED - shell=True with f-string
subprocess.run(f"ls -la {user_input}", shell=True)

# ❌ DETECTED - String concatenation with shell=True
subprocess.Popen("cat " + filename, shell=True)

# ✅ SAFE - List arguments without shell
subprocess.run(["ls", "-la", user_input])

# ✅ SAFE - shell=True with shlex.quote
subprocess.run(f"ls -la {shlex.quote(user_input)}", shell=True)
```

### 2. Node.js child_process.exec()

Detects shell injection in Node.js:

```javascript
// ❌ DETECTED - Template literal with user input
exec(`cat ${filename}`);
exec(`ping -c 1 ${host}`);

// ❌ DETECTED - String concatenation
exec("grep " + query);

// ✅ SAFE - execFile with array arguments
execFile('cat', [filename]);

// ✅ SAFE - spawn with array arguments
spawn('grep', ['-r', query, '.']);
```

### 3. Java Runtime.exec()

Detects unsafe command execution in Java:

```java
// ❌ DETECTED - String concatenation
Process p = Runtime.getRuntime().exec("cat " + filename);

// ✅ SAFE - Array of arguments
Process p = Runtime.getRuntime().exec(new String[]{"cat", filename});

// ✅ SAFE - ProcessBuilder
ProcessBuilder pb = new ProcessBuilder("cat", filename);
```

### 4. Ruby system and exec

Detects command injection in Ruby:

```ruby
# ❌ DETECTED - String interpolation
system("ls -la #{user_input}")
output = `cat #{filename}`

# ✅ SAFE - Separate arguments
system("ls", "-la", user_input)

# ✅ SAFE - Shellwords.escape
system("ls #{Shellwords.escape(user_input)}")
```

### 5. PHP exec functions

Detects command injection in PHP:

```php
<?php
// ❌ DETECTED - String interpolation
exec("ls -la $user_input");
system("cat $filename");

// ✅ SAFE - escapeshellarg
exec("ls -la " . escapeshellarg($user_input));

// ✅ SAFE - escapeshellcmd
system("cat " . escapeshellcmd($filename));
```

## Supported Languages & Frameworks

| Language | Dangerous Functions | Safe Alternatives |
|----------|-------------------|-------------------|
| Python | subprocess(shell=True), os.system, os.popen, exec | subprocess.run(args=[]), subprocess.run(args=[], shell=False), pathlib |
| JavaScript/TypeScript | exec, execSync, `backticks` | execFile, execFileSync, spawn, child_process.spawn |
| Ruby | system, exec, `` ` ``, %x | system(cmd, *args), Shellwords.escape |
| Java | Runtime.exec(String), ProcessBuilder with String | Runtime.exec(String[]), ProcessBuilder(args) |
| PHP | exec, shell_exec, system, passthru, popen, proc_open | escapeshellarg, escapeshellcmd |
| Go | exec.Command("bash", "-c", str) | exec.Command("cmd", "arg1", "arg2") |

## Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | subprocess(shell=True) with string formatting, exec() with interpolation | `subprocess.run(f"ls {input}", shell=True)` |
| **CRITICAL** | Direct user input in shell commands | `exec("cat " + filename)` |
| **HIGH** | os.system, Runtime.exec with concatenation | `os.system("rm " + path)` |
| **HIGH** | child_process.exec with template literals | `exec(\`ping ${host}\`)` |
| **MEDIUM** | Partial sanitization or weak validation | `system("ls " + shellescape(user))` |
| **LOW** | Patterns requiring manual review | Dynamic command with strict validation |
| **INFO** | Best practice suggestions | Use execFile over exec |

## Output Format

### JSON Report

```json
{
  "findings": [
    {
      "id": "CMDI-001",
      "severity": "CRITICAL",
      "title": "Command Injection via subprocess with shell=True",
      "description": "subprocess.run() called with shell=True and string formatting allows arbitrary command execution.",
      "file": "src/utils/file_handler.py",
      "line": 42,
      "column": 18,
      "snippet": "subprocess.run(f\"cat {filename}\", shell=True)",
      "cwe": "CWE-78",
      "owasp": "A03:2021 - Injection",
      "remediation": "Use subprocess.run(['cat', filename]) instead",
      "references": [
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html"
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

### Console Output

```
Command Injection Scan Results
==============================

Scanned 127 files in 2.34s

Findings by Severity:
  🔴 CRITICAL: 2
  🟠 HIGH:     1
  🟡 MEDIUM:   1
  🟢 LOW:      1
  ℹ️  INFO:     0

CRITICAL Findings:
------------------

[CMDI-001] Command Injection via subprocess with shell=True
  File: src/utils/file_handler.py:42:18
  Code: subprocess.run(f"cat {filename}", shell=True)
  
  Remediation:
    Use subprocess.run with list arguments:
    subprocess.run(['cat', filename])
  
  References:
    • https://owasp.org/www-community/attacks/Command_Injection
    • https://cwe.mitre.org/data/definitions/78.html
```

## Configuration

Create a `.ao/security.yaml` file to customize scanning:

```yaml
command_injection_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - api
    - server
  
  # Exclude patterns
  exclude_patterns:
    - "**/*.test.{py,js,ts}"
    - "**/*.spec.{py,js,ts}"
    - "**/node_modules/**"
    - "**/__tests__/**"
    - "**/migrations/**"
  
  # Fail CI on these severities
  fail_on:
    - critical
    - high
  
  # Language-specific settings
  languages:
    python:
      enabled: true
    javascript:
      enabled: true
    ruby:
      enabled: true
    java:
      enabled: true
    php:
      enabled: true
  
  # Custom detection patterns
  custom_patterns:
    - pattern: "subprocess\\..*shell=True.*\\+"
      severity: critical
      message: "String concatenation with shell=True detected"
```

## Integration

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run command injection scan on staged files
ao workflow run ao.security/command-injection-scan --staged

# Check exit code
if [ $? -ne 0 ]; then
  echo "Command injection vulnerabilities detected. Please fix before committing."
  exit 1
fi
```

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  command-injection-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup AO
        run: |
          curl -fsSL https://get.ao.dev | sh
          
      - name: Run Command Injection Scan
        run: |
          ao workflow run ao.security/command-injection-scan --output json > cmdi-report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: cmdi-report
          path: cmdi-report.json
          
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICALS=$(jq '.summary.critical' cmdi-report.json)
          if [ "$CRITICALS" -gt 0 ]; then
            echo "Found $CRITICALS critical command injection vulnerabilities!"
            exit 1
          fi
```

### GitLab CI

```yaml
command-injection-scan:
  stage: security
  script:
    - ao workflow run ao.security/command-injection-scan --output json > cmdi-report.json
  artifacts:
    reports:
      sast: cmdi-report.json
    expire_in: 1 week
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Remediation Guide

### 1. Use subprocess with List Arguments (Python)

**Before:**
```python
import subprocess

user_input = request.args.get('filename')
subprocess.run(f"cat {user_input}", shell=True)
```

**After:**
```python
import subprocess

user_input = request.args.get('filename')
subprocess.run(['cat', user_input])  # shell=False by default
```

### 2. Use execFile Instead of exec (Node.js)

**Before:**
```javascript
const { exec } = require('child_process');

exec(`cat ${filename}`, (err, stdout) => {});
```

**After:**
```javascript
const { execFile } = require('child_process');

execFile('cat', [filename], (err, stdout) => {});
```

### 3. Use Runtime.exec with Array (Java)

**Before:**
```java
String cmd = "cat " + filename;
Process p = Runtime.getRuntime().exec(cmd);
```

**After:**
```java
Process p = Runtime.getRuntime().exec(new String[]{"cat", filename});
```

### 4. Validate Input (Defense in Depth)

```python
import subprocess
import re

def safe_filename(filename):
    # Allow only alphanumeric, underscore, hyphen, and dot
    if re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        return filename
    raise ValueError("Invalid filename")

subprocess.run(['cat', safe_filename(user_input)])
```

## Best Practices

1. **Never Use shell=True**: Always use subprocess.run() with list arguments
2. **Use execFile over exec**: In Node.js, prefer execFile() which doesn't spawn a shell
3. **Validate Input Strictly**: Use allowlists, not blocklists
4. **Prefer Native Methods**: Use language-built-in file operations when possible
5. **Run with Minimal Permissions**: Limit the damage if exploitation occurs
6. **Log Command Execution**: Monitor for suspicious patterns
7. **Regular Scanning**: Include in CI/CD for continuous monitoring

## Limitations

- **Static Analysis Only**: Cannot detect runtime dynamic command generation
- **False Positives**: May flag safe code that looks dangerous (e.g., validated input)
- **Framework Knowledge**: Limited to known patterns and libraries
- **No Runtime Testing**: Does not attempt actual command execution

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Python subprocess Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Node.js Child Process Security Best Practices](https://nodejs.org/api/child_process.html#security-best-practices)
- [PortSwigger: OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PortSwigger: OS Command Injection Blind](https://portswigger.net/web-security/os-command-injection/blind)
- [PayloadsAllTheThings: OS Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OS%20Command%20Injection)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/launchapp-dev/ao-skill-security/issues
- AO Documentation: https://github.com/launchapp-dev/ao-docs
