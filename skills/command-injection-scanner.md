# Command Injection Scanner

Scan source code for OS command injection vulnerabilities, unsafe shell command execution, and subprocess misuse patterns using static analysis and pattern detection.

## Overview

This skill performs comprehensive static analysis to detect command injection vulnerabilities before they reach production. It identifies dangerous patterns in shell command execution, unsafe subprocess calls, and common misconfigurations that could lead to OS command injection attacks (OWASP A03:2021 - Injection).

## Capabilities

- **Pattern Detection**: Identify dangerous shell command construction patterns
- **Input Flow Analysis**: Trace user input to command execution sinks
- **Subprocess Safety Check**: Detect unsafe subprocess calls (shell=True, exec, system)
- **Language Support**: Support for Python, Node.js, Ruby, Java, PHP, Go, and Bash
- **Severity Classification**: Rank findings by exploitability and impact
- **Structured Reports**: Output JSON findings with location, severity, and remediation

## Scan Targets

### High Priority
- subprocess with shell=True in Python
- exec() and eval() with user-controlled input
- system() calls with unsanitized arguments
- Runtime.exec() in Java with string concatenation
- child_process.exec() in Node.js with shell injection

### Medium Priority
- Shell command construction with partial sanitization
- Dynamic command building from database values
- Command injection in template rendering

### Low Priority
- Complex command patterns requiring manual review
- Third-party library usage patterns

## Supported Languages

- Python (subprocess, os.system, os.popen, commands, fabric, invoke)
- JavaScript/TypeScript (Node.js) - child_process, exec, execSync, spawn
- Ruby (system, exec, `, %x, Open3)
- Java (Runtime.getRuntime().exec(), ProcessBuilder)
- PHP (exec, shell_exec, system, passthru, popen, proc_open)
- Go (os/exec package, Command, exec.Command)
- Bash scripts (eval, source with variables)

## Detection Patterns

### 1. Python - subprocess with shell=True

**DANGEROUS:**
```python
import subprocess

# CRITICAL - shell=True with string formatting
subprocess.run(f"ls -la {user_input}", shell=True)
subprocess.Popen("grep -r " + query, shell=True)
subprocess.call("cat %s" % filename, shell=True)

# CRITICAL - Using string interpolation
subprocess.run(f"echo {unsafe_data}", shell=True)
subprocess.check_output("ping -c 1 %s" % host, shell=True)
```

**SAFE:**
```python
import subprocess

# SAFE - shell=False with list arguments
subprocess.run(["ls", "-la", user_input])
subprocess.Popen(["grep", "-r", query])
subprocess.call(["cat", filename])

# SAFE - Using shlex.quote for shell=True
import shlex
subprocess.run(f"ls -la {shlex.quote(user_input)}", shell=True)
```

### 2. Python - os.system and os.popen

**DANGEROUS:**
```python
import os

# CRITICAL
os.system(f"rm -rf {user_path}")
os.popen("cat " + filename)
os.spawnl(mode, "command", arg1, user_input)
commands.getoutput("ls " + user_dir)
```

**SAFE:**
```python
import subprocess
import shlex

# SAFE - subprocess with list arguments
subprocess.run(["rm", "-rf", user_path])
subprocess.run(["cat", filename])

# SAFE - with validation
if user_path.startswith(safe_dir):
    os.system(f"ls {shlex.quote(user_path)}")
```

### 3. Node.js - child_process.exec()

**DANGEROUS:**
```javascript
const { exec } = require('child_process');

// CRITICAL - shell injection
exec(`ls -la ${userInput}`);
exec(`grep -r "${query}" .`);
exec(`cat ${req.params.file}`);

// CRITICAL - template literal injection
exec(`ping -c 1 ${host}`);
child_process.exec(`curl ${url}`);
```

**SAFE:**
```javascript
const { execFile } = require('child_process');

// SAFE - execFile with array arguments (no shell)
// execFile doesn't use a shell and prevents injection
execFile('ls', ['-la', userInput], (err, stdout) => {});

// SAFE - spawn with explicit arguments
const { spawn } = require('child_process');
spawn('grep', ['-r', query, '.']);

// SAFE - validation before exec
const safeInput = userInput.replace(/[^a-zA-Z0-9_-]/g, '');
exec(`ls -la ${safeInput}`);
```

### 4. Node.js - shell=True equivalent patterns

```javascript
const { execSync, execFileSync } = require('child_process');

// DANGEROUS - execSync uses shell by default for strings
execSync(`ls -la ${userInput}`);
execSync(`cat ${filename}`);

// SAFE - execFileSync with array arguments
execFileSync('ls', ['-la', userInput]);
execFileSync('cat', [filename]);

// SAFE - { shell: false } for explicit non-shell
spawn('ls', ['-la', userInput], { shell: false });
```

### 5. Java - Runtime.exec()

**DANGEROUS:**
```java
// CRITICAL - string concatenation in exec
Process p = Runtime.getRuntime().exec("cat " + filename);
Process p = Runtime.getRuntime().exec("ping -c 1 " + host);

// CRITICAL - String[] with single concatenated string
Process p = Runtime.getRuntime().exec(new String[]{"command", arg1, userInput});
```

**SAFE:**
```java
// SAFE - array of separate arguments
Process p = Runtime.getRuntime().exec(new String[]{"cat", filename});
Process p = Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});

// SAFE - ProcessBuilder
ProcessBuilder pb = new ProcessBuilder("cat", filename);
Process p = pb.start();

// SAFE - validation
if (filename.matches("^[a-zA-Z0-9._-]+$")) {
    Process p = Runtime.getRuntime().exec(new String[]{"cat", filename});
}
```

### 6. Ruby - system, exec, backticks

**DANGEROUS:**
```ruby
# CRITICAL - string interpolation
system("ls -la #{user_input}")
output = `cat #{filename}`
exec("rm -rf #{path}")
%x(ping -c 1 #{host})

# CRITICAL - string concatenation
system("grep -r " + query)
```

**SAFE:**
```ruby
# SAFE - separate arguments (uses execvp, no shell)
system("ls", "-la", user_input)
system("cat", filename)

# SAFE - validation
user_input = user_input.gsub(/[^a-zA-Z0-9_-]/, '')
system("ls #{Shellwords.escape(user_input)}")

# SAFE - Open3 for captured output
require 'open3'
stdout, stderr, status = Open3.capture3("ls", "-la", user_input)
```

### 7. PHP - exec, shell_exec, system

**DANGEROUS:**
```php
<?php
// CRITICAL - string interpolation
exec("ls -la $user_input");
$output = shell_exec("cat $filename");
system("ping -c 1 $host");
passthru("grep $query *");
popen("cat $file", "r");

// CRITICAL - concatenation
exec("rm -rf " . $path);
```

**SAFE:**
```php
<?php
// SAFE - escape function
exec("ls -la " . escapeshellarg($user_input));
system("cat " . escapeshellcmd($filename));

// SAFE - separate arguments where possible
shell_exec("cat " . escapeshellarg($file));

// SAFE - whitelist validation
if (preg_match('/^[a-zA-Z0-9_-]+$/', $user_input)) {
    system("ls -la $user_input");
}
```

### 8. Go - os/exec

**DANGEROUS:**
```go
package main

import (
    "os/exec"
)

// CRITICAL - Command with string formatting
cmd := exec.Command("bash", "-c", "ls -la "+userInput)

// CRITICAL - LookPath + Command injection
cmd := exec.Command("ls", "-la", userInput) // if userInput contains flags
```

**SAFE:**
```go
package main

import (
    "os/exec"
)

// SAFE - Command with separate arguments
cmd := exec.Command("ls", "-la", userInput)

// SAFE - Bash with validated input
if isSafe(userInput) {
    cmd := exec.Command("bash", "-c", "ls -la "+userInput)
}
```

### 9. Python - eval and exec

**DANGEROUS:**
```python
# CRITICAL - eval with any input
result = eval(user_input)
code = compile(user_string, '<string>', 'exec')
exec(f"print({user_value})")

# CRITICAL - dynamic code generation
exec("os.system('%s')" % user_command)
```

**SAFE:**
```python
# SAFE - ast.literal_eval for safe evaluation
import ast
try:
    result = ast.literal_eval(user_input)
except ValueError:
    pass

# SAFE - restricted execution environment
import RestrictedPython
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | subprocess(shell=True) with string formatting, direct exec() | `subprocess.run(f"ls {input}", shell=True)` |
| **CRITICAL** | Direct user input in shell commands | `exec("cat " + filename)` |
| **HIGH** | os.system, Runtime.exec with concatenation | `os.system("rm " + path)` |
| **HIGH** | child_process.exec with template literals | `exec(\`ping ${host}\`)` |
| **MEDIUM** | Partial sanitization or weak validation | `system("ls " + shellescape(user))` |
| **LOW** | Complex patterns requiring manual review | Dynamic command building with validation |
| **INFO** | Best practice suggestions | Use execFile over exec |

## Output Format

```json
{
  "findings": [
    {
      "id": "CMDI-001",
      "severity": "CRITICAL",
      "title": "Command Injection via subprocess with shell=True",
      "description": "subprocess.run() called with shell=True and string formatting allows arbitrary command execution. An attacker can inject shell metacharacters (;, |, &, $) to execute arbitrary commands.",
      "file": "src/utils/file_handler.py",
      "line": 42,
      "column": 18,
      "snippet": "subprocess.run(f\"cat {filename}\", shell=True)",
      "cwe": "CWE-78",
      "owasp": "A03:2021 - Injection",
      "remediation": "Use subprocess.run() with shell=False and list arguments: subprocess.run(['cat', filename])",
      "references": [
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://docs.python.org/3/library/subprocess.html#security-considerations"
      ]
    },
    {
      "id": "CMDI-002",
      "severity": "CRITICAL",
      "title": "Command Injection via Node.js child_process.exec()",
      "description": "child_process.exec() uses a shell to interpret the command string, making it vulnerable to command injection when used with user input.",
      "file": "src/services/shell.ts",
      "line": 23,
      "column": 12,
      "snippet": "exec(`grep -r \"${query}\" .`);",
      "cwe": "CWE-78",
      "owasp": "A03:2021 - Injection",
      "remediation": "Use execFile() or spawn() with array arguments instead of exec(): execFile('grep', ['-r', query, '.'])",
      "references": [
        "https://nodejs.org/api/child_process.html#security-best-practices",
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

## Execution Steps

1. **Initialize Scanner**
   - Load language-specific pattern matchers
   - Configure target directories and file extensions
   - Set up dangerous command execution sinks
   - Define safe alternatives for each language

2. **File Discovery**
   - Scan source directories for relevant files
   - Filter by language (.py, .js, .ts, .rb, .java, .php, .go, .sh)
   - Skip test files, node_modules, vendor directories

3. **Pattern Analysis**
   - Parse source files into AST (when possible)
   - Run regex patterns for quick detection
   - Track variable assignments and data flow
   - Identify command construction patterns

4. **Vulnerability Detection**
   - Identify dangerous subprocess patterns
   - Trace user input sources to command sinks
   - Check for shell=True, exec(), system() usage
   - Validate parameterization in command construction

5. **Severity Assignment**
   - Evaluate exploitability based on context
   - Consider authentication requirements
   - Assess impact on system integrity
   - Check for trivial exploitation

6. **Generate Report**
   - Compile findings with metadata
   - Include file paths, line numbers, code snippets
   - Provide CWE and OWASP references
   - Add remediation guidance with code examples

## Configuration

```yaml
command_injection_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - app
    - server
  
  exclude_patterns:
    - "**/*.test.{py,js,ts}"
    - "**/*.spec.{py,js,ts}"
    - "**/__tests__/**"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
  
  # Severity thresholds
  fail_on:
    - critical
    - high
  
  # Language-specific settings
  languages:
    python:
      enabled: true
      dangerous_patterns:
        - "shell=True"
        - "os.system"
        - "os.popen"
        - "commands."
        - "subprocess.*shell"
    javascript:
      enabled: true
      dangerous_patterns:
        - "child_process.exec"
        - "execSync"
        - "\\$`.*\\$"
    ruby:
      enabled: true
    java:
      enabled: true
    php:
      enabled: true
    go:
      enabled: true
  
  # Custom patterns (regex)
  custom_patterns:
    - pattern: "subprocess\\..*shell=True.*f\""
      severity: critical
      message: "subprocess with shell=True and f-string detected"
    - pattern: "exec\\(`.*\\${"
      severity: critical
      message: "Template literal with interpolation in exec() detected"
```

## Integration

### With AO Workflow

```yaml
phases:
  command-injection-scan:
    mode: agent
    agent: ao.security.command-injection-scanner
    directive: "Scan codebase for command injection vulnerabilities"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run command injection scan before commit
ao skill run ao.security/command-injection-scan --staged
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Command Injection Scan
  run: ao skill run ao.security/command-injection-scan --output json > cmdi-report.json
  
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: cmdi-report
    path: cmdi-report.json
```

## Remediation Checklist

1. **Avoid shell=True in Python**
   - [ ] Use subprocess.run() with list arguments
   - [ ] Use shell=False explicitly
   - [ ] Use execFile in Node.js

2. **Use Safe Alternatives**
   - [ ] Replace exec() with execFile() or spawn()
   - [ ] Use Runtime.exec() with array of arguments
   - [ ] Use ProcessBuilder in Java

3. **Validate and Sanitize Input**
   - [ ] Implement strict allowlist validation
   - [ ] Use proper escaping functions
   - [ ] Validate against known patterns

4. **Prefer Built-in Functions**
   - [ ] Use Python pathlib over shell commands
   - [ ] Use Node.js fs module over shell commands
   - [ ] Use language-native solutions

## Best Practices

1. **Never Trust User Input**: Assume all user input is malicious
2. **Avoid Shell Invocation**: Use subprocess with shell=False
3. **Use Allowlists**: Validate input against known good patterns
4. **Prefer Native Methods**: Use language-built-in file operations
5. **Defense in Depth**: Combine multiple validation layers
6. **Least Privilege**: Run commands with minimal permissions

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Python subprocess Security](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Node.js Child Process Security](https://nodejs.org/api/child_process.html#security-best-practices)
- [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings OS Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OS%20Command%20Injection)
