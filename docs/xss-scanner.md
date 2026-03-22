# XSS (Cross-Site Scripting) Scanner Documentation

## Overview

The XSS Scanner is a static analysis tool that detects Cross-Site Scripting vulnerabilities in source code before they reach production. It identifies dangerous HTML/JS rendering patterns, traces user input flow to DOM operations, and detects unsafe sanitization practices that could lead to XSS attacks.

## Installation

The XSS scanner is included in the `ao.security` skill pack. To use it:

```bash
# Install the skill pack
ao skill install ao.security

# Run XSS scan
ao workflow run ao.security/xss-scan
```

## Quick Start

### Basic Scan

```bash
# Scan current directory for XSS vulnerabilities
ao workflow run ao.security/xss-scan

# Scan specific directory
ao workflow run ao.security/xss-scan --input '{"path": "src/components"}'
```

### Scan and Fix

```bash
# Scan for vulnerabilities and automatically create fix tasks
ao workflow run ao.security/xss-scan-and-fix
```

## Detection Capabilities

### 1. Dangerous DOM Manipulation

Detects unsafe DOM manipulation with user input:

```javascript
// ❌ DETECTED - innerHTML with string concatenation
profileDiv.innerHTML = '<h2>' + user.bio + '</h2>';

// ❌ DETECTED - direct innerHTML assignment
element.innerHTML = req.body.content;

// ✅ SAFE - textContent
element.textContent = userInput;

// ✅ SAFE - with sanitization
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 2. React Dangerous Patterns

Identifies unsafe React patterns:

```jsx
// ❌ DETECTED - dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />
<div dangerouslySetInnerHTML={{__html: '<span>' + name + '</span>'}} />

// ✅ SAFE - let React handle escaping
<div>{userInput}</div>

// ✅ SAFE - with sanitization
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

### 3. Vue Dangerous Patterns

Identifies unsafe Vue patterns:

```vue
<!-- ❌ DETECTED - v-html without sanitization -->
<div v-html="userInput"></div>

<!-- ✅ SAFE - default escaping -->
<div>{{ userInput }}</div>

<!-- ✅ SAFE - with sanitization -->
<div v-html="sanitize(userInput)"></div>
```

### 4. Eval and Function Constructors

Detects dangerous dynamic code execution:

```javascript
// ❌ DETECTED - eval with user input
eval('(' + userData + ')');
new Function('return ' + userInput)();
setTimeout(userCode, 1000);

// ✅ SAFE - never pass user input to eval
const safeData = JSON.parse(userInput);
```

### 5. Template Injection (Backend)

Identifies unsafe template patterns:

```html
<!-- Jinja2 ❌ DETECTED -->
{{ user_input | safe }}
<div>{{ user_input | raw }}</div>

<!-- Jinja2 ✅ SAFE -->
<div>{{ user_input }}</div>
<div>{{ user_input | escape }}</div>
```

```erb
<!-- ERB ❌ DETECTED -->
<%= user_input.html_safe %>
<%= raw(user_input) %>

<!-- ERB ✅ SAFE -->
<%= user_input %>
```

### 6. URL-based XSS

Detects javascript: protocol injection:

```javascript
// ❌ DETECTED
<a href={userProvidedUrl}>Link</a>
element.setAttribute('href', userLink);

// ✅ SAFE
const safeUrl = sanitize(userUrl);
if (isValidUrl(safeUrl)) {
  element.href = safeUrl;
}
```

## Supported Languages & Frameworks

| Language | Frameworks | Dangerous Patterns |
|----------|-----------|-------------------|
| TypeScript/JavaScript | React, Vue, Angular, Express | innerHTML, dangerouslySetInnerHTML, eval |
| Python | Django, Flask, Jinja2 | {{ data \| safe }}, mark_safe() |
| Ruby | Rails, ERB | .html_safe, raw() |
| Java | JSP, Thymeleaf, Spring | c:out with escapeXml="false" |
| PHP | Laravel, Blade | {!! $data !!}, raw() |

## Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | Direct user input in innerHTML/eval, no sanitization | `element.innerHTML = userInput` |
| **HIGH** | String concatenation in HTML with user input | `'<span>' + name + '</span>'` injected |
| **MEDIUM** | Missing sanitization in template contexts | `{{ data \| safe }}` in Jinja2 |
| **LOW** | Potential DOM XSS with indirect paths | Event handlers with document.location |
| **INFO** | Best practice suggestions | Missing Content-Security-Policy |

## Output Format

### JSON Report

```json
{
  "findings": [
    {
      "id": "XSS-001",
      "severity": "CRITICAL",
      "title": "XSS via innerHTML Injection",
      "description": "Direct use of user input in innerHTML allows arbitrary HTML/JS execution",
      "file": "src/components/UserProfile.tsx",
      "line": 42,
      "column": 24,
      "snippet": "profileDiv.innerHTML = '<h2>' + user.bio + '</h2>';",
      "cwe": "CWE-79",
      "owasp": "A03:2021 - Injection",
      "remediation": "Use textContent instead: profileDiv.textContent = user.bio; or sanitize with DOMPurify: profileDiv.innerHTML = DOMPurify.sanitize(user.bio);",
      "references": [
        "https://owasp.org/www-community/attacks/xss/",
        "https://cwe.mitre.org/data/definitions/79.html"
      ]
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
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
XSS Scan Results
================

Scanned 127 files in 2.34s

Findings by Severity:
  🔴 CRITICAL: 1
  🟠 HIGH:     2
  🟡 MEDIUM:   1
  🟢 LOW:      1
  ℹ️  INFO:     0

CRITICAL Findings:
──────────────────

[XSS-001] XSS via innerHTML Injection
  File: src/components/UserProfile.tsx:42:24
  Code: profileDiv.innerHTML = '<h2>' + user.bio + '</h2>';
  
  Remediation:
    Use textContent instead:
    profileDiv.textContent = user.bio;
    
    Or sanitize with DOMPurify:
    profileDiv.innerHTML = DOMPurify.sanitize(user.bio);
  
  References:
    • https://owasp.org/www-community/attacks/xss/
    • https://cwe.mitre.org/data/definitions/79.html
```

## Configuration

Create a `.ao/security.yaml` file to customize scanning:

```yaml
xss_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - app
    - server
    - views
  
  # Exclude patterns
  exclude_patterns:
    - "**/*.test.{ts,js,tsx,jsx}"
    - "**/*.spec.{ts,js,tsx,jsx}"
    - "**/__tests__/**"
    - "**/node_modules/**"
    - "**/__mocks__/**"
    - "**/migrations/**"
    - "**/fixtures/**"
  
  # Fail CI on these severities
  fail_on:
    - critical
    - high
  
  # Known safe sanitization libraries
  safe_libraries:
    - DOMPurify.sanitize
    - sanitize-html
    - xss
    - escape-html
    - validator.escape
    - bleach.clean
    - sanitize
    - HtmlSanitizer
  
  # Language-specific settings
  languages:
    typescript:
      enabled: true
    javascript:
      enabled: true
    python:
      enabled: true
    ruby:
      enabled: true
  
  # Custom detection patterns
  custom_patterns:
    - pattern: "innerHTML\\s*=\\s*[^;]*\\+"
      severity: critical
      message: "String concatenation in innerHTML detected"
```

## Integration

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run XSS scan on staged files
ao workflow run ao.security/xss-scan --staged

# Check exit code
if [ $? -ne 0 ]; then
  echo "XSS vulnerabilities detected. Please fix before committing."
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
  xss-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup AO
        run: |
          curl -fsSL https://get.ao.dev | sh
          
      - name: Run XSS Scan
        run: |
          ao workflow run ao.security/xss-scan --output json > xss-report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: xss-report
          path: xss-report.json
          
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICALS=$(jq '.summary.critical' xss-report.json)
          if [ "$CRITICALS" -gt 0 ]; then
            echo "Found $CRITICALS critical XSS vulnerabilities!"
            exit 1
          fi
```

### GitLab CI

```yaml
xss-scan:
  stage: security
  script:
    - ao workflow run ao.security/xss-scan --output json > xss-report.json
  artifacts:
    reports:
      sast: xss-report.json
    expire_in: 1 week
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Remediation Guide

### 1. Use Safe DOM APIs

**Before:**
```javascript
element.innerHTML = '<span>' + userInput + '</span>';
```

**After:**
```javascript
// Option 1: textContent (safest for text)
const span = document.createElement('span');
span.textContent = userInput;
element.appendChild(span);

// Option 2: with sanitization
element.innerHTML = DOMPurify.sanitize(userInput);
```

### 2. React Safe Patterns

**Before:**
```jsx
<div dangerouslySetInnerHTML={{__html: content}} />
```

**After:**
```jsx
// Option 1: Let React handle it (safest)
<div>{content}</div>

// Option 2: With sanitization
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}} />
```

### 3. Vue Safe Patterns

**Before:**
```vue
<div v-html="userContent"></div>
```

**After:**
```vue
<!-- Default escaping (safest) -->
<div>{{ userContent }}</div>

<!-- With sanitization -->
<div v-html="sanitize(userContent)"></div>
```

### 4. Template Engine Safe Patterns

**Jinja2 (Python) - Before:**
```html
<div>{{ user_input | safe }}</div>
```

**Jinja2 (Python) - After:**
```html
<div>{{ user_input }}</div>
<!-- Auto-escaping is enabled by default -->
```

### 5. Content Security Policy

Add CSP headers to mitigate XSS:

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'unsafe-inline';">
```

```javascript
// Express.js
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
```

## Best Practices

1. **Prefer Safe APIs**: Use textContent instead of innerHTML when possible
2. **Context-Aware Encoding**: Use appropriate encoding for HTML, JS, URL, CSS contexts
3. **Use Sanitization Libraries**: Employ DOMPurify, bleach, or similar libraries
4. **Enable Template Auto-Escaping**: Default escaping prevents most XSS
5. **Content Security Policy**: Implement CSP headers to mitigate XSS
6. **Input Validation**: Validate and sanitize input at entry points
7. **Framework Security Features**: Leverage React's built-in protections
8. **Regular Scanning**: Include in CI/CD for continuous monitoring

## Limitations

- **Static Analysis Only**: Cannot detect runtime dynamic XSS generation
- **False Positives**: May flag safe code that looks dangerous
- **Framework Knowledge**: Limited to known frameworks and libraries
- **No Runtime Testing**: Does not attempt actual exploitation
- **DOM XSS Complexity**: Some DOM-based XSS requires complex data flow analysis

## References

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [OWASP Testing Guide: XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/launchapp-dev/ao-skill-security/issues
- AO Documentation: https://github.com/launchapp-dev/ao-docs
