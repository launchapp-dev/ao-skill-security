# XSS (Cross-Site Scripting) Scanner

Scan source code for Cross-Site Scripting (XSS) vulnerabilities, unsanitized user input in HTML/JS output, and DOM manipulation vulnerabilities using static analysis and pattern detection.

## Overview

This skill performs comprehensive static analysis to detect XSS vulnerabilities before they reach production. It identifies dangerous patterns in user input handling, unsafe HTML rendering, improper sanitization, and common JavaScript injection vectors that could lead to XSS attacks.

## Capabilities

- **Pattern Detection**: Identify dangerous string concatenation in HTML/JS output
- **Input Flow Analysis**: Trace user input to HTML rendering operations
- **Sanitization Verification**: Check for proper use of sanitization libraries
- **Framework Detection**: Support for React, Vue, Angular, Express, Django, Rails
- **DOM XSS Detection**: Identify dangerous DOM manipulation patterns
- **Severity Classification**: Rank findings by exploitability and impact
- **Structured Reports**: Output JSON findings with location, severity, and remediation

## Scan Targets

### High Priority
- Direct user input in innerHTML/dangerouslySetInnerHTML
- User input in eval()/Function() constructors
- Template strings with user content in HTML contexts
- Unsanitized dangerouslySetInnerHTML in React
- v-html in Vue without sanitization

### Medium Priority
- Missing HTML encoding in template engines
- Incomplete sanitization with DOMPurify
- Custom sanitization that may be bypassed
- URL parameters reflected in HTML

### Low Priority
- Complex rendering patterns (manual review required)
- Third-party library usage patterns
- Client-side only data handling

## Supported Languages

- TypeScript/JavaScript (Node.js, React, Vue, Angular)
- Python (Django, Flask, Jinja2 templates)
- Ruby (Rails, ERB templates)
- Java (JSP, Thymeleaf, Spring)
- PHP (Laravel, Blade templates)

## Detection Patterns

### 1. Dangerous DOM Manipulation

**JavaScript/TypeScript:**
```javascript
// DANGEROUS
element.innerHTML = userInput;
div.innerHTML = '<span>' + username + '</span>';
document.write(userProvidedContent);

// SAFE
element.textContent = userInput;
element.innerText = sanitizedContent;
textNode.appendData(userInput);
```

**React:**
```jsx
// DANGEROUS
<div dangerouslySetInnerHTML={{__html: userInput}} />
<div dangerouslySetInnerHTML={{__html: '<span>' + name + '</span>'}} />

// SAFE
<div>{userInput}</div>
<div>{sanitize(userInput)}</div>
```

**Vue:**
```vue
<!-- DANGEROUS -->
<div v-html="userInput"></div>

<!-- SAFE -->
<div>{{ userInput }}</div>
<div v-html="sanitize(userInput)"></div>
```

### 2. Eval and Function Constructors

**JavaScript/TypeScript:**
```javascript
// DANGEROUS
eval('(' + userInput + ')');
new Function('return ' + userData)();
setTimeout(userCode, 1000);
setInterval(userScript, 1000);
new Function(userFunctionBody)();

// SAFE - never pass user input to eval/Function
const safeParser = JSON.parse(userInput);
```

### 3. URL-based XSS (javascript: protocol)

```javascript
// DANGEROUS
<a href={userProvidedUrl}>Link</a>
window.location = userUrl;
location.href = redirectUrl;
element.setAttribute('href', userLink);

// SAFE
const safeUrl = sanitize(userUrl);
if (isValidUrl(safeUrl)) {
  element.href = safeUrl;
}
```

### 4. Template Injection

**Jinja2 (Python):**
```html
<!-- DANGEROUS -->
{{ user_input | safe }}
{{ user_input | safe_str }}
<div>{{ user_input | raw }}</div>

<!-- SAFE -->
<div>{{ user_input }}</div>
<div>{{ user_input | escape }}</div>
```

**ERB (Ruby):**
```erb
<!-- DANGEROUS -->
<%= user_input.html_safe %>
<%= raw(user_input) %>

<!-- SAFE -->
<%= user_input %>
<%= escape_html(user_input) %>
```

### 5. Reflected XSS

**Express.js:**
```javascript
// DANGEROUS
app.get('/search', (req, res) => {
  res.send(`<h1>Search results for ${req.query.q}</h1>`);
});

app.get('/hello', (req, res) => {
  res.send('Hello ' + req.query.name);
});

// SAFE
app.get('/search', (req, res) => {
  res.send(`<h1>Search results for ${escapeHtml(req.query.q)}</h1>`);
});
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct user input in innerHTML/eval, no sanitization | `element.innerHTML = userInput` |
| **HIGH** | String concatenation in HTML with user input | `'<span>' + name + '</span>'` injected |
| **MEDIUM** | Missing sanitization in template contexts | `{{ data \| safe }}` in Jinja2 |
| **LOW** | Potential DOM XSS with indirect paths | Event handlers with document.location |
| **INFO** | Best practice suggestions | Missing Content-Security-Policy |

## Output Format

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
      "remediation": "Use textContent instead: profileDiv.textContent = user.bio;",
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

## Execution Steps

1. **Initialize Scanner**
   - Load language-specific pattern matchers
   - Configure target directories and file extensions
   - Set up sanitization library detection rules
   - Define dangerous sink patterns

2. **File Discovery**
   - Scan source directories for relevant files
   - Filter by language (ts, js, tsx, jsx, py, rb, java, php)
   - Skip test files, node_modules, vendor directories

3. **Pattern Analysis**
   - Parse source files into AST (when possible)
   - Run regex patterns for quick detection
   - Track variable assignments and data flow
   - Identify HTML rendering patterns

4. **Vulnerability Detection**
   - Identify dangerous DOM manipulation patterns
   - Trace user input sources to HTML sinks
   - Check for proper sanitization
   - Validate template injection vectors

5. **Severity Assignment**
   - Evaluate exploitability based on context
   - Consider authentication requirements
   - Assess impact and likelihood

6. **Generate Report**
   - Compile findings with metadata
   - Include code snippets and line numbers
   - Provide actionable remediation guidance

## Configuration

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
  
  exclude_patterns:
    - "**/*.test.{ts,js,tsx,jsx}"
    - "**/*.spec.{ts,js,tsx,jsx}"
    - "**/__tests__/**"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
  
  # Severity thresholds
  fail_on:
    - critical
    - high
  
  # Sanitization libraries (known safe)
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
      dangerous_sinks:
        - innerHTML
        - outerHTML
        - insertAdjacentHTML
        - write
        - writeln
        - dangerouslySetInnerHTML
    javascript:
      enabled: true
    python:
      enabled: true
      template_engines:
        - jinja2
        - mako
        - django
    ruby:
      enabled: true
  
  # Custom patterns (regex)
  custom_patterns:
    - pattern: "innerHTML\\s*=\\s*[^;]*\\+"
      severity: critical
      message: "String concatenation in innerHTML detected"
```

## Integration

### With AO Workflow

```yaml
phases:
  xss-scan:
    mode: agent
    agent: ao.security.xss-scanner
    directive: "Scan codebase for XSS vulnerabilities"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run XSS scan before commit
ao skill run ao.security/xss-scan --staged
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: XSS Scan
  run: ao skill run ao.security/xss-scan --output json > xss-report.json
  
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: xss-report
    path: xss-report.json
```

## Best Practices

1. **Context-Aware Encoding**: Use appropriate encoding for HTML, JS, URL, CSS contexts
2. **Prefer Safe APIs**: Use textContent instead of innerHTML when possible
3. **Use Sanitization Libraries**: Employ DOMPurify, bleach, or similar libraries
4. **Content Security Policy**: Implement CSP headers to mitigate XSS
5. **Template Auto-Escaping**: Enable auto-escaping in template engines
6. **Input Validation**: Validate and sanitize input at entry points
7. **Framework Security Features**: Leverage React's built-in protections

## References

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: XSS](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
