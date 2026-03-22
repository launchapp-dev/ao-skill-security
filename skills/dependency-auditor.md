# Dependency Auditor

Audit npm dependencies for known CVEs, security vulnerabilities, and outdated packages using npm audit and security advisory databases.

## Overview

This skill performs comprehensive dependency security analysis using npm audit to detect known vulnerabilities, extract CVE information, and provide actionable remediation guidance. It analyzes both direct and transitive dependencies, classifies severity, and estimates remediation effort.

## Capabilities

- **npm audit Integration**: Execute and parse npm audit JSON output
- **CVE Extraction**: Identify and document CVE identifiers from advisories
- **CVSS Scoring**: Map vulnerabilities to CVSS severity scores
- **Dependency Tree Analysis**: Trace vulnerabilities through dependency paths
- **Transitive Dependency Detection**: Identify vulnerabilities in indirect dependencies
- **Exploitability Assessment**: Evaluate real-world attack vectors
- **Remediation Commands**: Generate exact npm install commands
- **Breaking Change Analysis**: Flag upgrades with potential breaking changes
- **Outdated Package Detection**: Identify packages with security fixes available

## Vulnerability Types Detected

### High Priority

1. **Known CVEs** - Published security advisories with CVE identifiers
2. **Prototype Pollution** - Object prototype manipulation vulnerabilities
3. **Code Injection** - Eval, Function constructor, unsafe deserialization
4. **ReDoS** - Regular expression denial of service
5. **Cryptographic Weaknesses** - Weak encryption, insufficient key lengths

### Medium Priority

6. **Path Traversal** - Directory traversal vulnerabilities
7. **Man-in-the-Middle** - TLS bypasses, insecure HTTP
8. **Denial of Service** - Memory exhaustion, CPU-intensive operations
9. **Information Disclosure** - Sensitive data leakage

### Low Priority

10. **Outdated Packages** - Versions with known security fixes
11. **Deprecated Packages** - Unmaintained dependencies

## Scan Targets

### Production Dependencies
- Direct dependencies in `dependencies` section
- Transitive dependencies in the dependency tree
- Critical path packages (authentication, encryption, networking)

### Development Dependencies
- Build tools and bundlers
- Test frameworks and utilities
- Development servers and compilers

## Severity Classification

| Severity | Criteria | CVSS Score |
|----------|----------|------------|
| **CRITICAL** | Actively exploited, trivially exploitable, RCE | 9.0 - 10.0 |
| **HIGH** | Exploitable, proof-of-concept exists | 7.0 - 8.9 |
| **MODERATE** | Potential impact, specific conditions required | 4.0 - 6.9 |
| **LOW** | Limited impact, difficult to exploit | 0.1 - 3.9 |
| **INFO** | Best practice recommendations | N/A |

## Usage

### Basic Audit

```bash
# Run dependency audit
ao workflow run ao.security/dependency-audit

# Audit with custom input
ao workflow run ao.security/dependency-audit --input '{"severity": "high"}'
```

### Audit and Fix

```bash
# Audit dependencies and create fix tasks
ao workflow run ao.security/dependency-audit-and-fix
```

## Output Format

### JSON Report Structure

```json
{
  "audit_summary": {
    "total_vulnerabilities": 12,
    "critical": 1,
    "high": 3,
    "moderate": 5,
    "low": 3,
    "info": 0,
    "scanned_dependencies": 847,
    "audit_duration_ms": 3420
  },
  "findings": [
    {
      "id": "DEP-001",
      "package": "lodash",
      "version": "4.17.15",
      "severity": "HIGH",
      "cve": "CVE-2020-8203",
      "cwe": "CWE-1321",
      "title": "Prototype Pollution in lodash",
      "description": "Prototype pollution occurs when the lodash functions merge, mergeWith, and defaultsDeep are used to modify Object.prototype.",
      "cvss": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
      },
      "vulnerable_versions": "<4.17.19",
      "patched_version": "4.17.19",
      "dependency_path": ["my-app", "express", "lodash"],
      "is_direct": false,
      "is_dev": false,
      "exploitability": "Functional exploit exists",
      "remediation": {
        "type": "upgrade",
        "command": "npm install lodash@4.17.19",
        "breaking_changes": false,
        "effort": "low"
      },
      "references": [
        "https://npmjs.com/advisories/1523",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
        "https://github.com/lodash/lodash/pull/4759"
      ],
      "advisory_url": "https://npmjs.com/advisories/1523",
      "published_date": "2020-07-15T00:00:00.000Z"
    }
  ],
  "outdated_packages": [
    {
      "package": "express",
      "current": "4.17.1",
      "latest": "4.18.2",
      "security_fixes": true,
      "breaking_changes": false
    }
  ],
  "recommendations": [
    {
      "priority": "high",
      "action": "Update lodash to 4.17.19 or later",
      "reason": "Fixes prototype pollution vulnerability CVE-2020-8203",
      "command": "npm install lodash@^4.17.19"
    }
  ]
}
```

## Execution Steps

1. **Verify Environment**
   - Check for package.json and package-lock.json
   - Verify npm version (7+ recommended)
   - Ensure network access for advisory database

2. **Run npm audit**
   ```bash
   npm audit --json
   ```
   - Capture full vulnerability report
   - Parse JSON output structure

3. **Parse Vulnerabilities**
   - Extract advisory metadata
   - Map to CVE identifiers
   - Determine CVSS scores
   - Identify vulnerable version ranges

4. **Analyze Dependency Tree**
   ```bash
   npm ls --json
   ```
   - Trace dependency paths
   - Identify transitive dependencies
   - Distinguish direct vs indirect

5. **Assess Impact**
   - Evaluate production vs development
   - Determine exploitability in context
   - Check for proof-of-concept exploits
   - Assess attack surface

6. **Classify Severity**
   - Map CVSS to severity levels
   - Consider production impact
   - Evaluate exploitability
   - Account for mitigating factors

7. **Generate Remediation**
   - Identify fixed versions
   - Generate upgrade commands
   - Check for breaking changes
   - Estimate remediation effort
   - Suggest alternatives for deprecated packages

8. **Produce Report**
   - Compile structured findings
   - Include CVE references and links
   - Add executive summary
   - Prioritize remediation actions

## Configuration

```yaml
dependency_auditor:
  enabled: true
  
  # Severity thresholds
  fail_on:
    - critical
    - high
  
  # Scope
  include_dev_dependencies: true
  include_optional_dependencies: false
  
  # Reporting
  max_findings: 100
  include_unchanged: false
  
  # Remediation
  auto_fix: false
  breaking_change_review: true
  
  # Advisory sources
  advisory_sources:
    - npm
    - github
    - snyk
  
  # Exclude patterns
  exclude_packages:
    - "@types/*"  # Type definitions only
    - "eslint-*"  # Dev tools
```

## Common Vulnerabilities

### 1. Prototype Pollution (lodash, underscore)

```json
{
  "package": "lodash",
  "cve": "CVE-2020-8203",
  "severity": "HIGH",
  "issue": "Prototype Pollution",
  "fix": "npm install lodash@^4.17.19"
}
```

### 2. ReDoS (validator, moment)

```json
{
  "package": "validator",
  "cve": "CVE-2020-36632",
  "severity": "MODERATE",
  "issue": "Regular Expression Denial of Service",
  "fix": "npm install validator@^13.7.0"
}
```

### 3. Code Injection (serialize-to-js)

```json
{
  "package": "serialize-to-js",
  "cve": "CVE-2020-7660",
  "severity": "CRITICAL",
  "issue": "Code Injection",
  "fix": "npm uninstall serialize-to-js"
}
```

### 4. Path Traversal (npm, tar)

```json
{
  "package": "tar",
  "cve": "CVE-2021-32804",
  "severity": "HIGH",
  "issue": "Path Traversal",
  "fix": "npm install tar@^6.1.2"
}
```

### 5. Cryptographic Issues (node-forge)

```json
{
  "package": "node-forge",
  "cve": "CVE-2020-7720",
  "severity": "HIGH",
  "issue": "Weak RSA Key Generation",
  "fix": "npm install node-forge@^0.10.0"
}
```

## Remediation Guide

### Direct Dependencies

```bash
# Upgrade to fixed version
npm install package@^version

# Update to latest
npm update package

# Install specific version
npm install package@1.2.3
```

### Transitive Dependencies

```bash
# Use npm audit fix
npm audit fix

# Force fix breaking changes
npm audit fix --force

# Override resolution (package.json)
"overrides": {
  "vulnerable-package": "^2.0.0"
}
```

### Alternative Approaches

```json
// package.json - Use resolutions (yarn)
"resolutions": {
  "vulnerable-package": "^2.0.0"
}

// package.json - Override (npm 8.3+)
"overrides": {
  "vulnerable-package": "^2.0.0"
}
```

## Integration

### With AO Workflow

```yaml
phases:
  dependency-audit:
    mode: agent
    agent: ao.security.dependency-auditor
    directive: "Audit dependencies for CVEs and vulnerabilities"
    capabilities:
      produces_artifacts: true
      security_scanning: true
      network_access: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run dependency audit before commit
ao workflow run ao.security/dependency-audit

# Check for critical/high vulnerabilities
if [ $? -ne 0 ]; then
  echo "Critical or high vulnerabilities detected!"
  exit 1
fi
```

### GitHub Actions

```yaml
name: Dependency Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          
      - name: Install dependencies
        run: npm ci
        
      - name: Run Dependency Audit
        run: |
          ao workflow run ao.security/dependency-audit --output json > audit-report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: dependency-audit
          path: audit-report.json
          
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICAL=$(jq '.audit_summary.critical' audit-report.json)
          HIGH=$(jq '.audit_summary.high' audit-report.json)
          
          if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            echo "Found $CRITICAL critical and $HIGH high vulnerabilities!"
            exit 1
          fi
```

### GitLab CI

```yaml
dependency-audit:
  stage: security
  script:
    - npm ci
    - ao workflow run ao.security/dependency-audit --output json > audit-report.json
  artifacts:
    reports:
      dependency_scanning: audit-report.json
    expire_in: 1 week
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Best Practices

1. **Regular Audits**: Run weekly or on every PR
2. **Automate Remediation**: Use npm audit fix for safe upgrades
3. **Review Breaking Changes**: Test upgrades before merging
4. **Minimize Dependencies**: Reduce attack surface
5. **Lock File Version Control**: Commit package-lock.json
6. **Monitor Dependencies**: Use tools like Dependabot or Snyk
7. **Private Packages**: Audit internal packages too
8. **Transitive Awareness**: Check indirect dependencies
9. **Dev vs Prod**: Distinguish development and production risks
10. **Document Exceptions**: Track accepted risks with justification

## Limitations

- **npm Ecosystem Only**: Limited to Node.js packages
- **Known CVEs Only**: Cannot detect zero-day vulnerabilities
- **Static Analysis**: No runtime behavior analysis
- **Registry Dependency**: Requires access to npm registry
- **False Positives**: May report unused vulnerable code
- **Transitive Complexity**: Deep trees can be hard to resolve

## References

- [npm audit Documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)
- [npm Security Advisories](https://www.npmjs.com/advisories)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov)
- [GitHub Advisory Database](https://github.com/advisories)
- [Snyk Vulnerability DB](https://security.snyk.io)
- [OWASP Top 10 - A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [CVSS Calculator](https://www.first.org/cvss/calculator)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
