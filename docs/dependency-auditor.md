# Dependency Auditor Documentation

## Overview

The Dependency Auditor is a security analysis tool that scans npm dependencies for known CVEs and vulnerabilities using `npm audit`. It identifies security issues in both direct and transitive dependencies, extracts CVE information, assesses severity using CVSS scores, and provides actionable remediation guidance.

## Installation

The dependency auditor is included in the `ao.security` skill pack. To use it:

```bash
# Install the skill pack
ao skill install ao.security

# Run dependency audit
ao workflow run ao.security/dependency-audit
```

## Quick Start

### Basic Audit

```bash
# Scan dependencies for vulnerabilities
ao workflow run ao.security/dependency-audit

# Audit with severity filter
ao workflow run ao.security/dependency-audit --input '{"severity": "high"}'

# Output as JSON
ao workflow run ao.security/dependency-audit --output json > audit-report.json
```

### Audit and Fix

```bash
# Audit and automatically create fix tasks
ao workflow run ao.security/dependency-audit-and-fix
```

## How It Works

### 1. npm audit Execution

The auditor runs `npm audit --json` to scan your dependencies:

```bash
npm audit --json
```

This queries the npm registry's security advisory database for known vulnerabilities in your dependency tree.

### 2. Advisory Parsing

The JSON output is parsed to extract:

- **Vulnerability metadata**: Package name, version, severity
- **CVE identifiers**: Links to National Vulnerability Database
- **CVSS scores**: Standardized severity assessment
- **Vulnerable versions**: Version ranges with the issue
- **Patched versions**: Versions with the fix
- **Dependency paths**: How the package is included

### 3. Dependency Tree Analysis

Using `npm ls`, the auditor traces:

- Direct vs transitive dependencies
- Dependency paths from root to vulnerable package
- Dev vs production dependencies
- Peer dependency requirements

### 4. Severity Classification

Vulnerabilities are classified by CVSS score:

| Severity | CVSS Score | Impact |
|----------|------------|--------|
| CRITICAL | 9.0 - 10.0 | Actively exploited, RCE, data breach |
| HIGH | 7.0 - 8.9 | Exploitable, PoC exists, significant impact |
| MODERATE | 4.0 - 6.9 | Potential impact, specific conditions |
| LOW | 0.1 - 3.9 | Limited impact, difficult to exploit |
| INFO | N/A | Best practice recommendations |

### 5. Remediation Generation

For each vulnerability, the auditor provides:

- Exact upgrade command: `npm install package@version`
- Breaking change assessment
- Estimated effort (low, medium, high)
- Alternative packages if deprecated

## Output Format

### JSON Report

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
      "description": "Prototype pollution occurs when the lodash functions merge, mergeWith, and defaultsDeep are used to modify Object.prototype. An attacker can add properties to Object.prototype that are inherited by all objects.",
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

### Console Output

```
Dependency Security Audit Results
==================================

Scanned 847 dependencies in 3.42s

Vulnerabilities by Severity:
  🔴 CRITICAL: 1
  🟠 HIGH:     3
  🟡 MODERATE: 5
  🟢 LOW:      3
  ℹ️  INFO:     0

CRITICAL Findings:
──────────────────

[DEP-001] Prototype Pollution in lodash
  Package: lodash@4.17.15
  CVE: CVE-2020-8203
  CVSS: 7.5 (HIGH)
  Path: my-app → express → lodash
  
  Issue: Prototype pollution via merge, mergeWith, defaultsDeep
  
  Remediation:
    npm install lodash@4.17.19
    
  Breaking Changes: No
  Effort: Low
  
  References:
    • https://npmjs.com/advisories/1523
    • https://nvd.nist.gov/vuln/detail/CVE-2020-8203

Recommendations:
────────────────

Priority: HIGH
  → Update lodash to 4.17.19 or later
    Reason: Fixes prototype pollution vulnerability
    Command: npm install lodash@^4.17.19
```

## Common Vulnerability Types

### 1. Prototype Pollution

**Affected Packages**: lodash, underscore, merge, deepmerge

**Example**:
```json
{
  "package": "lodash",
  "cve": "CVE-2020-8203",
  "severity": "HIGH",
  "title": "Prototype Pollution",
  "description": "Unsafe recursive merge allows Object.prototype modification"
}
```

**Remediation**:
```bash
npm install lodash@^4.17.19
```

### 2. Regular Expression Denial of Service (ReDoS)

**Affected Packages**: validator, moment, underscore.string

**Example**:
```json
{
  "package": "validator",
  "cve": "CVE-2020-36632",
  "severity": "MODERATE",
  "title": "ReDoS Vulnerability",
  "description": "Catastrophic backtracking in email validation regex"
}
```

**Remediation**:
```bash
npm install validator@^13.7.0
```

### 3. Code Injection

**Affected Packages**: serialize-to-js, js-yaml, vm2

**Example**:
```json
{
  "package": "serialize-to-js",
  "cve": "CVE-2020-7660",
  "severity": "CRITICAL",
  "title": "Code Injection",
  "description": "Arbitrary code execution during deserialization"
}
```

**Remediation**:
```bash
npm uninstall serialize-to-js
# Use safer alternatives
npm install serialize-javascript
```

### 4. Path Traversal

**Affected Packages**: tar, unzip, adm-zip

**Example**:
```json
{
  "package": "tar",
  "cve": "CVE-2021-32804",
  "severity": "HIGH",
  "title": "Path Traversal",
  "description": "Directory traversal during archive extraction"
}
```

**Remediation**:
```bash
npm install tar@^6.1.2
```

### 5. Cryptographic Weaknesses

**Affected Packages**: node-forge, crypto-js, elliptic

**Example**:
```json
{
  "package": "node-forge",
  "cve": "CVE-2020-7720",
  "severity": "HIGH",
  "title": "Weak Key Generation",
  "description": "Insufficient entropy in RSA key generation"
}
```

**Remediation**:
```bash
npm install node-forge@^0.10.0
# Consider using Node.js built-in crypto module
```

## Remediation Strategies

### Direct Dependencies

**Simple Upgrade**:
```bash
# Upgrade to patched version
npm install package@^version

# Upgrade to latest
npm update package
```

**Breaking Change Review**:
```bash
# Check for breaking changes
npm info package@latest

# Test upgrade
npm install package@latest
npm test
```

### Transitive Dependencies

**npm audit fix**:
```bash
# Apply safe fixes
npm audit fix

# Apply breaking changes (review first!)
npm audit fix --force
```

**Package Overrides** (npm 8.3+):
```json
// package.json
{
  "overrides": {
    "vulnerable-package": "^2.0.0",
    "transitive-dep": {
      "nested-package": "^1.2.3"
    }
  }
}
```

**Yarn Resolutions**:
```json
// package.json
{
  "resolutions": {
    "vulnerable-package": "^2.0.0"
  }
}
```

### Alternative Packages

When packages are deprecated or unmaintained:

```bash
# Uninstall vulnerable package
npm uninstall vulnerable-package

# Install alternative
npm install alternative-package
```

## Integration

### CI/CD Pipeline

**GitHub Actions**:
```yaml
name: Dependency Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          
      - run: npm ci
      
      - name: Run Dependency Audit
        run: |
          ao workflow run ao.security/dependency-audit --output json > audit-report.json
          
      - uses: actions/upload-artifact@v4
        with:
          name: dependency-audit
          path: audit-report.json
          
      - name: Fail on Critical/High
        run: |
          CRITICAL=$(jq '.audit_summary.critical' audit-report.json)
          HIGH=$(jq '.audit_summary.high' audit-report.json)
          
          if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            echo "::error::Found $CRITICAL critical and $HIGH high vulnerabilities"
            exit 1
          fi
```

**GitLab CI**:
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

### Pre-commit Hook

`.git/hooks/pre-commit`:
```bash
#!/bin/bash

# Run dependency audit
echo "Checking dependencies for vulnerabilities..."
ao workflow run ao.security/dependency-audit

if [ $? -ne 0 ]; then
  echo "❌ Critical or high vulnerabilities detected!"
  echo "Run 'npm audit' for details"
  exit 1
fi

echo "✅ Dependency audit passed"
```

### Automated Remediation

**Dependabot** (`.github/dependabot.yml`):
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
```

**Renovate** (`renovate.json`):
```json
{
  "extends": ["config:base"],
  "schedule": ["before 10am on Monday"],
  "packageRules": [
    {
      "matchUpdateTypes": ["patch", "minor"],
      "groupName": "non-breaking updates"
    },
    {
      "matchUpdateTypes": ["major"],
      "labels": ["breaking-change"]
    }
  ]
}
```

## Configuration

Create `.ao/security.yaml` to customize:

```yaml
dependency_auditor:
  enabled: true
  
  # Fail CI on these severities
  fail_on:
    - critical
    - high
  
  # Include development dependencies
  include_dev_dependencies: true
  
  # Exclude packages from audit
  exclude_packages:
    - "@types/*"
    - "eslint-config-*"
  
  # Advisory sources
  advisory_sources:
    - npm
    - github
  
  # Auto-fix options
  auto_fix:
    enabled: false
    breaking_changes: false
  
  # Reporting
  max_findings: 100
  include_patch_level: true
```

## Best Practices

1. **Run Regularly**: Audit on every PR and weekly on main branches
2. **Prioritize by Severity**: Fix critical and high first
3. **Test Upgrades**: Review breaking changes before merging
4. **Minimize Dependencies**: Fewer packages = smaller attack surface
5. **Lock Dependencies**: Commit package-lock.json
6. **Monitor Continuously**: Use Dependabot/Renovate for automated updates
7. **Review Transitive**: Don't ignore indirect dependencies
8. **Document Exceptions**: Track accepted risks with justification
9. **Security Review**: Have security team review major upgrades
10. **Incident Response**: Have a plan for zero-day vulnerabilities

## Troubleshooting

### No Vulnerabilities Found

```bash
# Verify npm audit works
npm audit

# Check registry access
npm config get registry

# Clear cache
npm cache clean --force
```

### Transitive Dependency Issues

```bash
# View dependency tree
npm ls vulnerable-package

# Check for duplicates
npm dedupe

# Force resolution
npm install --force
```

### Breaking Changes

```bash
# Check changelog
npm info package@latest

# View diff
npm diff package@current package@latest

# Test in isolation
npm install package@latest --save-dev
npm test
```

### Private Registry

```bash
# Configure private registry
npm config set registry https://registry.company.com

# Set auth token
npm config set //registry.company.com/:_authToken ${NPM_TOKEN}
```

## Limitations

- **npm Ecosystem Only**: Cannot audit Python, Ruby, Go, or other ecosystems
- **Known CVEs Only**: Cannot detect zero-day or unpublished vulnerabilities
- **Registry Dependency**: Requires access to npm advisory database
- **Static Analysis**: Cannot detect runtime vulnerabilities
- **False Positives**: May report unused code paths
- **Transitive Complexity**: Deep dependency trees can be hard to resolve

## References

- [npm audit Documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)
- [npm Security Advisories](https://www.npmjs.com/advisories)
- [National Vulnerability Database](https://nvd.nist.gov)
- [GitHub Advisory Database](https://github.com/advisories)
- [Snyk Vulnerability Database](https://security.snyk.io)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/launchapp-dev/ao-skill-security/issues
- AO Documentation: https://github.com/launchapp-dev/ao-docs
- npm Security: security@npmjs.com
