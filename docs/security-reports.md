# Security Report Output System

This document describes the structured security report output system for the AO Security Skill Pack.

## Overview

The security report system generates standardized reports from security scanner findings in multiple formats:

- **JSON Report**: Full-structured report with metadata, findings, and compliance mapping
- **SARIF Report**: GitHub Advanced Security and Azure DevOps compatible format

## Features

- ✅ Multi-format output (JSON and SARIF)
- ✅ Severity classification (Critical, High, Medium, Low, Info)
- ✅ File paths and line numbers for all findings
- ✅ Code snippets with context
- ✅ Remediation recommendations with code examples
- ✅ CWE and OWASP mapping
- ✅ CI/CD integration with exit codes
- ✅ Compliance framework mapping (OWASP Top 10, PCI-DSS, NIST)
- ✅ Finding deduplication
- ✅ Trending and baseline comparison

## Quick Start

### Run Security Scan with Report

```bash
# Run full scan and generate reports
ao workflow run ao.security/scan-and-report

# Output will be in:
# - reports/security-report.json
# - reports/security-report.sarif
```

### Generate Report from Existing Findings

```bash
# If you already have scanner findings
ao skill run ao.security/report \
  --input findings.json \
  --output reports/ \
  --format sarif,json
```

## Report Formats

### JSON Report

The JSON report provides comprehensive information:

```json
{
  "schema": "ao.security.report.v1",
  "metadata": {
    "generated_at": "2024-03-22T10:30:00Z",
    "scanner_version": "0.1.0",
    "project": "my-app",
    "commit_sha": "abc123"
  },
  "summary": {
    "total_findings": 12,
    "by_severity": {
      "critical": 2,
      "high": 3,
      "medium": 4,
      "low": 2,
      "info": 1
    }
  },
  "findings": [...]
}
```

### SARIF Report

SARIF format for GitHub Advanced Security:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "AO Security Scanner",
        "version": "0.1.0"
      }
    },
    "results": [...]
  }]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        run: ao workflow run ao.security/scan-and-report
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/security-report.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - ao workflow run ao.security/scan-and-report
  artifacts:
    reports:
      sast: reports/security-report.sarif
```

## Severity Levels

| Level | SARIF | Exit Code | Description |
|-------|-------|-----------|-------------|
| Critical | error | 10 | Trivially exploitable, severe impact |
| High | error | 8 | Easily exploitable, significant impact |
| Medium | warning | 6 | Exploitable under specific conditions |
| Low | note | 4 | Low exploitability, defense in depth |
| Info | none | 0 | Informational, best practices |

## Exit Codes

The report system uses exit codes to indicate security posture:

- `0` - No findings or only informational
- `4` - Low severity findings
- `6` - Medium severity findings
- `8` - High severity findings
- `10` - Critical severity findings
- `1` - Error during report generation

## Finding Structure

Each finding includes:

- **id**: Unique identifier (AO-SEC-XXX)
- **severity**: Critical/High/Medium/Low/Info
- **title**: Short description
- **description**: Detailed explanation
- **file**: File path
- **line**: Line number
- **column**: Column number
- **snippet**: Code snippet
- **cwe**: CWE identifiers
- **owasp**: OWASP Top 10 categories
- **remediation**: Fix guidance with code example

## Workflows

### ao.security/scan-and-report

Run scanners and generate reports.

### ao.security/full-audit

Full security audit with scan, report, review, and fix.

### ao.security/report-only

Generate report from existing findings.

## Compliance Mapping

Reports automatically map findings to:

- **OWASP Top 10 2021**
- **CWE** (Common Weakness Enumeration)
- **PCI-DSS** (Payment Card Industry)
- **NIST 800-53** (when configured)

## Configuration

```yaml
security_report:
  output:
    formats: [json, sarif]
    directory: reports/
    
  thresholds:
    fail_on: [critical, high]
    warn_on: [medium]
    
  compliance:
    frameworks:
      - owasp_top_10_2021
      - pci_dss
```

## Best Practices

1. **Automate**: Run on every PR and push to main
2. **Fail Fast**: Configure fail-on for critical/high
3. **Track Trends**: Monitor security posture over time
4. **Upload**: Push SARIF to GitHub Advanced Security
5. **Review**: Regularly review and prioritize findings
6. **Remediate**: Use provided fix suggestions

## Troubleshooting

### Empty Reports

- Check that scanners ran successfully
- Verify findings file format
- Check input path configuration

### SARIF Validation Errors

- Ensure SARIF version is 2.1.0
- Validate JSON structure
- Check required fields (tool, results)

### Exit Code Issues

- Review severity threshold configuration
- Check fail_on/warn_on settings
- Verify finding severity levels

## References

- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
