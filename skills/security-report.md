# Security Report Output System

Generate standardized security reports in JSON and SARIF formats with severity levels, file paths, line numbers, and remediation recommendations. Designed for CI/CD integration and security tool interoperability.

## Overview

This skill produces structured security reports from scanner findings. It transforms raw vulnerability data into standardized formats (JSON and SARIF) that can be consumed by CI/CD pipelines, security dashboards, code scanning tools, and compliance systems.

## Capabilities

- **Multi-Format Output**: Generate reports in JSON and SARIF (Static Analysis Results Interchange Format)
- **Standardized Schema**: Consistent structure with severity, location, and remediation
- **CI/CD Integration**: Exit codes, artifact generation, and pipeline-compatible output
- **Aggregation**: Combine findings from multiple scanners into unified reports
- **Trending**: Track security posture changes over time
- **Compliance Mapping**: Map findings to OWASP, CWE, and compliance frameworks

## Output Formats

### 1. Standard JSON Report

The primary JSON format for programmatic consumption:

```json
{
  "schema": "ao.security.report.v1",
  "metadata": {
    "generated_at": "2024-03-22T10:30:00Z",
    "scanner_version": "0.1.0",
    "project": "my-app",
    "branch": "main",
    "commit_sha": "abc123def456",
    "scan_duration_ms": 5230
  },
  "summary": {
    "total_findings": 12,
    "by_severity": {
      "critical": 2,
      "high": 3,
      "medium": 4,
      "low": 2,
      "info": 1
    },
    "by_category": {
      "sqli": 4,
      "xss": 3,
      "auth": 2,
      "secrets": 2,
      "config": 1
    },
    "files_affected": 8,
    "files_scanned": 156
  },
  "findings": [
    {
      "id": "AO-SEC-001",
      "rule_id": "sqli-string-concat",
      "severity": "critical",
      "confidence": "high",
      "category": "sqli",
      "title": "SQL Injection via String Concatenation",
      "description": "User input 'req.params.id' is directly concatenated into SQL query string, allowing arbitrary SQL execution",
      "file": "src/routes/users.ts",
      "line": 42,
      "column": 24,
      "end_line": 42,
      "end_column": 85,
      "snippet": "const query = `SELECT * FROM users WHERE id = ${req.params.id}`;",
      "code_context": {
        "before": ["app.get('/users/:id', async (req, res) => {", "  try {"],
        "line": "    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;",
        "after": ["    const result = await db.query(query);", "    res.json(result.rows);"]
      },
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021 - Injection"],
      "references": [
        {
          "title": "OWASP SQL Injection",
          "url": "https://owasp.org/www-community/attacks/SQL_Injection"
        },
        {
          "title": "CWE-89: SQL Injection",
          "url": "https://cwe.mitre.org/data/definitions/89.html"
        }
      ],
      "remediation": {
        "description": "Use parameterized queries to prevent SQL injection",
        "fix": "const result = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);",
        "effort": "low",
        "complexity": "trivial"
      },
      "impact": {
        "confidentiality": "high",
        "integrity": "high",
        "availability": "high"
      },
      "exploitability": "easy",
      "tags": ["sqli", "user-input", "database", "injection"],
      "scanner": "ao.security.sqli-scanner",
      "detected_at": "2024-03-22T10:30:01Z"
    }
  ],
  "compliance": {
    "owasp_top_10_2021": {
      "A03:2021 - Injection": 4,
      "A05:2021 - Security Misconfiguration": 2
    },
    "pci_dss": {
      "6.5.1 - Injection flaws": 4
    }
  }
}
```

### 2. SARIF Report

Static Analysis Results Interchange Format for GitHub Advanced Security, Azure DevOps, and other tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "AO Security Scanner",
          "version": "0.1.0",
          "informationUri": "https://github.com/launchapp-dev/ao-skill-security",
          "rules": [
            {
              "id": "sqli-string-concat",
              "name": "SQL Injection via String Concatenation",
              "shortDescription": {
                "text": "User input concatenated into SQL query"
              },
              "fullDescription": {
                "text": "User input is directly concatenated into SQL query string, allowing arbitrary SQL execution. This is a critical security vulnerability that can lead to data exfiltration, modification, or deletion."
              },
              "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
              "help": {
                "text": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])",
                "markdown": "Use **parameterized queries**: `db.query('SELECT * FROM users WHERE id = ?', [userId])`"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "category": "sqli",
                "cwe": ["CWE-89"],
                "owasp": ["A03:2021 - Injection"],
                "severity": "critical"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "sqli-string-concat",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "SQL Injection via String Concatenation: User input 'req.params.id' is directly concatenated into SQL query string"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/routes/users.ts",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 24,
                  "endLine": 42,
                  "endColumn": 85,
                  "snippet": {
                    "text": "const query = `SELECT * FROM users WHERE id = ${req.params.id}`;"
                  }
                }
              }
            }
          ],
          "fixes": [
            {
              "description": {
                "text": "Use parameterized queries to prevent SQL injection"
              },
              "artifactChanges": [
                {
                  "artifactLocation": {
                    "uri": "src/routes/users.ts"
                  },
                  "replacements": [
                    {
                      "deletedRegion": {
                        "startLine": 42,
                        "startColumn": 24,
                        "endLine": 42,
                        "endColumn": 85
                      },
                      "insertedContent": {
                        "text": "const result = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);"
                      }
                    }
                  ]
                }
              ]
            }
          ],
          "properties": {
            "confidence": "high",
            "impact": {
              "confidentiality": "high",
              "integrity": "high",
              "availability": "high"
            }
          }
        }
      ],
      "invocation": {
        "executionSuccessful": true,
        "startTimeUtc": "2024-03-22T10:30:00Z",
        "endTimeUtc": "2024-03-22T10:30:05Z",
        "workingDirectory": "/project"
      }
    }
  ]
}
```

## Severity Levels

| Level | SARIF Level | Exit Code | Description |
|-------|-------------|-----------|-------------|
| **critical** | `error` | 10 | Actively exploited or trivially exploitable, severe impact |
| **high** | `error` | 8 | Easily exploitable, significant impact |
| **medium** | `warning` | 6 | Exploitable under specific conditions, moderate impact |
| **low** | `note` | 4 | Low exploitability or impact, defense in depth |
| **info** | `note` | 0 | Informational, best practice recommendations |

## Report Generation Workflow

1. **Collect Findings**
   - Aggregate findings from all scanner agents
   - Deduplicate findings across files and scanners
   - Normalize severity levels and categories

2. **Enrich Findings**
   - Add code context (lines before/after)
   - Map to compliance frameworks (OWASP, CWE, PCI-DSS)
   - Generate unique finding IDs
   - Calculate confidence scores

3. **Generate Output**
   - Create JSON report with full metadata
   - Generate SARIF for CI/CD integration
   - Produce summary statistics
   - Write reports to artifacts directory

4. **Set Exit Status**
   - Determine exit code based on severity thresholds
   - Configure fail-on thresholds per project

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
        run: |
          ao workflow run ao.security/scan-and-report \
            --output-format sarif \
            --output-path reports/
          
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/security-report.sarif
          
      - name: Upload Report Artifact
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: reports/
          
      - name: Fail on Critical/High
        run: |
          if grep -q '"critical": [1-9]' reports/summary.json || \
             grep -q '"high": [1-9]' reports/summary.json; then
            echo "Critical or High severity findings detected"
            exit 1
          fi
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - ao workflow run ao.security/scan-and-report
      --output-format sarif
      --output-path reports/
  artifacts:
    reports:
      sast: reports/security-report.sarif
    paths:
      - reports/
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Azure DevOps

```yaml
- task: Bash@3
  displayName: 'Security Scan'
  inputs:
    targetType: 'inline'
    script: |
      ao workflow run ao.security/scan-and-report \
        --output-format sarif \
        --output-path $(Build.ArtifactStagingDirectory)/reports/

- task: PublishSarif@1
  displayName: 'Publish SARIF Results'
  inputs:
    SarifFilePattern: '$(Build.ArtifactStagingDirectory)/reports/*.sarif'
    Condition: 'always()'
```

## Configuration

```yaml
security_report:
  # Output settings
  output:
    formats:
      - json
      - sarif
    directory: reports/
    filename_pattern: security-report-{timestamp}
    
  # Severity thresholds
  thresholds:
    fail_on:
      - critical
      - high
    warn_on:
      - medium
      
  # Finding limits
  max_findings: 1000
  max_snippet_lines: 5
  
  # Deduplication
  dedup:
    enabled: true
    scope: file  # file, project, organization
    
  # Compliance mapping
  compliance:
    frameworks:
      - owasp_top_10_2021
      - pci_dss
      - nist_800_53
      
  # SARIF-specific settings
  sarif:
    include_snippets: true
    include_fixes: true
    baseline_root: ${SRCROOT}
```

## Report Schema

### Finding Schema

```typescript
interface SecurityFinding {
  // Identification
  id: string;                    // Unique finding ID (AO-SEC-001)
  rule_id: string;               // Rule that triggered this finding
  
  // Classification
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  category: string;              // sqli, xss, auth, secrets, etc.
  
  // Description
  title: string;
  description: string;
  
  // Location
  file: string;                  // Relative file path
  line: number;
  column: number;
  end_line?: number;
  end_column?: number;
  snippet: string;               // Code snippet showing the issue
  
  // Context
  code_context?: {
    before: string[];
    line: string;
    after: string[];
  };
  
  // Standards mapping
  cwe: string[];                 // CWE identifiers
  owasp: string[];               // OWASP Top 10 categories
  references: Reference[];
  
  // Remediation
  remediation: {
    description: string;
    fix?: string;                // Suggested fix code
    effort: 'trivial' | 'low' | 'medium' | 'high';
    complexity: 'trivial' | 'low' | 'medium' | 'high';
  };
  
  // Impact assessment
  impact: {
    confidentiality: 'none' | 'low' | 'medium' | 'high';
    integrity: 'none' | 'low' | 'medium' | 'high';
    availability: 'none' | 'low' | 'medium' | 'high';
  };
  
  // Metadata
  exploitability?: 'easy' | 'moderate' | 'difficult';
  tags: string[];
  scanner: string;               // Scanner that detected this
  detected_at: string;           // ISO 8601 timestamp
}
```

## Aggregation

Combine findings from multiple scanners:

```json
{
  "aggregated": {
    "sources": [
      {
        "scanner": "ao.security.sqli-scanner",
        "findings_count": 4,
        "scan_time_ms": 1200
      },
      {
        "scanner": "ao.security.secrets-scanner",
        "findings_count": 3,
        "scan_time_ms": 800
      }
    ],
    "deduplication": {
      "total_before": 8,
      "duplicates_removed": 1,
      "total_after": 7
    }
  }
}
```

## Trending

Track security posture over time:

```json
{
  "trend": {
    "previous_scan": {
      "timestamp": "2024-03-21T10:30:00Z",
      "commit_sha": "abc123",
      "total_findings": 15
    },
    "current_scan": {
      "timestamp": "2024-03-22T10:30:00Z",
      "commit_sha": "def456",
      "total_findings": 12
    },
    "delta": {
      "fixed": 5,
      "new": 2,
      "unchanged": 10,
      "trend": "improving"
    }
  }
}
```

## API Usage

### Generate Report from Findings

```bash
# Generate report from scanner output
ao skill run ao.security/report \
  --input findings.json \
  --output reports/ \
  --format sarif,json
  
# With baseline comparison
ao skill run ao.security/report \
  --input findings.json \
  --baseline reports/baseline.json \
  --output reports/
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings, or only informational findings |
| 4 | Low severity findings detected |
| 6 | Medium severity findings detected |
| 8 | High severity findings detected |
| 10 | Critical severity findings detected |
| 1 | Error during report generation |

## Best Practices

1. **Automate in CI/CD**: Run on every pull request and push to main
2. **Set Fail Thresholds**: Fail builds on critical/high findings
3. **Track Trends**: Monitor security posture over time
4. **Upload to Security Tools**: Integrate with GitHub Advanced Security, SonarQube, etc.
5. **Review Regularly**: Schedule periodic security reviews
6. **Baseline Management**: Maintain baselines to focus on new issues
7. **Remediation Tracking**: Use report data to track fix progress

## Integration Examples

### SonarQube

Convert SARIF to SonarQube format for import into existing quality gates.

### DefectDojo

Push findings to DefectDojo for vulnerability management and tracking.

### Jira

Create tickets automatically for critical/high findings with remediation details.

## References

- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
