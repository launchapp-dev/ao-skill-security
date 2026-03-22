# Hardcoded Secrets Scanner

The Hardcoded Secrets Scanner is a security scanning skill that detects hardcoded passwords, API keys, AWS credentials, SSH keys, tokens, and other sensitive secrets in source code.

## Overview

This scanner identifies dangerous patterns where sensitive information has been directly embedded in source code, configuration files, or other static files. These hardcoded secrets can be easily extracted by attackers who gain access to the source code repository, leading to unauthorized access, data breaches, and other security incidents.

## What It Detects

### Critical Severity
- **AWS Access Keys** - `AKIAIOSFODNN7EXAMPLE` format credentials
- **AWS Secret Access Keys** - 40-character base64 encoded secrets
- **GCP Service Account Keys** - JSON format credentials
- **Azure Storage Account Keys** - Connection strings
- **Stripe Live Keys** - Payment processing API keys
- **GitHub Personal Access Tokens** - Developer authentication tokens
- **SSH Private Keys** - RSA, DSA, EC, and OPENSSH format keys
- **PGP Private Keys** - Encryption private keys

### High Severity
- **JWT Secrets** - JSON Web Token signing keys
- **API Keys** - Generic service API keys (SendGrid, Twilio, etc.)
- **Encryption Keys** - AES, RSA, and other encryption keys
- **HMAC Secrets** - Message authentication codes
- **OAuth Client Secrets** - Third-party authentication

### Medium Severity
- **Database Passwords** - Hardcoded database credentials
- **Connection Strings** - MySQL, PostgreSQL, Redis, MongoDB URLs
- **Authorization Headers** - Bearer tokens in code
- **Cookie Secrets** - Session encryption keys

### Low Severity
- **Test Fixtures** - Sample credentials in test files
- **Placeholder Values** - Example patterns resembling secrets
- **Configuration Defaults** - Non-sensitive default values

## Supported File Types

| Language/Format | Extensions |
|-----------------|------------|
| JavaScript | `.js`, `.mjs`, `.cjs` |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` |
| Python | `.py` |
| Ruby | `.rb` |
| Go | `.go` |
| Java | `.java` |
| PHP | `.php` |
| Shell | `.sh`, `.bash` |
| YAML | `.yml`, `.yaml` |
| JSON | `.json` |
| Properties | `.properties` |
| Environment | `.env` |
| XML | `.xml` |

## Usage

### Basic Scan

```bash
ao skill run ao.security/secrets-scan
```

### Scan and Fix Workflow

```bash
ao skill run ao.security/secrets-scan-and-fix
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Secrets Scan
  run: ao skill run ao.security/secrets-scan --output json > secrets-report.json
  
- name: Check for Critical Secrets
  run: |
    CRITICAL=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' secrets-report.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical secrets found! Commit rejected."
      exit 1
    fi
```

## Output Example

```json
{
  "findings": [
    {
      "id": "SECRET-001",
      "severity": "CRITICAL",
      "title": "AWS Access Key ID Detected",
      "description": "Hardcoded AWS Access Key ID found in source code.",
      "file": "src/config/aws.ts",
      "line": 15,
      "column": 22,
      "snippet": "const awsKey = 'AKIAXXXXXXXXXXXXXXXXXX';",
      "secret_type": "aws_access_key",
      "cwe": "CWE-798",
      "owasp": "A02:2021 - Cryptographic Failures",
      "remediation": "Use AWS SDK default credential chain or environment variables. Rotate the exposed key immediately."
    }
  ],
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0
  },
  "scanned_files": 127,
  "scan_duration_ms": 1890
}
```

## Configuration

```yaml
hardcoded_secrets_scanner:
  enabled: true
  
  fail_on:
    - critical
    - high
  
  patterns:
    aws_access_key:
      regex: "(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"
      severity: critical
    stripe_key:
      regex: "(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"
      severity: critical
```

## Remediation

### Step 1: Remove the Secret

```javascript
// BEFORE - DANGEROUS
const awsKey = 'AKIAXXXXXXXXXXXXXXXXXX';
const config = { accessKeyId: awsKey };

// AFTER - SAFE
const config = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
};
```

### Step 2: Create Environment File

```bash
# .env (add to .gitignore)
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Step 3: Rotate Exposed Credentials

If a secret was exposed in a public repository:

1. Immediately revoke/rotate the exposed credential
2. Review access logs for unauthorized usage
3. Check for any security implications
4. Create new credentials if necessary

### Step 4: Use Secret Management

For production environments, consider:

- **AWS Secrets Manager** - Store and retrieve secrets
- **HashiCorp Vault** - Centralized secret management
- **AWS Systems Manager Parameter Store** - Simple configuration
- **GitHub Secrets** - For CI/CD pipelines
- **Doppler/1Password** - Developer secret management

## Best Practices

1. **Never commit secrets** - Treat all code as public
2. **Use environment variables** - Store secrets outside code
3. **Enable secret scanning** - Use tools like GitHub Secret Scanning
4. **Rotate regularly** - Implement automated credential rotation
5. **Use least privilege** - Grant minimum necessary permissions
6. **Audit access** - Monitor who accesses sensitive resources
7. **Educate team** - Train on secure secret management

## References

- [OWASP A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
