# Hardcoded Secrets Scanner

Scan source code for hardcoded passwords, API keys, AWS credentials, SSH keys, tokens, and other sensitive secrets using static analysis and pattern detection.

## Overview

This skill performs comprehensive static analysis to detect hardcoded secrets before they reach production. It identifies dangerous patterns such as embedded passwords, API keys, AWS credentials, SSH keys, private tokens, and other sensitive information that should be managed through environment variables or secret management systems.

## Capabilities

- **Pattern Detection**: Identify hardcoded secrets using regex and entropy analysis
- **API Key Detection**: Detect AWS, GCP, Azure, Stripe, GitHub, and other service API keys
- **Credential Detection**: Identify hardcoded passwords, usernames, and connection strings
- **SSH Key Detection**: Find embedded SSH private keys and certificates
- **Token Detection**: Detect authentication tokens, JWT secrets, and session keys
- **Entropy Analysis**: Identify high-entropy strings that may be secrets
- **Framework Detection**: Support for JavaScript, TypeScript, Python, Ruby, Go, Java, PHP
- **Severity Classification**: Rank findings by sensitivity and exposure risk
- **Structured Reports**: Output JSON findings with location, severity, and remediation

## Scan Targets

### Critical Severity
- AWS Access Keys (AKIA...)
- AWS Secret Access Keys
- AWS Session Tokens
- GCP Service Account Keys
- Azure Storage Account Keys
- Stripe API Keys (sk_live..., sk_test...)
- GitHub Personal Access Tokens
- SSH Private Keys
- PGP Private Keys
- Database connection strings with credentials
- OAuth Client Secrets

### High Severity
- Generic API keys and tokens
- Authorization headers with Bearer tokens
- HMAC secrets
- Encryption keys (AES, RSA)
- JWT secrets
- Passwords in configuration files
- Connection strings with embedded credentials

### Medium Severity
- Username/password pairs in code
- Email addresses with associated credentials
- Hardcoded session IDs
- Cookie secrets
- Salt values (if not properly generated)

### Low Severity
- Test fixtures with sample credentials
- Example configuration values
- Placeholder text resembling secrets
- Comments referencing secrets

## Supported Languages

- TypeScript/JavaScript (.ts, .js)
- Python (.py)
- Ruby (.rb)
- Go (.go)
- Java (.java)
- PHP (.php)
- YAML (.yml, .yaml)
- JSON (.json)
- Properties files (.properties)
- ENV files (.env)
- Shell scripts (.sh)

## Detection Patterns

### 1. AWS Credentials

**AWS Access Key ID:**
```javascript
// DANGEROUS - AWS Access Key ID
const AWS_KEY = 'AKIAXXXXXXXXXXXXXXXXXX';
const config = { accessKeyId: 'AKIAXXXXXXXXXXXXXXXXXX' };

// DANGEROUS - AWS Secret Access Key
const secretKey = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';

// SAFE - Environment variables
const config = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
};
```

**Python:**
```python
# DANGEROUS - AWS credentials
aws_access_key = 'AKIAXXXXXXXXXXXXXXXXXX'
aws_secret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

# SAFE - Environment variables or config
import boto3
s3 = boto3.resource('s3')  # Uses IAM role/env vars automatically
```

### 2. Generic API Keys

```javascript
// DANGEROUS - Generic API keys
const apiKey = 'xkeys-prod-1234567890abcdef';
const stripeKey = 'pk_test_REPLACE_WITH_YOUR_STRIPE_KEY';
const sendgridKey = 'SG.REPLACE_WITH_YOUR_SENDGRID_KEY';
const twilioKey = 'SK.REPLACE_WITH_YOUR_TWILIO_KEY';

// SAFE - Environment variables
const apiKey = process.env.STRIPE_API_KEY;
```

### 3. Passwords in Strings

```javascript
// DANGEROUS - Hardcoded passwords
const password = 'SuperSecret123!';
const dbPassword = 'admin123';
const connectionString = 'mysql://admin:password123@localhost:3306/mydb';

// DANGEROUS - Password in connection config
const db = {
  host: 'localhost',
  user: 'admin',
  password: 'secret123'  // HARDCODED PASSWORD
};

// SAFE - Environment variables
const db = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
};
```

### 4. SSH and PGP Keys

```javascript
// DANGEROUS - SSH private key
const sshKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8Qj...
-----END RSA PRIVATE KEY-----`;

// DANGEROUS - SSH key file content
const privateKey = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...';

// DANGEROUS - PGP private key
const pgpKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2
lQHYBF...`;
```

### 5. JWT and Auth Tokens

```javascript
// DANGEROUS - JWT secret
const jwtSecret = 'my-super-secret-jwt-key';
const JWT_SECRET = 'secret12345';
app.set('jwtSecret', 'production-secret-key');

// DANGEROUS - Bearer tokens
const token = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';

// DANGEROUS - Authorization headers
axios.defaults.headers.common['Authorization'] = 'Bearer secret-token-here';
```

### 6. Connection Strings

```python
# DANGEROUS - Database connection strings
conn_string = 'postgresql://user:password@host:5432/database'
conn = 'Server=localhost;Database=mydb;User=admin;Password=secret;'

# DANGEROUS - Redis connection
redis_url = 'redis://default:password123@redis-host:6379/0'

# SAFE - Environment variables
import os
conn_string = os.getenv('DATABASE_URL')
redis_url = os.getenv('REDIS_URL')
```

### 7. High Entropy Strings

```javascript
// DANGEROUS - High entropy strings (likely secrets)
const apiSecret = 'a8f5f167f44f4964e6c998dee827110c';  // MD5-like
const webhookSecret = 'whsec_abcdef1234567890abcdef1234567890';
const encryptionKey = 'k7MDENGbPxRfiCYEXAMPLEKEY==';

// Entropy calculation helps identify:
const likelySecret = 'YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2Rm';  // High entropy
```

### 8. Configuration Files

**YAML (.env):**
```yaml
# DANGEROUS - Hardcoded secrets in config
database:
  username: admin
  password: "secret123"  # HARDCODED PASSWORD
  host: localhost

api:
  key: "xkeys-prod-1234567890abcdef"  # HARDCODED API KEY
  secret: "super-secret-value"  # HARDCODED SECRET

# SAFE - Reference environment variables
database:
  username: "${DB_USER}"
  password: "${DB_PASSWORD}"
  host: "${DB_HOST}"
```

**JSON (.json):**
```json
{
  "database": {
    "username": "admin",
    "password": "secret123"
  }
}
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | AWS/GCP/Azure credentials, SSH private keys, live API keys | `AKIAXXXXXXXXXXXXXXXXXX` |
| **CRITICAL** | Stripe live keys, payment processor credentials | `pk_test_REPLACE_WITH_KEY` |
| **HIGH** | Test/prod API keys, JWT secrets, encryption keys | `JWT_SECRET = 'secret'` |
| **HIGH** | Database credentials in connection strings | `mysql://admin:pass@...` |
| **MEDIUM** | Generic passwords, authorization headers | `password = 'admin'` |
| **LOW** | Test fixtures, example values, placeholder text | `username = 'test'` |
| **INFO** | Comments referencing secrets without values | `// TODO: add API key` |

## Output Format

```json
{
  "findings": [
    {
      "id": "SECRET-001",
      "severity": "CRITICAL",
      "title": "AWS Access Key ID Detected",
      "description": "Hardcoded AWS Access Key ID found in source code. AWS credentials should be stored in environment variables or AWS Secrets Manager, never in source code.",
      "file": "src/config/aws.ts",
      "line": 15,
      "column": 22,
      "snippet": "const awsKey = 'AKIAXXXXXXXXXXXXXXXXXX';",
      "secret_type": "aws_access_key",
      "cwe": "CWE-798",
      "owasp": "A02:2021 - Cryptographic Failures",
      "remediation": "Use AWS SDK default credential chain: process.env.AWS_ACCESS_KEY_ID or IAM roles. Remove the hardcoded credential immediately and rotate the exposed key.",
      "references": [
        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        "https://cwe.mitre.org/data/definitions/798.html"
      ]
    },
    {
      "id": "SECRET-002",
      "severity": "CRITICAL",
      "title": "Hardcoded Database Password",
      "description": "Hardcoded database password found in configuration. Database credentials should be stored in environment variables or secure secret management systems.",
      "file": "src/config/database.ts",
      "line": 8,
      "column": 18,
      "snippet": "password: 'admin123'",
      "secret_type": "password",
      "cwe": "CWE-259",
      "owasp": "A02:2021 - Cryptographic Failures",
      "remediation": "Replace with environment variable: password: process.env.DB_PASSWORD",
      "references": [
        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
      ]
    },
    {
      "id": "SECRET-003",
      "severity": "HIGH",
      "title": "JWT Secret Key Detected",
      "description": "Hardcoded JWT secret found in application code. JWT secrets should be stored securely and rotated regularly.",
      "file": "src/middleware/auth.ts",
      "line": 12,
      "column": 20,
      "snippet": "secret: 'my-super-secret-jwt-key'",
      "secret_type": "jwt_secret",
      "cwe": "CWE-798",
      "owasp": "A02:2021 - Cryptographic Failures",
      "remediation": "Use environment variable: secret: process.env.JWT_SECRET",
      "references": [
        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
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
  "scan_duration_ms": 1890
}
```

## Execution Steps

1. **Initialize Scanner**
   - Load secret detection pattern database
   - Configure target directories and file extensions
   - Set up entropy analysis thresholds
   - Define file-specific detection rules

2. **File Discovery**
   - Scan source directories for relevant files
   - Filter by language and config file types
   - Skip test fixtures, mocks, and example directories
   - Check .gitignore for expected secret locations

3. **Pattern Analysis**
   - Run regex patterns for known secret formats
   - Calculate string entropy for unknown secrets
   - Identify variable names indicating secrets
   - Check for common secret patterns

4. **Validation**
   - Verify secrets match expected formats
   - Check for false positives (example values)
   - Validate against known test patterns
   - Assess context for severity

5. **Generate Report**
   - Compile findings with metadata
   - Include code snippets and line numbers
   - Provide actionable remediation guidance
   - Categorize by severity and secret type

## Configuration

```yaml
hardcoded_secrets_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - app
    - server
    - config
    - scripts
  
  exclude_patterns:
    - "**/*.test.{ts,js}"
    - "**/*.spec.{ts,js}"
    - "**/__tests__/**"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/*.min.js"
    - "**/__mocks__/**"
    - "**/fixtures/**"
    - "**/examples/**"
    - "**/.git/**"
  
  # Severity thresholds
  fail_on:
    - critical
    - high
  
  # Secret detection patterns
  patterns:
    aws_access_key:
      regex: "(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"
      severity: critical
    aws_secret_key:
      regex: "(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
      severity: critical
    stripe_key:
      regex: "(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"
      severity: critical
    github_token:
      regex: "gh[pousr]_[A-Za-z0-9_]{36,}"
      severity: critical
    ssh_private_key:
      regex: "-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"
      severity: critical
    jwt_secret:
      regex: "(jwt[_-]?secret|JWT[_-]?SECRET|secret[_-]?key)[\\s]*[=:][\\s]*['\"][^'\"]{8,}['\"]"
      severity: high
    password_assignment:
      regex: "(password|passwd|pwd|secret)[\\s]*[=:][\\s]*['\"][^'\"]{3,}['\"]"
      severity: medium
  
  # Entropy analysis
  entropy:
    enabled: true
    threshold: 4.5  # Bits per character
    min_length: 20  # Minimum string length to analyze
    exclude_patterns:
      - "^[a-f0-9]{32}$"  # MD5 hashes (not secrets)
      - "^[a-f0-9]{40}$"  # SHA1 hashes (not secrets)
      - "^[a-f0-9]{64}$"  # SHA256 hashes (not secrets)
  
  # Allowlisted values (false positives)
  allowlist:
    - "changeme"
    - "password123"
    - "admin"
    - "secret"
    - "your-password-here"
    - "your-api-key"
    - "test"
    - "undefined"
    - "null"
```

## Integration

### With AO Workflow

```yaml
phases:
  secrets-scan:
    mode: agent
    agent: ao.security.hardcoded-secrets-agent
    directive: "Scan codebase for hardcoded secrets"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run secrets scan before commit
ao skill run ao.security/secrets-scan --staged
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Secrets Scan
  run: ao skill run ao.security/secrets-scan --output json > secrets-report.json
  
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: secrets-report
    path: secrets-report.json

# Fail on CRITICAL or HIGH findings
- name: Check for Critical Secrets
  run: |
    CRITICAL=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' secrets-report.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical secrets found! Commit rejected."
      exit 1
    fi
```

## Remediation Checklist

1. **Immediate Actions**
   - [ ] Identify the exposed secret type and scope
   - [ ] Rotate/revoke the exposed credential immediately
   - [ ] Review access logs for unauthorized usage
   - [ ] Remove the hardcoded secret from source code

2. **Replacement Strategy**
   - [ ] Move secrets to environment variables
   - [ ] Use secret management services (AWS Secrets Manager, HashiCorp Vault)
   - [ ] Update all deployment configurations
   - [ ] Update documentation to reference new secret locations

3. **Prevention Measures**
   - [ ] Add secrets scanner to pre-commit hooks
   - [ ] Enable pre-push scanning in CI/CD
   - [ ] Add .gitignore rules for sensitive files
   - [ ] Implement secret scanning at PR level
   - [ ] Train team on secure secret management

4. **Monitoring**
   - [ ] Enable commit scanning for secrets
   - [ ] Set up alerts for new secret exposure
   - [ ] Monitor for secret rotation compliance
   - [ ] Review scanner findings regularly

## Best Practices

1. **Never Commit Secrets**: Treat source code as public - assume it will be exposed
2. **Use Environment Variables**: Store secrets outside of code in environment variables
3. **Use Secret Management**: Leverage AWS Secrets Manager, Vault, or similar tools
4. **Rotate Regularly**: Implement automated secret rotation where possible
5. **Principle of Least Privilege**: Grant minimum necessary permissions to secrets
6. **Scan Early and Often**: Run secrets detection in pre-commit, pre-push, and CI/CD
7. **Defense in Depth**: Combine multiple detection methods and preventions
8. **Audit Access**: Log and monitor all access to sensitive credentials

## References

- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [AWS Credentials Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [TruffleHog - Secret Scanner](https://github.com/trufflesecurity/trufflehog)
- [Gitleaks - Secret Detection](https://github.com/gitleaks/gitleaks)
- [Detect Secrets](https://github.com/Yelp/detect-secrets)
