# SQL Injection Scanner Documentation

## Overview

The SQL Injection Scanner is a static analysis tool that detects SQL injection vulnerabilities in source code before they reach production. It identifies dangerous query construction patterns, traces user input flow to database operations, and detects unsafe ORM usage.

## Installation

The SQL injection scanner is included in the `ao.security` skill pack. To use it:

```bash
# Install the skill pack
ao skill install ao.security

# Run SQL injection scan
ao workflow run ao.security/sqli-scan
```

## Quick Start

### Basic Scan

```bash
# Scan current directory for SQL injection vulnerabilities
ao workflow run ao.security/sqli-scan

# Scan specific directory
ao workflow run ao.security/sqli-scan --input '{"path": "src/api"}'
```

### Scan and Fix

```bash
# Scan for vulnerabilities and automatically create fix tasks
ao workflow run ao.security/sqli-scan-and-fix
```

## Detection Capabilities

### 1. String Concatenation

Detects unsafe SQL string construction:

```javascript
// ❌ DETECTED - String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;

// ❌ DETECTED - Template literal interpolation
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ✅ SAFE - Parameterized query
const query = "SELECT * FROM users WHERE id = ?";
await db.query(query, [userId]);
```

### 2. User Input Tracing

Tracks user input from HTTP requests to database queries:

```javascript
// ❌ DETECTED - Express.js
app.get('/users/:id', async (req, res) => {
  const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});

// ❌ DETECTED - Python Flask
@app.route('/users/<user_id>')
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

// ✅ SAFE - Parameterized
app.get('/users/:id', async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
});
```

### 3. ORM Misuse

Identifies unsafe ORM method calls:

```javascript
// ❌ DETECTED - Sequelize
User.findAll({
  where: sequelize.literal(`id = ${userId}`)
});

// ❌ DETECTED - TypeORM
repository.query(`SELECT * FROM users WHERE id = ${id}`);

// ❌ DETECTED - Prisma
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;

// ✅ SAFE - ORM methods
User.findAll({ where: { id: userId } });
repository.findOne({ where: { id } });
await prisma.user.findUnique({ where: { id } });
```

## Supported Languages & Frameworks

| Language | Frameworks | Database Libraries |
|----------|-----------|-------------------|
| TypeScript/JavaScript | Express, Fastify, NestJS, Koa | pg, mysql, mysql2, sequelize, typeorm, prisma, knex |
| Python | Django, Flask, FastAPI | SQLAlchemy, psycopg2, mysql-connector |
| Ruby | Rails, Sinatra | ActiveRecord, pg, mysql2 |
| Go | net/http, gin, echo | database/sql, GORM, sqlx |
| Java | Spring Boot | JDBC, JPA, Hibernate |
| PHP | Laravel, Symfony | PDO, Eloquent |

## Severity Classification

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | Direct user input in raw SQL, no sanitization | `` db.query(`SELECT * FROM users WHERE id = ${req.params.id}`) `` |
| **HIGH** | String concatenation with external variables | `db.query("SELECT * FROM users WHERE name = '" + name + "'")` |
| **MEDIUM** | ORM raw/query methods that could be unsafe | `sequelize.query(userProvidedSQL)` |
| **LOW** | Patterns requiring manual review | Dynamic ORDER BY with validation |
| **INFO** | Best practice recommendations | Missing input validation |

## Output Format

### JSON Report

```json
{
  "findings": [
    {
      "id": "SQLI-001",
      "severity": "CRITICAL",
      "title": "SQL Injection via User Input",
      "description": "Direct use of req.params.id in SQL query string interpolation",
      "file": "src/routes/users.ts",
      "line": 42,
      "column": 24,
      "snippet": "const query = `SELECT * FROM users WHERE id = ${req.params.id}`;",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection",
      "remediation": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html"
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
SQL Injection Scan Results
==========================

Scanned 127 files in 2.34s

Findings by Severity:
  🔴 CRITICAL: 1
  🟠 HIGH:     2
  🟡 MEDIUM:   1
  🟢 LOW:      1
  ℹ️  INFO:     0

CRITICAL Findings:
──────────────────

[SQLI-001] SQL Injection via User Input
  File: src/routes/users.ts:42:24
  Code: const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  
  Remediation:
    Use parameterized queries:
    db.query('SELECT * FROM users WHERE id = ?', [req.params.id])
  
  References:
    • https://owasp.org/www-community/attacks/SQL_Injection
    • https://cwe.mitre.org/data/definitions/89.html
```

## Configuration

Create a `.ao/security.yaml` file to customize scanning:

```yaml
sqli_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - api
    - server
  
  # Exclude patterns
  exclude_patterns:
    - "**/*.test.{ts,js}"
    - "**/*.spec.{ts,js}"
    - "**/node_modules/**"
    - "**/__tests__/**"
    - "**/migrations/**"
    - "**/seeds/**"
  
  # Fail CI on these severities
  fail_on:
    - critical
    - high
  
  # Language-specific settings
  languages:
    typescript:
      enabled: true
    javascript:
      enabled: true
    python:
      enabled: true
  
  # Custom detection patterns
  custom_patterns:
    - pattern: "rawQuery\\([^)]*\\+"
      severity: high
      message: "String concatenation in rawQuery detected"
```

## Integration

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run SQL injection scan on staged files
ao workflow run ao.security/sqli-scan --staged

# Check exit code
if [ $? -ne 0 ]; then
  echo "SQL injection vulnerabilities detected. Please fix before committing."
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
  sqli-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup AO
        run: |
          curl -fsSL https://get.ao.dev | sh
          
      - name: Run SQL Injection Scan
        run: |
          ao workflow run ao.security/sqli-scan --output json > sqli-report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: sqli-report
          path: sqli-report.json
          
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICALS=$(jq '.summary.critical' sqli-report.json)
          if [ "$CRITICALS" -gt 0 ]; then
            echo "Found $CRITICALS critical SQL injection vulnerabilities!"
            exit 1
          fi
```

### GitLab CI

```yaml
sqli-scan:
  stage: security
  script:
    - ao workflow run ao.security/sqli-scan --output json > sqli-report.json
  artifacts:
    reports:
      sast: sqli-report.json
    expire_in: 1 week
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Remediation Guide

### 1. Use Parameterized Queries

**Before:**
```javascript
const query = `SELECT * FROM users WHERE id = ${userId}`;
await db.query(query);
```

**After:**
```javascript
const query = 'SELECT * FROM users WHERE id = ?';
await db.query(query, [userId]);
```

### 2. Use ORM Safely

**Before:**
```javascript
await sequelize.query(`SELECT * FROM users WHERE email = '${email}'`);
```

**After:**
```javascript
// Option 1: Use ORM model methods
const user = await User.findOne({ where: { email } });

// Option 2: Use parameterized raw query
await sequelize.query(
  'SELECT * FROM users WHERE email = $1',
  { bind: [email] }
);
```

### 3. Validate Dynamic Queries

**Before:**
```javascript
let query = 'SELECT * FROM products WHERE 1=1';
if (category) query += ` AND category = '${category}'`;
```

**After:**
```javascript
const conditions = [];
const params = [];

if (category) {
  conditions.push('category = ?');
  params.push(category);
}

const query = `SELECT * FROM products WHERE ${conditions.join(' AND ')}`;
await db.query(query, params);
```

### 4. Whitelist Dynamic Column Names

**Before:**
```javascript
const query = `SELECT * FROM users ORDER BY ${sortBy}`;
```

**After:**
```javascript
const ALLOWED_SORT_COLUMNS = ['name', 'email', 'created_at'];

if (!ALLOWED_SORT_COLUMNS.includes(sortBy)) {
  throw new Error('Invalid sort column');
}

const query = `SELECT * FROM users ORDER BY ${sortBy}`;
```

## Best Practices

1. **Always Parameterize**: Never concatenate user input into SQL strings
2. **Prefer ORM Methods**: Use model methods over raw queries
3. **Validate Input**: Whitelist allowed values, validate formats
4. **Least Privilege**: Use database users with minimal permissions
5. **Regular Scanning**: Include in CI/CD for continuous monitoring
6. **Security Training**: Educate developers on SQL injection risks

## Limitations

- **Static Analysis Only**: Cannot detect runtime dynamic SQL generation
- **False Positives**: May flag safe code that looks dangerous
- **Framework Knowledge**: Limited to known frameworks and ORMs
- **No Runtime Testing**: Does not attempt actual exploitation

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger: SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP Testing Guide: SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/launchapp-dev/ao-skill-security/issues
- AO Documentation: https://github.com/launchapp-dev/ao-docs
