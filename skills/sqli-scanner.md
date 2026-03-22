# SQL Injection Scanner

Scan source code for SQL injection vulnerabilities, unsanitized user input in database queries, and ORM misuse patterns using static analysis and pattern detection.

## Overview

This skill performs comprehensive static analysis to detect SQL injection vulnerabilities before they reach production. It identifies dangerous patterns, unsafe query construction, and common ORM misconfigurations that could lead to SQL injection attacks.

## Capabilities

- **Pattern Detection**: Identify dangerous string concatenation in SQL queries
- **Input Flow Analysis**: Trace user input to database operations
- **ORM Safety Check**: Detect unsafe ORM patterns (Sequelize, TypeORM, Prisma, etc.)
- **Framework Detection**: Support for Express, Fastify, NestJS, Django, Flask, Rails
- **Severity Classification**: Rank findings by exploitability and impact
- **Structured Reports**: Output JSON findings with location, severity, and remediation

## Scan Targets

### High Priority
- Raw SQL queries with string interpolation
- User input directly in WHERE clauses
- Dynamic ORDER BY, LIMIT, or OFFSET clauses
- Unsafe stored procedure calls

### Medium Priority
- ORM `raw()` or `query()` method calls
- Database query builders with user input
- Template literals in SQL strings

### Low Priority
- Complex query chains (manual review required)
- Third-party library usage patterns

## Supported Languages

- TypeScript/JavaScript (Node.js)
- Python (Django, SQLAlchemy, raw queries)
- Ruby (Rails ActiveRecord, raw SQL)
- Go (database/sql, GORM, sqlx)
- Java (JDBC, JPA, Hibernate)
- PHP (PDO, Laravel Eloquent)

## Detection Patterns

### 1. String Concatenation in SQL

**JavaScript/TypeScript:**
```javascript
// DANGEROUS
const query = "SELECT * FROM users WHERE id = " + userId;
await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// SAFE
await db.query("SELECT * FROM users WHERE id = $1", [userId]);
await db.query("SELECT * FROM users WHERE email = ?", [email]);
```

**Python:**
```python
# DANGEROUS
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

# SAFE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

### 2. Unsanitized User Input

**Express.js:**
```javascript
// DANGEROUS - req.params, req.query, req.body directly in query
app.get('/users/:id', async (req, res) => {
  const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});

// SAFE - parameterized query
app.get('/users/:id', async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
});
```

### 3. ORM Misuse

**Sequelize:**
```javascript
// DANGEROUS
User.findAll({
  where: sequelize.literal(`id = ${userId}`)
});
await sequelize.query(`SELECT * FROM users WHERE id = ${id}`);

// SAFE
User.findAll({ where: { id: userId } });
await sequelize.query('SELECT * FROM users WHERE id = $1', { bind: [id] });
```

**TypeORM:**
```typescript
// DANGEROUS
repository.query(`SELECT * FROM users WHERE id = ${id}`);

// SAFE
repository.findOne({ where: { id } });
repository.query('SELECT * FROM users WHERE id = $1', [id]);
```

**Prisma:**
```typescript
// DANGEROUS - Prisma allows raw queries
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;

// SAFE
await prisma.user.findUnique({ where: { id } });
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${Prisma.sql`${id}`}`;
```

### 4. Dynamic Query Building

**JavaScript:**
```javascript
// DANGEROUS
let query = "SELECT * FROM products WHERE 1=1";
if (category) query += ` AND category = '${category}'`;
if (minPrice) query += ` AND price >= ${minPrice}`;

// SAFE - use query builder with parameterization
const conditions = [];
const params = [];
if (category) { conditions.push('category = ?'); params.push(category); }
if (minPrice) { conditions.push('price >= ?'); params.push(minPrice); }
const query = `SELECT * FROM products WHERE ${conditions.join(' AND ')}`;
await db.query(query, params);
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct user input in raw SQL, trivially exploitable | `db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`)` |
| **HIGH** | String concatenation with external input | `db.query("SELECT * FROM users WHERE name = '" + userName + "'")` |
| **MEDIUM** | ORM raw/query with potential injection | `sequelize.query(userProvidedSQL)` |
| **LOW** | Complex patterns requiring manual review | Dynamic ORDER BY with validation |
| **INFO** | Best practice suggestions | Missing input validation |

## Output Format

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

## Execution Steps

1. **Initialize Scanner**
   - Load language-specific pattern matchers
   - Configure target directories and file extensions
   - Set up AST parsers for supported languages

2. **File Discovery**
   - Scan source directories for relevant files
   - Filter by language (ts, js, py, rb, go, java, php)
   - Skip test files, node_modules, vendor directories

3. **Pattern Analysis**
   - Parse source files into AST (when possible)
   - Run regex patterns for quick detection
   - Track variable assignments and data flow

4. **Vulnerability Detection**
   - Identify SQL string construction patterns
   - Trace user input sources to sinks
   - Check ORM method calls for unsafe usage
   - Validate parameterization in queries

5. **Severity Assignment**
   - Evaluate exploitability based on context
   - Consider authentication requirements
   - Assess data sensitivity and impact

6. **Generate Report**
   - Compile findings with metadata
   - Include code snippets and line numbers
   - Provide actionable remediation guidance

## Configuration

```yaml
sqli_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - app
    - server
  
  exclude_patterns:
    - "**/*.test.{ts,js}"
    - "**/*.spec.{ts,js}"
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
    typescript:
      enabled: true
      parsers: ["@typescript-eslint/parser"]
    javascript:
      enabled: true
      parsers: ["@babel/parser"]
    python:
      enabled: true
      parsers: ["ast"]
  
  # Custom patterns (regex)
  custom_patterns:
    - pattern: "executeQuery\\([^)]*\\+"
      severity: high
      message: "String concatenation detected in executeQuery"
```

## Integration

### With AO Workflow

```yaml
phases:
  sqli-scan:
    mode: agent
    agent: ao.security.sqli-scanner
    directive: "Scan codebase for SQL injection vulnerabilities"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run SQL injection scan before commit
ao skill run ao.security/sqli-scan --staged
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: SQL Injection Scan
  run: ao skill run ao.security/sqli-scan --output json > sqli-report.json
  
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: sqli-report
    path: sqli-report.json
```

## Best Practices

1. **Parameterize All Queries**: Never concatenate user input into SQL strings
2. **Use ORM Safely**: Prefer ORM methods over raw queries
3. **Validate Input**: Whitelist allowed characters and formats
4. **Least Privilege**: Use database users with minimal permissions
5. **Regular Scanning**: Include in CI/CD pipeline for continuous monitoring

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger: SQL Injection](https://portswigger.net/web-security/sql-injection)
