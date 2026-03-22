# Unsafe Deserialization & Prototype Pollution Scanner

Scan source code for unsafe deserialization patterns, insecure pickle/yaml.loads usage, and JavaScript prototype pollution vulnerabilities using static analysis and pattern detection.

## Overview

This skill performs comprehensive static analysis to detect dangerous deserialization vulnerabilities and JavaScript prototype pollution attacks before they reach production. It identifies insecure usage of pickle, yaml, marshal, JSON, and other deserialization methods that could lead to remote code execution attacks.

## Capabilities

- **Python Deserialization**: Detect unsafe pickle.loads, yaml.load, marshal.loads patterns
- **JavaScript Prototype Pollution**: Identify dangerous object merge and prototype modification patterns
- **Java Deserialization**: Detect ObjectInputStream.readObject and XStream vulnerabilities
- **Ruby Deserialization**: Find Marshal.load and YAML.load security issues
- **.NET Deserialization**: Identify BinaryFormatter.Deserialize vulnerabilities
- **PHP Unserialize**: Detect unsafe unserialize() usage
- **Severity Classification**: Rank findings by exploitability and impact
- **Structured Reports**: Output JSON findings with location, severity, and remediation

## Scan Targets

### Critical Priority (Remote Code Execution Risk)

- Python `pickle.loads()` with untrusted data
- Python `yaml.load()` without SafeLoader
- Java `ObjectInputStream.readObject()`
- .NET `BinaryFormatter.Deserialize()`
- Ruby `Marshal.load()` with user input
- PHP `unserialize()` with user-controlled data

### High Priority

- JavaScript prototype pollution via `__proto__`
- JavaScript deep merge without key sanitization
- Java `XStream.fromXML()` without security framework
- Python `marshal.loads()` with untrusted data

### Medium Priority

- JavaScript `Object.assign()` with unsanitized source
- Java `JSON.parse()` with remote class loading enabled
- Complex deserialization chains

### Low Priority

- Safe deserialization with partial mitigations
- Third-party library usage patterns
- Test/Mock code with unsafe patterns

## Supported Languages

- Python (pickle, yaml, marshal)
- JavaScript/TypeScript (prototype pollution)
- Java (ObjectInputStream, XStream, Kryo)
- Ruby (Marshal, YAML/ Psych)
- .NET (BinaryFormatter, LosFormatter)
- PHP (unserialize)

## Detection Patterns

### 1. Python - Unsafe Pickle

```python
# DANGEROUS - Remote code execution risk
import pickle
data = pickle.loads(user_provided_bytes)
obj = pickle.load(open('data.pkl', 'rb'))

# SAFE - With signature verification
import hmac
import hashlib
import pickle

def safe_pickle_loads(data, signature, secret_key):
    expected = hmac.new(secret_key, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid pickle signature")
    return pickle.loads(data)

# SAFE - Restricted unpickler
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module.startswith('_'):
            raise pickle.UnpicklingError(f"Module '{module}' is forbidden")
        return super().find_class(module, name)

def safe_load(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

### 2. Python - Unsafe YAML

```python
# DANGEROUS
import yaml
data = yaml.load(user_yaml_string)  # No Loader specified
data = yaml.load(user_yaml_string, Loader=yaml.FullLoader)  # Not fully safe

# SAFE
import yaml
data = yaml.safe_load(user_yaml_string)  # Uses SafeLoader
data = yaml.load(user_yaml_string, Loader=yaml.SafeLoader)

# For untrusted input, use yaml.unsafe_load with caution:
# yaml.unsafe_load() - Only if you trust the source completely
```

### 3. JavaScript - Prototype Pollution

```javascript
// DANGEROUS - Prototype pollution via JSON.parse
const userInput = '{"__proto__": {"admin": true}}';
const obj = JSON.parse(userInput); // Adds admin to Object.prototype!

// DANGEROUS - Merge function without sanitization
function unsafeMerge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = unsafeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// DANGEROUS - Object.assign without check
const config = {};
Object.assign(config, userProvidedObject);

// SAFE - Block dangerous properties
const DANGEROUS_PROPS = ['__proto__', 'constructor', 'prototype'];

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (!DANGEROUS_PROPS.includes(key)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        target[key] = safeMerge(target[key] || {}, source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

// SAFE - Deep clone without pollution
function safeDeepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}
```

### 4. Java - Unsafe Deserialization

```java
// DANGEROUS
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// SAFE - Use secure JSON alternatives
ObjectMapper mapper = new ObjectMapper();
mapper.disableDefaultTyping();
MyObject obj = mapper.readValue(inputStream, MyObject.class);

// SAFE - XStream with security framework
XStream xstream = new XStream();
// Add permissions to restrict allowed types
xstream.addPermission(NoTypePermission.NONE);
xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
xstream.addPermission(NullPermission.NULL);
xstream.addPermission(ArrayPermission.INSTANCE);
xstream.addPermission(CollectionPermission.INTERNAL_EMPTY_COLLECTION);
xstream.addPermission(CollectionPermission.INTERNAL_EMPTY_MAP);
xstream.addPermission(ReflectionPermission.BASIC);
xstream.addPermission(SerializableVersionablePermission.CHECK);
```

### 5. Ruby - Unsafe Marshal

```ruby
# DANGEROUS
data = Marshal.load(user_provided_string)
data = YAML.load(user_yaml_string)  # Without safe_load

# SAFE
data = Marshal.load(user_provided_string, permitted_classes: [MyClass])
data = YAML.safe_load(user_yaml_string, permitted_classes: [MyClass])
```

### 6. .NET - Unsafe BinaryFormatter

```csharp
// DANGEROUS
var formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

// SAFE - Use JSON serializers
var serializer = new JsonSerializer();
object obj = serializer.Deserialize(stream);

// Or DataContractSerializer with known types
var ser = new DataContractSerializer(typeof(MyType), knownTypes);
```

### 7. PHP - Unsafe Unserialize

```php
// DANGEROUS
$data = unserialize($_GET['data']);

// SAFE - Use JSON
$data = json_decode($_GET['data']);

// SAFE - Unserialize with allowed classes
$data = unserialize($data, ['allowed_classes' => ['MyClass', 'OtherClass']]);
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct user input in pickle/yaml.loads, trivially exploitable RCE | `pickle.loads(request.data)` |
| **HIGH** | Unsafe deserialization with indirect user input | `yaml.load(db_result)` |
| **MEDIUM** | Prototype pollution with limited impact | `Object.assign({}, userInput)` |
| **LOW** | Complex patterns requiring specific conditions | Library usage patterns |
| **INFO** | Best practice suggestions | Missing input validation |

## Output Format

```json
{
  "findings": [
    {
      "id": "DESER-001",
      "severity": "CRITICAL",
      "title": "Unsafe Pickle Deserialization",
      "description": "pickle.loads() called with potentially untrusted data without signature verification",
      "file": "src/serialization.py",
      "line": 42,
      "column": 15,
      "snippet": "data = pickle.loads(user_provided_bytes)",
      "cwe": "CWE-502",
      "owasp": "A08:2021 - Software and Data Integrity Failures",
      "remediation": "Use pickle.loads(signed_data) with cryptographic signature verification, or use JSON with restricted unpickler",
      "references": [
        "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
        "https://cwe.mitre.org/data/definitions/502.html"
      ]
    },
    {
      "id": "DESER-002",
      "severity": "HIGH",
      "title": "Prototype Pollution via Object Merge",
      "description": "Deep merge function allows modification of Object.prototype via __proto__ property",
      "file": "src/utils/merge.ts",
      "line": 15,
      "column": 10,
      "snippet": "function merge(target, source) { ... }",
      "cwe": "CWE-1321",
      "owasp": "A03:2021 - Injection",
      "remediation": "Add checks to prevent dangerous properties: if (!['__proto__', 'constructor', 'prototype'].includes(key))",
      "references": [
        "https://portswigger.net/web-security/prototype-pollution",
        "https://cwe.mitre.org/data/definitions/1321.html"
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
   - Set up detection rules for each language

2. **File Discovery**
   - Scan source directories for relevant files
   - Filter by language (.py, .js, .ts, .java, .rb, .cs, .php)
   - Skip test files, node_modules, vendor directories

3. **Pattern Analysis**
   - Run regex patterns for deserialization patterns
   - Parse source files for AST analysis when possible
   - Track variable assignments and data flow
   - Identify user input sources and sinks

4. **Vulnerability Detection**
   - Match dangerous deserialization patterns
   - Evaluate context and exploitability
   - Check for safe alternatives and mitigations
   - Identify prototype pollution entry points

5. **Severity Assignment**
   - Evaluate exploitability based on context
   - Consider authentication requirements
   - Assess remote code execution potential
   - Evaluate impact on application security

6. **Generate Report**
   - Compile findings with metadata
   - Include code snippets and line numbers
   - Provide actionable remediation guidance
   - Output structured JSON format

## Configuration

```yaml
deserialization_scanner:
  enabled: true
  
  # Scan scope
  scan_directories:
    - src
    - lib
    - app
    - server
  
  exclude_patterns:
    - "**/*.test.{ts,js,py}"
    - "**/*.spec.{ts,js,py}"
    - "**/__tests__/**"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/migrations/**"
  
  # Severity thresholds
  fail_on:
    - critical
    - high
  
  # Language-specific settings
  languages:
    python:
      enabled: true
      check_pickle: true
      check_yaml: true
      check_marshal: true
    javascript:
      enabled: true
      check_prototype_pollution: true
      check_json_parse: true
    java:
      enabled: true
      check_object_input_stream: true
      check_xstream: true
    ruby:
      enabled: true
      check_marshal: true
      check_yaml: true
    dotnet:
      enabled: true
      check_binary_formatter: true
    php:
      enabled: true
      check_unserialize: true
  
  # Custom patterns (regex)
  custom_patterns:
    - pattern: "pickle\\.loads\\([^)]*\\)"
      severity: critical
      message: "Unsafe pickle deserialization detected"
```

## Integration

### With AO Workflow

```yaml
phases:
  deserialization-scan:
    mode: agent
    agent: ao.security.deserialization-scanner
    directive: "Scan codebase for unsafe deserialization patterns"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run deserialization scan before commit
ao skill run ao.security/deserialization-scan --staged
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Deserialization Scan
  run: ao skill run ao.security/deserialization-scan --output json > deser-report.json

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: deserialization-report
    path: deser-report.json
```

## Best Practices

1. **Avoid Pickle for Untrusted Data**: Never use pickle.loads() with data from untrusted sources
2. **Use yaml.safe_load()**: Always use SafeLoader for YAML from untrusted sources
3. **Protect JavaScript Objects**: Sanitize object keys before merging
4. **Prefer JSON**: Use JSON serialization over binary formats when possible
5. **Validate Signatures**: If using pickle, implement cryptographic signature verification
6. **Restrict Classes**: Use allowed_classes options in deserialization when supported
7. **Update Dependencies**: Keep deserialization libraries up to date
8. **Regular Scanning**: Include in CI/CD pipeline for continuous monitoring

## References

- [OWASP Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [PortSwigger: Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [PayloadsAllTheThings: Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [James Kettle: Deserialization Intro](https://www.youtube.com/watch?v=Nh4A8wN2tRk)
