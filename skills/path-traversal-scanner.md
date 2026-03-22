# Path Traversal & File Inclusion Scanner

## Purpose
Detect file path manipulation vulnerabilities including directory traversal, 
local file inclusion (LFI), and zip slip vulnerabilities in archive handling code.

## Vulnerability Types

### 1. Directory Traversal
- Uses `../` sequences to escape intended directories
- Manipulates file paths to access unauthorized files
- Examples: `../../../etc/passwd`, `....//....//etc/passwd`

### 2. Local File Inclusion (LFI)
- Includes files based on user input without validation
- Can lead to code execution or information disclosure
- Common in PHP `include()`, Node.js `fs.readFile()` with user input

### 3. Zip Slip
- Extracts archive entries with malicious paths
- Overwrites critical files outside target directory
- Path traversal within archive file names

### 4. URL-Based File Inclusion
- Accepts URLs to local/remote files
- Can be exploited via `file://` protocol
- Server-Side Request Forgery (SSRF) adjacent

## Code Patterns to Detect

### JavaScript/TypeScript
```javascript
// VULNERABLE: Direct user input to file operations
app.get('/file', (req, res) => {
  const path = req.query.path;  // User-controlled
  res.sendFile(path);            // No validation
});

// VULNERABLE: Path join without normalization
const filePath = path.join(baseDir, userInput);

// VULNERABLE: Zip slip
zip.entry.forEach(entry => {
  fs.writeFileSync(entry.fileName, entry.getData());  // No path validation
});

// SAFE: Proper validation
const safePath = path.normalize(path.join(baseDir, userInput));
if (!safePath.startsWith(baseDir)) {
  throw new Error('Path traversal detected');
}
```

### Python
```python
# VULNERABLE
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')  # No validation

# SAFE
import os
def safe_path(base_dir, filename):
    filepath = os.path.normpath(os.path.join(base_dir, filename))
    if not filepath.startswith(os.path.abspath(base_dir)):
        raise ValueError('Path traversal detected')
    return filepath
```

### PHP
```php
// VULNERABLE
include($_GET['page'] . '.php');

// SAFE
$allowed = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed)) {
    include($_GET['page'] . '.php');
}
```

## Detection Patterns

### File Operations to Check
- `fs.readFile`, `fs.readFileSync`, `fs.writeFile`
- `readFile`, `writeFile`, `sendFile`
- `include`, `include_once`, `require`, `require_once`
- `fopen`, `file_get_contents`, `file_put_contents`
- Archive extraction: `unzip`, `extract`, `extractAll`
- Path operations: `path.join`, `os.path.join`

### User Input Sources
- Request parameters: `req.query`, `req.params`, `req.body`
- URL path segments
- HTTP headers: `Content-Disposition`, file names
- Cookie values
- Environment variables (sometimes)

### Validation Bypass Techniques
- URL encoding: `%2e%2e%2f`
- Double encoding: `%252e%252e%252f`
- UTF-8 encoding: `..%c0%af`
- Null bytes: `../../../etc/passwd%00.jpg`
- Backslashes on Windows: `..\..\..\`

## Safe Implementation Patterns

### Path Normalization + Prefix Check
```javascript
function safePath(baseDir, userPath) {
  const normalized = path.normalize(path.join(baseDir, userPath));
  const absoluteBase = path.resolve(baseDir);
  if (!normalized.startsWith(absoluteBase + path.sep)) {
    throw new Error('Path traversal attempt detected');
  }
  return normalized;
}
```

### Whitelist Validation
```javascript
const ALLOWED_FILES = new Set(['report.pdf', 'data.json', 'image.png']);

function serveFile(filename) {
  if (!ALLOWED_FILES.has(filename)) {
    throw new Error('File not allowed');
  }
  return fs.readFileSync(path.join(SAFE_DIR, filename));
}
```

### Archive Extraction Protection
```javascript
function safeExtract(zipEntry, targetDir) {
  const entryPath = path.normalize(path.join(targetDir, zipEntry.fileName));
  if (!entryPath.startsWith(path.resolve(targetDir) + path.sep)) {
    throw new Error('Zip slip attempt detected');
  }
  // Safe to extract
  fs.writeFileSync(entryPath, zipEntry.getData());
}
```

## Severity Classification

### CRITICAL
- Direct file read/write with user-controlled path
- No validation on file inclusion
- Zip slip allowing arbitrary file write

### HIGH
- Path operations with weak validation (can be bypassed)
- File operations with partial validation
- URL-based file inclusion

### MEDIUM
- Indirect path manipulation through multiple variables
- Complex path construction with some validation
- Archive operations with minimal checks

### LOW
- Path operations with normalization but no prefix check
- File operations with allowlist that could be bypassed

## Reporting Format

```yaml
vulnerability:
  type: path-traversal | lfi | zip-slip
  severity: critical | high | medium | low
  file: path/to/file.js
  line: 42
  function: handleDownload
  
  code_snippet: |
    const path = req.query.file;
    res.sendFile(path);
  
  user_input_source: req.query.file
  sink: res.sendFile()
  
  remediation: |
    Normalize the path and verify it's within the allowed directory:
    const safePath = path.normalize(path.join(BASE_DIR, req.query.file));
    if (!safePath.startsWith(BASE_DIR)) {
      return res.status(400).send('Invalid path');
    }
  
  references:
    - https://owasp.org/www-community/attacks/Path_Traversal
    - https://cwe.mitre.org/data/definitions/22.html
```

## Testing Recommendations

### Test Cases to Implement
1. Basic traversal: `../../../etc/passwd`
2. Encoded traversal: `%2e%2e%2f%2e%2e%2f`
3. Null byte injection: `../../../etc/passwd%00.jpg`
4. Windows-style: `..\..\..\`
5. Mixed separators: `..%5c..%5c`
6. Archive paths: `zip:../../../malicious.jar!/evil.class`
7. Symlink attacks (if applicable)

### Automated Testing
```javascript
const { expect } = require('chai');

describe('Path traversal protection', () => {
  it('should reject parent directory traversal', () => {
    expect(() => safePath('/app/data', '../../../etc/passwd'))
      .to.throw('Path traversal');
  });
  
  it('should reject URL-encoded traversal', () => {
    expect(() => safePath('/app/data', '%2e%2e%2f%2e%2e%2f'))
      .to.throw('Path traversal');
  });
  
  it('should allow valid files', () => {
    expect(safePath('/app/data', 'report.pdf'))
      .to.equal('/app/data/report.pdf');
  });
});
```
