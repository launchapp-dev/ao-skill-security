# ao-skill-security

Security scanning skill pack for AO that detects:
- OWASP Top 10 vulnerabilities
- CVEs in dependencies
- Hardcoded secrets and credentials
- Authentication/authorization misconfigurations

## Installation

```bash
npm install
```

## Build

```bash
npm run build
```

## Type Checking

```bash
npm run typecheck
```

## Testing

```bash
npm test
```

## Usage

```typescript
import { createScanner, Severity } from 'ao-skill-security';

const scanner = createScanner();
const result = await scanner.scan(['src/**/*.ts'], {
  minSeverity: Severity.HIGH,
});

console.log(`Found ${result.summary.totalFindings} issues`);
```

## Scanners

This pack includes four specialized scanners:

1. **Secret Scanner** - Detects hardcoded secrets, API keys, passwords
2. **Dependency Scanner** - Checks for CVE vulnerabilities in dependencies
3. **Code Scanner** - Analyzes code for OWASP Top 10 vulnerabilities
4. **Auth Scanner** - Finds authentication and authorization issues

## Report Formats

Reports can be generated in multiple formats:

- `json` - Machine-readable JSON
- `sarif` - Standard static analysis format
- `table` - Human-readable table
- `csv` - Spreadsheet-compatible CSV

## License

MIT
