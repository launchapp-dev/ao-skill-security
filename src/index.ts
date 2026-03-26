/**
 * ao-skill-security Scanner Pack
 *
 * Security scanning skill pack for AO that detects:
 * - OWASP Top 10 vulnerabilities
 * - CVEs in dependencies
 * - Hardcoded secrets and credentials
 * - Authentication/authorization misconfigurations
 */

import {
  Severity,
  VulnerabilityCategory,
  type SecurityFinding,
  type ScannerOptions,
  type ScanResult,
  type ScanSummary,
  type SecurityScanner,
  type ScannerRegistry,
} from './types.js';

export {
  Severity,
  VulnerabilityCategory,
  type FindingLocation,
  type FindingEvidence,
  type Remediation,
  type SecurityFinding,
  type ScannerOptions,
  type ScannerRule,
  type ScanResult,
  type ScanSummary,
  type SecurityScanner,
  type ScannerFactory,
  type ScannerRegistry,
  type ReportFormat,
  type ReportOptions,
} from './types.js';

export { createSecretScanner, type SecretScannerConfig } from './scanners/secret-scanner.js';
export { createDependencyScanner, type DependencyScannerConfig } from './scanners/dependency-scanner.js';
export { createCodeScanner, type CodeScannerConfig } from './scanners/code-scanner.js';
export { createAuthScanner, type AuthScannerConfig } from './scanners/auth-scanner.js';
export { generateReport, type GenerateReportOptions } from './reporters/reporter.js';

/**
 * Scanner registry containing all built-in scanners
 */
const registry: ScannerRegistry = {};

/**
 * Register a scanner with the global registry
 */
export function registerScanner(name: string, scanner: SecurityScanner): void {
  if (registry[name]) {
    throw new Error(`Scanner "${name}" is already registered`);
  }
  registry[name] = scanner;
}

/**
 * Get a registered scanner by name
 */
export function getScanner(name: string): SecurityScanner | undefined {
  return registry[name];
}

/**
 * Get all registered scanner names
 */
export function listScanners(): string[] {
  return Object.keys(registry);
}

/**
 * Create a unified scanner that combines all registered scanners
 */
export function createScanner(_options?: ScannerOptions): SecurityScanner {
  const registeredScanners = listScanners().map((name) => getScanner(name)!);

  if (registeredScanners.length === 0) {
    throw new Error('No scanners registered. Register scanners before creating a unified scanner.');
  }

  return {
    name: 'ao-skill-security',
    version: '0.1.0',
    description: 'Unified security scanner combining OWASP, CVE, secrets, and auth scanners',

    async scan(filePaths: string[], opts?: ScannerOptions): Promise<ScanResult> {
      const startTime = new Date();
      const allFindings: SecurityFinding[] = [];
      const filesScanned: string[] = [];
      const filesSkipped: string[] = [];

      // Run all registered scanners in parallel
      const results = await Promise.all(
        registeredScanners.map(async (scanner) => {
          try {
            return await scanner.scan(filePaths, opts);
          } catch (error) {
            console.error(`Scanner ${scanner.name} failed:`, error);
            return null;
          }
        })
      );

      // Aggregate results
      for (const result of results) {
        if (result) {
          allFindings.push(...result.findings);
          filesScanned.push(...result.filesScanned);
          filesSkipped.push(...result.filesSkipped);
        }
      }

      // Remove duplicates based on ruleId and location
      const uniqueFindings = deduplicateFindings(allFindings);

      const endTime = new Date();

      return {
        scanId: generateScanId(),
        startTime,
        endTime,
        filesScanned: [...new Set(filesScanned)],
        filesSkipped: [...new Set(filesSkipped)],
        findings: uniqueFindings,
        summary: calculateSummary(uniqueFindings, startTime, endTime),
      };
    },

    validateConfig(options: ScannerOptions): boolean {
      return registeredScanners.every(
        (scanner) => !scanner.validateConfig || scanner.validateConfig(options)
      );
    },
  };
}

/**
 * Generate a unique scan ID
 */
function generateScanId(): string {
  return `scan-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Deduplicate findings based on ruleId and file location
 */
function deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();

  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.location.file}:${finding.location.line}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

/**
 * Calculate scan summary statistics
 */
function calculateSummary(
  findings: SecurityFinding[],
  startTime: Date,
  endTime: Date
): ScanSummary {
  const findingsBySeverity: Record<string, number> = {};
  const findingsByCategory: Record<string, number> = {};

  for (const finding of findings) {
    findingsBySeverity[finding.severity] =
      (findingsBySeverity[finding.severity] || 0) + 1;
    findingsByCategory[finding.category] =
      (findingsByCategory[finding.category] || 0) + 1;
  }

  return {
    totalFilesScanned: new Set(findings.map((f) => f.location.file)).size,
    totalFindings: findings.length,
    findingsBySeverity: {
      [Severity.CRITICAL]: findingsBySeverity[Severity.CRITICAL] || 0,
      [Severity.HIGH]: findingsBySeverity[Severity.HIGH] || 0,
      [Severity.MEDIUM]: findingsBySeverity[Severity.MEDIUM] || 0,
      [Severity.LOW]: findingsBySeverity[Severity.LOW] || 0,
      [Severity.INFO]: findingsBySeverity[Severity.INFO] || 0,
    },
    findingsByCategory: {
      [VulnerabilityCategory.INJECTION]: findingsByCategory[VulnerabilityCategory.INJECTION] || 0,
      [VulnerabilityCategory.BROKEN_AUTH]: findingsByCategory[VulnerabilityCategory.BROKEN_AUTH] || 0,
      [VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE]: findingsByCategory[VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE] || 0,
      [VulnerabilityCategory.XML_EXTERNAL_ENTITIES]: findingsByCategory[VulnerabilityCategory.XML_EXTERNAL_ENTITIES] || 0,
      [VulnerabilityCategory.BROKEN_ACCESS_CONTROL]: findingsByCategory[VulnerabilityCategory.BROKEN_ACCESS_CONTROL] || 0,
      [VulnerabilityCategory.SECURITY_MISCONFIGURATION]: findingsByCategory[VulnerabilityCategory.SECURITY_MISCONFIGURATION] || 0,
      [VulnerabilityCategory.XSS]: findingsByCategory[VulnerabilityCategory.XSS] || 0,
      [VulnerabilityCategory.INSECURE_DESERIALIZATION]: findingsByCategory[VulnerabilityCategory.INSECURE_DESERIALIZATION] || 0,
      [VulnerabilityCategory.VULNERABLE_COMPONENTS]: findingsByCategory[VulnerabilityCategory.VULNERABLE_COMPONENTS] || 0,
      [VulnerabilityCategory.INSUFFICIENT_LOGGING]: findingsByCategory[VulnerabilityCategory.INSUFFICIENT_LOGGING] || 0,
      [VulnerabilityCategory.HARDCODED_SECRETS]: findingsByCategory[VulnerabilityCategory.HARDCODED_SECRETS] || 0,
      [VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES]: findingsByCategory[VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES] || 0,
    },
    scanDurationMs: endTime.getTime() - startTime.getTime(),
  };
}

/**
 * Default export is the createScanner factory
 */
export default createScanner;
