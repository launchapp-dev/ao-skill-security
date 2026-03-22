/**
 * Security Scanner Type Definitions
 *
 * Shared interfaces and types for the ao-skill-security scanner pack.
 * These types define the contract for security scanning operations.
 */

/**
 * Severity levels for security findings
 */
export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

/**
 * Categories of security vulnerabilities
 */
export enum VulnerabilityCategory {
  INJECTION = 'injection',
  BROKEN_AUTH = 'broken-auth',
  SENSITIVE_DATA_EXPOSURE = 'sensitive-data-exposure',
  XML_EXTERNAL_ENTITIES = 'xxe',
  BROKEN_ACCESS_CONTROL = 'broken-access-control',
  SECURITY_MISCONFIGURATION = 'security-misconfiguration',
  XSS = 'xss',
  INSECURE_DESERIALIZATION = 'insecure-deserialization',
  VULNERABLE_COMPONENTS = 'vulnerable-components',
  INSUFFICIENT_LOGGING = 'insufficient-logging',
  HARDCODED_SECRETS = 'hardcoded-secrets',
  CRYPTOGRAPHIC_FAILURES = 'cryptographic-failures',
}

/**
 * OWASP Top 10 category mapping
 */
export type OwaspCategory = 'A01' | 'A02' | 'A03' | 'A04' | 'A05' | 'A06' | 'A07' | 'A08' | 'A09' | 'A10';

/**
 * Location information for a finding
 */
export interface FindingLocation {
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
}

/**
 * Evidence supporting a security finding
 */
export interface FindingEvidence {
  code?: string;
  match?: string;
  context?: string;
  cwe?: string;
  cve?: string;
}

/**
 * Remediation recommendation for a finding
 */
export interface Remediation {
  description: string;
  references?: string[];
  codeExample?: string;
}

/**
 * A single security finding from a scanner
 */
export interface SecurityFinding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: VulnerabilityCategory;
  owaspCategory?: OwaspCategory;
  location: FindingLocation;
  evidence?: FindingEvidence;
  remediation?: Remediation;
  confidence: 'high' | 'medium' | 'low';
  metadata?: Record<string, unknown>;
}

/**
 * Scanner configuration options
 */
export interface ScannerOptions {
  /** File patterns to include in scan */
  include?: string[];
  /** File patterns to exclude from scan */
  exclude?: string[];
  /** Minimum severity level to report */
  minSeverity?: Severity;
  /** Enable OWASP category classification */
  classifyOwasp?: boolean;
  /** Custom rules to apply */
  customRules?: ScannerRule[];
  /** Enable parallel processing */
  parallel?: boolean;
  /** Maximum number of workers */
  maxWorkers?: number;
}

/**
 * A scanner rule definition
 */
export interface ScannerRule {
  id: string;
  pattern: string | RegExp;
  message: string;
  severity: Severity;
  category: VulnerabilityCategory;
  owaspCategory?: OwaspCategory;
  confidence?: 'high' | 'medium' | 'low';
}

/**
 * Scanner result containing all findings
 */
export interface ScanResult {
  /** Unique scan identifier */
  scanId: string;
  /** Timestamp when scan started */
  startTime: Date;
  /** Timestamp when scan completed */
  endTime: Date;
  /** Files that were scanned */
  filesScanned: string[];
  /** Total files that were skipped */
  filesSkipped: string[];
  /** All findings from the scan */
  findings: SecurityFinding[];
  /** Summary statistics */
  summary: ScanSummary;
  /** Scanner metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Summary statistics for a scan
 */
export interface ScanSummary {
  totalFilesScanned: number;
  totalFindings: number;
  findingsBySeverity: Record<Severity, number>;
  findingsByCategory: Record<VulnerabilityCategory, number>;
  scanDurationMs: number;
}

/**
 * Scanner interface that all scanners must implement
 */
export interface SecurityScanner {
  /** Scanner name */
  name: string;
  /** Scanner version */
  version: string;
  /** Brief description of what the scanner detects */
  description: string;

  /**
   * Perform a security scan
   * @param filePaths - Array of file paths to scan
   * @param options - Scanner configuration options
   * @returns Promise resolving to scan results
   */
  scan(filePaths: string[], options?: ScannerOptions): Promise<ScanResult>;

  /**
   * Validate scanner configuration
   * @param options - Scanner configuration to validate
   * @returns True if configuration is valid
   */
  validateConfig?(options: ScannerOptions): boolean;
}

/**
 * Factory function type for creating scanners
 */
export type ScannerFactory = (options?: ScannerOptions) => SecurityScanner;

/**
 * Registry of available scanners
 */
export interface ScannerRegistry {
  [scannerName: string]: SecurityScanner;
}

/**
 * Report format options
 */
export type ReportFormat = 'json' | 'sarif' | 'table' | 'csv';

/**
 * Report generation options
 */
export interface ReportOptions {
  format: ReportFormat;
  includeSummary?: boolean;
  sortBy?: 'severity' | 'file' | 'category' | 'ruleId';
  outputPath?: string;
}
