/**
 * Reporter Module
 *
 * Generates security scan reports in various formats:
 * - JSON: Machine-readable format
 * - SARIF: Standard for static analysis results
 * - Table: Human-readable table format
 * - CSV: Spreadsheet-compatible format
 */

import {
  Severity,
  type ScanResult,
  type ReportFormat,
  type SecurityFinding,
} from '../types.js';

/**
 * Options for report generation
 */
export interface GenerateReportOptions {
  /** Output format for the report */
  format: ReportFormat;
  /** Include summary statistics */
  includeSummary?: boolean;
  /** Sort findings by this field */
  sortBy?: 'severity' | 'file' | 'category' | 'ruleId';
  /** Output file path (if not specified, returns string) */
  outputPath?: string;
  /** Include only findings at or above this severity */
  minSeverity?: Severity;
}

/**
 * Sort order mapping for severity
 */
const SEVERITY_ORDER: Record<string, number> = {
  [Severity.CRITICAL]: 0,
  [Severity.HIGH]: 1,
  [Severity.MEDIUM]: 2,
  [Severity.LOW]: 3,
  [Severity.INFO]: 4,
};

/**
 * Sort findings based on criteria
 */
function sortFindings(
  findings: SecurityFinding[],
  sortBy: string
): SecurityFinding[] {
  return [...findings].sort((a, b) => {
    switch (sortBy) {
      case 'severity':
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      case 'file':
        return a.location.file.localeCompare(b.location.file);
      case 'category':
        return a.category.localeCompare(b.category);
      case 'ruleId':
        return a.ruleId.localeCompare(b.ruleId);
      default:
        return 0;
    }
  });
}

/**
 * Generate a report from scan results
 */
export function generateReport(
  result: ScanResult,
  options: GenerateReportOptions
): string {
  const {
    format,
    includeSummary = true,
    sortBy = 'severity',
    minSeverity = Severity.INFO,
  } = options;

  // Filter and sort findings
  let findings = result.findings.filter(
    (f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[minSeverity]
  );
  findings = sortFindings(findings, sortBy);

  switch (format) {
    case 'json':
      return generateJsonReport(result, findings, includeSummary);
    case 'sarif':
      return generateSarifReport(findings);
    case 'table':
      return generateTableReport(result, findings, includeSummary);
    case 'csv':
      return generateCsvReport(findings);
    default:
      throw new Error(`Unsupported report format: ${format}`);
  }
}

/**
 * Generate JSON format report
 */
function generateJsonReport(
  result: ScanResult,
  findings: SecurityFinding[],
  includeSummary: boolean
): string {
  const report: Record<string, unknown> = {
    scanId: result.scanId,
    startTime: result.startTime,
    endTime: result.endTime,
    filesScanned: result.filesScanned,
    filesSkipped: result.filesSkipped,
    findings,
  };

  if (includeSummary) {
    report.summary = result.summary;
  }

  return JSON.stringify(report, null, 2);
}

/**
 * Generate SARIF (Static Analysis Results Interchange Format) report
 */
function generateSarifReport(findings: SecurityFinding[]): string {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'ao-skill-security',
            version: '0.1.0',
            informationUri: 'https://github.com/launchapp-dev/ao-skill-security',
            rules: findings.map((f) => ({
              id: f.ruleId,
              name: f.title,
              shortDescription: {
                text: f.description,
              },
              properties: {
                tags: [f.category, f.owaspCategory || ''].filter(Boolean),
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: severityToSarifLevel(f.severity),
          message: {
            text: f.description,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.location.file,
                },
                region: {
                  startLine: f.location.line,
                  startColumn: f.location.column || 1,
                  endLine: f.location.endLine,
                  endColumn: f.location.endColumn,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Convert severity to SARIF level
 */
function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH:
      return 'error';
    case Severity.MEDIUM:
      return 'warning';
    case Severity.LOW:
    case Severity.INFO:
      return 'note';
    default:
      return 'warning';
  }
}

/**
 * Generate human-readable table report
 */
function generateTableReport(
  result: ScanResult,
  findings: SecurityFinding[],
  includeSummary: boolean
): string {
  const lines: string[] = [];

  lines.push('═'.repeat(80));
  lines.push('SECURITY SCAN REPORT');
  lines.push('═'.repeat(80));

  if (includeSummary) {
    lines.push('');
    lines.push('SUMMARY');
    lines.push('─'.repeat(40));
    lines.push(`Total Files Scanned: ${result.summary.totalFilesScanned}`);
    lines.push(`Total Findings:       ${result.summary.totalFindings}`);
    lines.push(`Scan Duration:       ${result.summary.scanDurationMs}ms`);
    lines.push('');
    lines.push('Findings by Severity:');
    for (const [severity, count] of Object.entries(result.summary.findingsBySeverity)) {
      if (count > 0) {
        lines.push(`  ${severity.toUpperCase().padEnd(10)}: ${count}`);
      }
    }
    lines.push('');
  }

  if (findings.length > 0) {
    lines.push('FINDINGS');
    lines.push('─'.repeat(40));

    for (const finding of findings) {
      lines.push('');
      lines.push(`[${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push(`  Rule ID:  ${finding.ruleId}`);
      lines.push(`  Category: ${finding.category}`);
      lines.push(`  Location: ${finding.location.file}:${finding.location.line}`);
      lines.push(`  ${finding.description}`);
      if (finding.remediation) {
        lines.push(`  Remediation: ${finding.remediation.description}`);
      }
    }
  } else {
    lines.push('');
    lines.push('No security findings detected.');
  }

  lines.push('');
  lines.push('═'.repeat(80));

  return lines.join('\n');
}

/**
 * Generate CSV format report
 */
function generateCsvReport(findings: SecurityFinding[]): string {
  const headers = [
    'Rule ID',
    'Severity',
    'Category',
    'File',
    'Line',
    'Title',
    'Description',
  ];

  const lines = [headers.join(',')];

  for (const finding of findings) {
    const row = [
      escapeCsv(finding.ruleId),
      finding.severity,
      finding.category,
      escapeCsv(finding.location.file),
      String(finding.location.line),
      escapeCsv(finding.title),
      escapeCsv(finding.description),
    ];
    lines.push(row.join(','));
  }

  return lines.join('\n');
}

/**
 * Escape a value for CSV format
 */
function escapeCsv(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
