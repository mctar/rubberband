import chalk from 'chalk';
import type { Finding, ScanResult, Severity, ValidationIssue } from '../utils/types.js';
import { countBySeverity } from '../scanner/index.js';
import { formatOpenClawInfo } from '../utils/openclaw.js';

const VERSION = '0.2.0';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

export function reportConsole(result: ScanResult): void {
  console.log(chalk.bold(`\nrubberband v${VERSION}\n`));
  if (result.openClaw) {
    console.log(chalk.gray(formatOpenClawInfo(result.openClaw)));
    console.log();
  }

  if (result.validation && result.validation.length > 0) {
    reportValidation(result.validation);
  }

  if (result.findings.length === 0) {
    console.log(chalk.green('No issues found. Your OpenClaw installation looks secure.\n'));
    printSummary(result);
    return;
  }

  // Sort findings by severity
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low'];
  const sorted = [...result.findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  for (const finding of sorted) {
    printFinding(finding);
  }

  printSummary(result);
}

export function reportValidation(issues: ValidationIssue[]): void {
  console.log(chalk.bold('Config validation\n'));
  for (const issue of issues) {
    const levelLabel = issue.level === 'error' ? chalk.red('ERROR') : chalk.yellow('WARN');
    const lineInfo = issue.line ? ` (line ${issue.line})` : '';
    console.log(`${levelLabel} ${issue.message}${lineInfo}`);
    if (issue.path) {
      console.log(chalk.gray(`  → ${issue.path}`));
    }
    if (issue.recommendation) {
      console.log(chalk.gray(`  → ${issue.recommendation}`));
    }
    console.log();
  }
}

function printFinding(finding: Finding): void {
  const colorFn = SEVERITY_COLORS[finding.severity];
  const label = SEVERITY_LABELS[finding.severity];

  console.log(colorFn(`[${label}]`) + ' ' + finding.title);
  console.log(chalk.gray(`  → ${finding.recommendation}`));
  console.log();
}

function printSummary(result: ScanResult): void {
  const counts = countBySeverity(result.findings);
  const line = '─'.repeat(40);

  console.log(chalk.gray(line));

  const scoreColor =
    result.score >= 80 ? chalk.green : result.score >= 50 ? chalk.yellow : chalk.red;
  console.log(`Score: ${scoreColor.bold(result.score.toString())}/100`);

  const parts: string[] = [];
  if (counts.critical > 0) parts.push(chalk.red(`Critical: ${counts.critical}`));
  if (counts.high > 0) parts.push(chalk.red(`High: ${counts.high}`));
  if (counts.medium > 0) parts.push(chalk.yellow(`Medium: ${counts.medium}`));
  if (counts.low > 0) parts.push(chalk.blue(`Low: ${counts.low}`));

  if (parts.length > 0) {
    console.log(parts.join(' | '));
  }

  if (result.waivedCount && result.waivedCount > 0) {
    console.log(chalk.gray(`Waived: ${result.waivedCount}`));
  }

  console.log(chalk.gray(line));
  console.log();
}
