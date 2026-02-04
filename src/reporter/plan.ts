import chalk from 'chalk';
import type { OpenClawConfig, ScanContext, ScanResult, Severity } from '../utils/types.js';
import { formatOpenClawInfo } from '../utils/openclaw.js';
import { previewConfigChanges } from '../hardener/index.js';
import { createUnifiedDiff } from '../utils/diff.js';
import { reportValidation } from './console.js';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export function reportPlan(
  result: ScanResult,
  config: OpenClawConfig,
  context: ScanContext,
  strict: boolean
): void {
  console.log(chalk.bold(`\nrubberband plan\n`));
  console.log(chalk.gray(formatOpenClawInfo(result.openClaw)));
  console.log();

  if (result.validation && result.validation.length > 0) {
    reportValidation(result.validation);
  }

  if (result.findings.length === 0) {
    console.log(chalk.green('No issues found. Nothing to plan.\n'));
    return;
  }

  const grouped: Record<Severity, typeof result.findings> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  for (const finding of result.findings) {
    grouped[finding.severity].push(finding);
  }

  for (const severity of SEVERITY_ORDER) {
    const entries = grouped[severity];
    if (entries.length === 0) continue;
    console.log(chalk.bold(`${severity.toUpperCase()} (${entries.length})`));
    for (const finding of entries) {
      const pathInfo = finding.path ? ` [${finding.path}]` : '';
      console.log(`- ${finding.code}: ${finding.title}${pathInfo}`);
      console.log(chalk.gray(`  → ${finding.recommendation}`));
    }
    console.log();
  }

  if (result.waivedCount && result.waivedCount > 0) {
    console.log(chalk.gray(`Waived findings: ${result.waivedCount}\n`));
  }

  const preview = previewConfigChanges(
    config,
    result.findings,
    { dryRun: true, strict },
    context
  );
  const before = JSON.stringify(config, null, 2);
  const after = JSON.stringify(preview.updated, null, 2);

  if (before !== after) {
    console.log(chalk.bold('Config diff preview\n'));
    const diff = createUnifiedDiff(before, after, context.paths.configPath);
    console.log(diff);
  } else {
    console.log(chalk.gray('No config changes to preview.\n'));
  }

  if (preview.nonConfig.length > 0) {
    console.log(chalk.bold('\nNon-config fixes'));
    for (const item of preview.nonConfig) {
      console.log(`- ${item}`);
    }
    console.log();
  }
}
