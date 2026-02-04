#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig, getConfigPath, getStateDirPath, ConfigError } from './utils/config.js';
import { buildScanContext } from './utils/openclaw.js';
import { runScan } from './scanner/index.js';
import { reportConsole } from './reporter/console.js';
import { reportJson } from './reporter/json.js';
import { reportPlan } from './reporter/plan.js';
import { harden, reportHarden } from './hardener/index.js';
import type { OpenClawConfig, ScanContext } from './utils/types.js';
import { validateConfig } from './validator/config.js';
import { addWaiver, loadWaivers, removeWaiver } from './utils/waivers.js';

const VERSION = '0.2.1';

const DEMO_CONFIG: OpenClawConfig = {
  gateway: {
    host: '0.0.0.0',
    port: 18789,
  },
  controlUI: {
    enabled: true,
    dangerousDeviceAuthBypass: true,
  },
  hooks: {
    enabled: true,
    token: '',
  },
  channels: {
    whatsapp: {
      dmPolicy: 'open',
      groups: {
        family: { requireMention: false },
      },
    },
  },
  shell: { enabled: true },
  browser: { enabled: true, sandbox: false },
  logging: { level: 'debug' },
  rateLimit: { enabled: false },
  memory: { persistent: true, encrypted: false },
  skills: [
    {
      name: 'moltbook-skill',
      source: 'community:moltbook',
      verified: false,
      permissions: ['filesystem:write'],
    },
  ],
};

const program = new Command();

program
  .name('rubberband')
  .description(
    'Lightweight security assessment tool for OpenClaw installations.\n\n' +
      'Checks your OpenClaw config for common security misconfigurations\n' +
      'and provides a security score from 0-100.'
  )
  .version(VERSION);

function handleConfigError(error: ConfigError, jsonMode: boolean): never {
  if (jsonMode) {
    console.log(
      JSON.stringify({
        error: error.message,
        code: error.code,
      })
    );
  } else {
    console.error(chalk.red(`\nError: ${error.message}`));

    if (error.code === 'NOT_FOUND') {
      console.error(chalk.gray('\nMake sure OpenClaw is installed, or specify a config path:'));
      console.error(chalk.gray('  rubberband scan --config /path/to/openclaw.json'));
      console.error(chalk.gray('  OPENCLAW_CONFIG_PATH=/path/to/config.json rubberband scan'));
      console.error(chalk.gray('\nOr try the demo mode to see example output:'));
      console.error(chalk.gray('  rubberband scan --demo\n'));
    } else if (error.code === 'PARSE_ERROR') {
      console.error(chalk.gray('\nThe config file contains invalid JSON5. Check for:'));
      console.error(chalk.gray('  - Missing or extra commas'));
      console.error(chalk.gray('  - Unquoted keys or strings'));
      console.error(chalk.gray('  - Trailing commas\n'));
    } else if (error.code === 'PERMISSION_DENIED') {
      console.error(chalk.gray('\nCheck file permissions or run with appropriate access.\n'));
    }
  }
  process.exit(1);
}

program
  .command('scan')
  .description(
    'Run all security checks and output report.\n\n' +
      'Checks performed:\n' +
      '  Network     Gateway binding, auth tokens, hooks, control UI\n' +
      '  Credentials File permissions, plaintext API keys\n' +
      '  Access      DM policies, allowlists, group mentions\n' +
      '  Skills      Malicious skills, dangerous permissions, verification\n' +
      '  Runtime     Logging, rate limits, shell, browser sandbox, memory\n\n' +
      'Exit codes:\n' +
      '  0  No critical issues\n' +
      '  1  Error (config not found, parse error)\n' +
      '  2  Critical security issues found'
  )
  .option('--json', 'Output results as JSON (for CI/CD pipelines)')
  .option('--config <path>', 'Path to OpenClaw config file')
  .option('--demo', 'Run with example insecure config (no OpenClaw needed)')
  .option('--openclaw-version <version>', 'Override detected OpenClaw version')
  .option('--no-version-detect', 'Skip CLI/state/package version detection')
  .action((options) => {
    let config: OpenClawConfig;
    let rawConfig: string | undefined;

    if (options.demo) {
      if (!options.json) {
        console.log(chalk.yellow('\n[Demo mode] Using example insecure configuration\n'));
      }
      config = DEMO_CONFIG;
    } else {
      const configPath = options.config || getConfigPath();
      const result = loadConfig(configPath);

      if (result.error || !result.config) {
        handleConfigError(
          result.error || new ConfigError('Unknown error loading config', 'NOT_FOUND'),
          options.json
        );
      }
      config = result.config;
      rawConfig = result.raw;
    }

    const context = buildScanContext({
      config,
      configPath: options.config,
      versionOverride: options.openclawVersion,
      disableVersionDetect: options.versionDetect === false,
    });
    context.waivers = loadWaivers(context);
    const validation = validateConfig(config, context, rawConfig);
    const result = runScan(config, context);
    result.validation = validation;

    if (options.json) {
      reportJson(result);
    } else {
      reportConsole(result);
    }

    // Exit with non-zero if critical findings (but not in demo mode)
    if (!options.demo) {
      const hasCritical = result.findings.some((f) => f.severity === 'critical');
      if (hasCritical) {
        process.exit(2);
      }
    }
  });

program
  .command('plan')
  .description('Generate a fix plan with grouped findings and config diff preview')
  .option('--config <path>', 'Path to OpenClaw config file')
  .option('--demo', 'Run with example insecure config (no OpenClaw needed)')
  .option('--openclaw-version <version>', 'Override detected OpenClaw version')
  .option('--no-version-detect', 'Skip CLI/state/package version detection')
  .option('--strict', 'Preview strict-mode fixes')
  .action((options) => {
    let config: OpenClawConfig;
    let rawConfig: string | undefined;

    if (options.demo) {
      config = DEMO_CONFIG;
    } else {
      const configPath = options.config || getConfigPath();
      const result = loadConfig(configPath);

      if (result.error || !result.config) {
        handleConfigError(
          result.error || new ConfigError('Unknown error loading config', 'NOT_FOUND'),
          false
        );
      }
      config = result.config;
      rawConfig = result.raw;
    }

    const context = buildScanContext({
      config,
      configPath: options.config,
      versionOverride: options.openclawVersion,
      disableVersionDetect: options.versionDetect === false,
    });
    context.waivers = loadWaivers(context);
    const validation = validateConfig(config, context, rawConfig);
    const result = runScan(config, context);
    result.validation = validation;

    reportPlan(result, config, context, options.strict ?? false);

    if (!options.demo) {
      const hasCritical = result.findings.some((f) => f.severity === 'critical');
      if (hasCritical) {
        process.exit(2);
      }
    }
  });

program
  .command('harden')
  .description(
    'Apply security fixes automatically.\n\n' +
      'Fixes that can be applied:\n' +
      '  NET001   Bind gateway to localhost\n' +
      '  NET003   Disable control UI auth bypass\n' +
      '  NET004   Enable webhook authentication (legacy)\n' +
      '  CRED001  Fix config file permissions (chmod 600)\n' +
      '  CRED003  Fix .env file permissions\n' +
      '  ACCESS001 Set DM policy to pairing\n' +
      '  ACCESS003 Require mentions in groups\n' +
      '  RUN001   Set logging to info level\n' +
      '  RUN003   Enable rate limiting\n' +
      '  RUN004   Enable browser sandbox (--strict)\n' +
      '  RUN006   Disable shell execution (--strict)'
  )
  .option('--dry-run', 'Preview fixes without applying them')
  .option('--strict', 'Apply maximum lockdown (disables shell, enables sandbox)')
  .option('--config <path>', 'Path to OpenClaw config file')
  .option('--openclaw-version <version>', 'Override detected OpenClaw version')
  .option('--no-version-detect', 'Skip CLI/state/package version detection')
  .action((options) => {
    const configPath = options.config || getConfigPath();
    const { config, error } = loadConfig(configPath);

    if (error || !config) {
      handleConfigError(
        error || new ConfigError('Unknown error loading config', 'NOT_FOUND'),
        false
      );
    }

    // First run scan to get findings
    const context = buildScanContext({
      config,
      configPath,
      versionOverride: options.openclawVersion,
      disableVersionDetect: options.versionDetect === false,
    });
    context.waivers = loadWaivers(context);
    const scanResult = runScan(config, context);

    // Apply hardening
    const hardenResult = harden(
      config,
      scanResult.findings,
      {
        dryRun: options.dryRun ?? false,
        strict: options.strict ?? false,
      },
      context
    );

    reportHarden(hardenResult, options.dryRun ?? false);

    if (hardenResult.errors.length > 0) {
      process.exit(1);
    }
  });

program
  .command('ignore')
  .description('Manage waivers for findings')
  .option('--code <code>', 'Finding code to waive (e.g., NET001)')
  .option('--reason <reason>', 'Reason for waiving')
  .option('--days <days>', 'Waiver duration in days', '30')
  .option('--until <date>', 'Waiver expiration date (YYYY-MM-DD)')
  .option('--path <path>', 'Optional path to match (file or config path)')
  .option('--list', 'List active waivers')
  .option('--remove <code>', 'Remove waivers by code')
  .action((options) => {
    const context: ScanContext = {
      openClaw: { version: null, schema: 'unknown', source: 'unknown' },
      paths: {
        configPath: getConfigPath(),
        stateDir: getStateDirPath(),
      },
    };

    if (options.list) {
      const waivers = loadWaivers(context);
      if (waivers.length === 0) {
        console.log('No active waivers.');
        return;
      }
      console.log('\nActive waivers:\n');
      for (const waiver of waivers) {
        const pathInfo = waiver.path ? ` (${waiver.path})` : '';
        console.log(`- ${waiver.code}${pathInfo} until ${waiver.expiresAt}`);
        console.log(`  ${waiver.reason}`);
      }
      console.log();
      return;
    }

    if (options.remove) {
      const { removed } = removeWaiver(context, options.remove, options.path);
      console.log(removed > 0 ? `Removed ${removed} waiver(s).` : 'No matching waivers found.');
      return;
    }

    if (!options.code || !options.reason) {
      console.error('Missing required options. Use --code and --reason, or --list.');
      process.exit(1);
    }

    const now = new Date();
    let expiresAt: Date;
    if (options.until) {
      const parsed = new Date(options.until);
      if (Number.isNaN(parsed.getTime())) {
        console.error('Invalid --until date. Use YYYY-MM-DD.');
        process.exit(1);
      }
      expiresAt = parsed;
    } else {
      const days = Number(options.days);
      if (!Number.isFinite(days) || days <= 0) {
        console.error('Invalid --days value.');
        process.exit(1);
      }
      expiresAt = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
    }

    addWaiver(context, {
      code: options.code,
      reason: options.reason,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      path: options.path,
    });

    console.log(
      `Waived ${options.code}${options.path ? ` (${options.path})` : ''} until ${expiresAt.toISOString()}`
    );
  });

program.parse();
