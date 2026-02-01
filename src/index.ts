#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig, getConfigPath, ConfigError } from './utils/config.js';
import { runScan } from './scanner/index.js';
import { reportConsole } from './reporter/console.js';
import { reportJson } from './reporter/json.js';
import { harden, reportHarden } from './hardener/index.js';
import type { OpenClawConfig } from './utils/types.js';

const VERSION = '0.1.0';

const DEMO_CONFIG: OpenClawConfig = {
  gateway: {
    host: '0.0.0.0',
    port: 18789,
  },
  controlUI: {
    enabled: true,
    dangerousDeviceAuthBypass: true,
  },
  webhooks: {
    enabled: true,
    requireAuth: false,
  },
  channels: {
    whatsapp: {
      dm: { policy: 'open' },
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
      console.error(chalk.gray('\nThe config file contains invalid JSON. Check for:'));
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
      '  Network     Gateway binding, auth tokens, webhooks, control UI\n' +
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
  .action((options) => {
    let config: OpenClawConfig;

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
    }

    const result = runScan(config);

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
  .command('harden')
  .description(
    'Apply security fixes automatically.\n\n' +
      'Fixes that can be applied:\n' +
      '  NET001   Bind gateway to localhost\n' +
      '  NET003   Disable control UI auth bypass\n' +
      '  NET004   Enable webhook authentication\n' +
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
    const scanResult = runScan(config);

    // Apply hardening
    const hardenResult = harden(config, scanResult.findings, {
      dryRun: options.dryRun ?? false,
      strict: options.strict ?? false,
    });

    reportHarden(hardenResult, options.dryRun ?? false);

    if (hardenResult.errors.length > 0) {
      process.exit(1);
    }
  });

program.parse();
