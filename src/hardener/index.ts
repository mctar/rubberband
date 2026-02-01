import chalk from 'chalk';
import type { Finding, OpenClawConfig, HardenOptions, HardenResult } from '../utils/types.js';
import {
  saveConfig,
  getConfigPath,
  setFilePermissions,
  getStateDirPath,
  fileExists,
} from '../utils/config.js';
import { join } from 'node:path';

type HardenFn = (config: OpenClawConfig, options: HardenOptions) => boolean;

const HARDENERS: Record<string, { fn: HardenFn; strictOnly?: boolean; description: string }> = {
  NET001: {
    fn: (config) => {
      if (!config.gateway) config.gateway = {};
      config.gateway.host = '127.0.0.1';
      return true;
    },
    description: 'Bind gateway to localhost',
  },
  NET003: {
    fn: (config) => {
      if (!config.controlUI) config.controlUI = {};
      config.controlUI.dangerousDeviceAuthBypass = false;
      return true;
    },
    description: 'Disable control UI auth bypass',
  },
  NET004: {
    fn: (config) => {
      if (!config.webhooks) config.webhooks = {};
      config.webhooks.requireAuth = true;
      return true;
    },
    description: 'Enable webhook authentication',
  },
  CRED001: {
    fn: () => {
      const configPath = getConfigPath();
      setFilePermissions(configPath, 0o600);
      return true;
    },
    description: 'Fix config file permissions (chmod 600)',
  },
  CRED003: {
    fn: () => {
      const envPath = join(getStateDirPath(), '.env');
      if (fileExists(envPath)) {
        setFilePermissions(envPath, 0o600);
        return true;
      }
      return false;
    },
    description: 'Fix .env file permissions (chmod 600)',
  },
  CRED004: {
    fn: () => {
      const stateDir = getStateDirPath();
      setFilePermissions(stateDir, 0o700);
      return true;
    },
    description: 'Fix state directory permissions (chmod 700)',
  },
  ACCESS001: {
    fn: (config) => {
      if (!config.channels) return false;
      for (const channel of Object.values(config.channels)) {
        if (channel.dm?.policy === 'open') {
          channel.dm.policy = 'pairing';
        }
      }
      return true;
    },
    description: 'Set DM policy to pairing',
  },
  ACCESS003: {
    fn: (config) => {
      if (!config.channels) return false;
      for (const channel of Object.values(config.channels)) {
        if (channel.groups) {
          for (const group of Object.values(channel.groups)) {
            group.requireMention = true;
          }
        }
      }
      return true;
    },
    description: 'Require mentions in groups',
  },
  RUN001: {
    fn: (config) => {
      if (!config.logging) config.logging = {};
      config.logging.level = 'info';
      return true;
    },
    description: 'Set logging level to info',
  },
  RUN003: {
    fn: (config) => {
      if (!config.rateLimit) config.rateLimit = {};
      config.rateLimit.enabled = true;
      return true;
    },
    description: 'Enable rate limiting',
  },
  RUN004: {
    fn: (config) => {
      if (!config.browser) config.browser = {};
      config.browser.sandbox = true;
      return true;
    },
    strictOnly: true,
    description: 'Enable browser sandbox',
  },
  RUN005: {
    fn: (config) => {
      if (!config.browser) config.browser = {};
      config.browser.headless = true;
      return true;
    },
    description: 'Enable headless browser mode',
  },
  RUN006: {
    fn: (config) => {
      if (!config.shell) config.shell = {};
      config.shell.enabled = false;
      return true;
    },
    strictOnly: true,
    description: 'Disable shell execution',
  },
  RUN008: {
    fn: (config) => {
      if (!config.memory) config.memory = {};
      config.memory.encrypted = true;
      return true;
    },
    description: 'Enable memory encryption',
  },
};

export function harden(
  config: OpenClawConfig,
  findings: Finding[],
  options: HardenOptions
): HardenResult {
  const result: HardenResult = {
    applied: [],
    skipped: [],
    errors: [],
  };

  const fixableFindings = findings.filter((f) => f.fixable);

  for (const finding of fixableFindings) {
    const hardener = HARDENERS[finding.code];

    if (!hardener) {
      result.skipped.push(`${finding.code}: No automatic fix available`);
      continue;
    }

    if (hardener.strictOnly && !options.strict) {
      result.skipped.push(`${finding.code}: Requires --strict mode`);
      continue;
    }

    if (options.dryRun) {
      result.applied.push(`${finding.code}: ${hardener.description} (dry run)`);
      continue;
    }

    try {
      const success = hardener.fn(config, options);
      if (success) {
        result.applied.push(`${finding.code}: ${hardener.description}`);
      } else {
        result.skipped.push(`${finding.code}: Condition not met`);
      }
    } catch (err) {
      result.errors.push(
        `${finding.code}: ${err instanceof Error ? err.message : 'Unknown error'}`
      );
    }
  }

  // Save config changes if not dry run
  if (!options.dryRun && result.applied.length > 0) {
    try {
      saveConfig(config);
    } catch (err) {
      result.errors.push(
        `Failed to save config: ${err instanceof Error ? err.message : 'Unknown error'}`
      );
    }
  }

  return result;
}

export function reportHarden(result: HardenResult, dryRun: boolean): void {
  console.log(chalk.bold(`\nrubberband harden${dryRun ? ' --dry-run' : ''}\n`));

  if (result.applied.length > 0) {
    console.log(chalk.green.bold(dryRun ? 'Would apply:' : 'Applied:'));
    for (const item of result.applied) {
      console.log(chalk.green(`  ✓ ${item}`));
    }
    console.log();
  }

  if (result.skipped.length > 0) {
    console.log(chalk.yellow.bold('Skipped:'));
    for (const item of result.skipped) {
      console.log(chalk.yellow(`  - ${item}`));
    }
    console.log();
  }

  if (result.errors.length > 0) {
    console.log(chalk.red.bold('Errors:'));
    for (const item of result.errors) {
      console.log(chalk.red(`  ✗ ${item}`));
    }
    console.log();
  }

  if (result.applied.length === 0 && result.skipped.length === 0) {
    console.log(chalk.gray('No fixable issues found.\n'));
  }
}
