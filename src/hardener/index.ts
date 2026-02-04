import chalk from 'chalk';
import type {
  Finding,
  OpenClawConfig,
  HardenOptions,
  HardenResult,
  ScanContext,
} from '../utils/types.js';
import { saveConfig, setFilePermissions, fileExists } from '../utils/config.js';
import { join } from 'node:path';

type HardenFn = (config: OpenClawConfig, options: HardenOptions, context: ScanContext) => boolean;
type HardenerType = 'config' | 'filesystem';

function setDmPolicy(
  channel: NonNullable<OpenClawConfig['channels']>[string],
  context: ScanContext,
  value: 'open' | 'pairing' | 'allowlist'
): void {
  if (context.openClaw.schema === 'legacy') {
    if (!channel.dm) channel.dm = {};
    channel.dm.policy = value;
    return;
  }
  if (context.openClaw.schema === 'current') {
    channel.dmPolicy = value;
    return;
  }
  if (channel.dm?.policy !== undefined) {
    channel.dm.policy = value;
  } else {
    channel.dmPolicy = value;
  }
}

const HARDENERS: Record<
  string,
  { fn: HardenFn; strictOnly?: boolean; description: string; type: HardenerType }
> = {
  NET001: {
    fn: (config, _options, context) => {
      if (!config.gateway) config.gateway = {};
      config.gateway.host = '127.0.0.1';
      if (context.openClaw.schema === 'current' || config.gateway.bind) {
        config.gateway.bind = 'loopback';
      }
      return true;
    },
    description: 'Bind gateway to localhost',
    type: 'config',
  },
  NET003: {
    fn: (config) => {
      if (!config.controlUI) config.controlUI = {};
      config.controlUI.dangerousDeviceAuthBypass = false;
      return true;
    },
    description: 'Disable control UI auth bypass',
    type: 'config',
  },
  NET004: {
    fn: (config, _options, context) => {
      if (context.openClaw.schema === 'current') {
        return false;
      }
      if (!config.webhooks) config.webhooks = {};
      config.webhooks.requireAuth = true;
      return true;
    },
    description: 'Enable webhook authentication (legacy)',
    type: 'config',
  },
  CRED001: {
    fn: (_config, _options, context) => {
      setFilePermissions(context.paths.configPath, 0o600);
      return true;
    },
    description: 'Fix config file permissions (chmod 600)',
    type: 'filesystem',
  },
  CRED003: {
    fn: (_config, _options, context) => {
      const envPath = join(context.paths.stateDir, '.env');
      if (fileExists(envPath)) {
        setFilePermissions(envPath, 0o600);
        return true;
      }
      return false;
    },
    description: 'Fix .env file permissions (chmod 600)',
    type: 'filesystem',
  },
  CRED004: {
    fn: (_config, _options, context) => {
      setFilePermissions(context.paths.stateDir, 0o700);
      return true;
    },
    description: 'Fix state directory permissions (chmod 700)',
    type: 'filesystem',
  },
  ACCESS001: {
    fn: (config, _options, context) => {
      if (!config.channels) return false;
      for (const channel of Object.values(config.channels)) {
        const dmPolicy = channel.dmPolicy ?? channel.dm?.policy;
        if (dmPolicy === 'open') {
          setDmPolicy(channel, context, 'pairing');
        }
      }
      return true;
    },
    description: 'Set DM policy to pairing',
    type: 'config',
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
    type: 'config',
  },
  RUN001: {
    fn: (config) => {
      if (!config.logging) config.logging = {};
      config.logging.level = 'info';
      return true;
    },
    description: 'Set logging level to info',
    type: 'config',
  },
  RUN003: {
    fn: (config) => {
      if (!config.rateLimit) config.rateLimit = {};
      config.rateLimit.enabled = true;
      return true;
    },
    description: 'Enable rate limiting',
    type: 'config',
  },
  RUN004: {
    fn: (config) => {
      if (!config.browser) config.browser = {};
      config.browser.sandbox = true;
      return true;
    },
    strictOnly: true,
    description: 'Enable browser sandbox',
    type: 'config',
  },
  RUN005: {
    fn: (config) => {
      if (!config.browser) config.browser = {};
      config.browser.headless = true;
      return true;
    },
    description: 'Enable headless browser mode',
    type: 'config',
  },
  RUN006: {
    fn: (config) => {
      if (!config.shell) config.shell = {};
      config.shell.enabled = false;
      return true;
    },
    strictOnly: true,
    description: 'Disable shell execution',
    type: 'config',
  },
  RUN008: {
    fn: (config) => {
      if (!config.memory) config.memory = {};
      config.memory.encrypted = true;
      return true;
    },
    description: 'Enable memory encryption',
    type: 'config',
  },
};

function cloneConfig(config: OpenClawConfig): OpenClawConfig {
  if (typeof structuredClone === 'function') {
    return structuredClone(config);
  }
  return JSON.parse(JSON.stringify(config)) as OpenClawConfig;
}

export function previewConfigChanges(
  config: OpenClawConfig,
  findings: Finding[],
  options: HardenOptions,
  context: ScanContext
): { updated: OpenClawConfig; applied: string[]; skipped: string[]; nonConfig: string[] } {
  const preview = cloneConfig(config);
  const applied: string[] = [];
  const skipped: string[] = [];
  const nonConfig: string[] = [];

  const fixableFindings = findings.filter((f) => f.fixable);
  for (const finding of fixableFindings) {
    const hardener = HARDENERS[finding.code];
    if (!hardener) {
      skipped.push(`${finding.code}: No automatic fix available`);
      continue;
    }
    if (hardener.strictOnly && !options.strict) {
      skipped.push(`${finding.code}: Requires --strict mode`);
      continue;
    }
    if (hardener.type !== 'config') {
      nonConfig.push(`${finding.code}: ${hardener.description}`);
      continue;
    }
    try {
      const success = hardener.fn(preview, options, context);
      if (success) {
        applied.push(`${finding.code}: ${hardener.description}`);
      } else {
        skipped.push(`${finding.code}: Condition not met`);
      }
    } catch (err) {
      skipped.push(
        `${finding.code}: ${err instanceof Error ? err.message : 'Unknown error'}`
      );
    }
  }

  return { updated: preview, applied, skipped, nonConfig };
}

export function harden(
  config: OpenClawConfig,
  findings: Finding[],
  options: HardenOptions,
  context: ScanContext
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
      const success = hardener.fn(config, options, context);
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
      saveConfig(config, context.paths.configPath);
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
