import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import JSON5 from 'json5';
import type {
  ChannelConfig,
  OpenClawConfig,
  OpenClawInfo,
  OpenClawVersionInfo,
  ScanContext,
  SchemaVersion,
  VersionSource,
} from './types.js';
import { fileExists, getConfigPath, getStateDirPath } from './config.js';

const VERSION_FIELD_CANDIDATES = ['openclawVersion', 'version', 'appVersion'];

const STATE_VERSION_FILES = [
  'version',
  'openclaw.version',
  'openclaw-version',
  'version.json',
  'about.json',
];

function getPackageVersionFiles(): string[] {
  return [
    join(process.cwd(), 'node_modules', 'openclaw', 'package.json'),
    join(getStateDirPath(), 'node_modules', 'openclaw', 'package.json'),
  ];
}

export interface BuildContextOptions {
  config: OpenClawConfig;
  configPath?: string;
  versionOverride?: string;
  disableVersionDetect?: boolean;
}

export function buildScanContext(options: BuildContextOptions): ScanContext {
  const { version, source } = detectOpenClawVersion(options);
  const schema = detectSchemaVersion(options.config, version);
  return {
    openClaw: { version, schema, source },
    paths: {
      configPath: options.configPath || getConfigPath(),
      stateDir: getStateDirPath(),
    },
  };
}

export function parseOpenClawVersion(raw: string): OpenClawVersionInfo | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const normalized = trimmed.replace(/^v/i, '').replace(/^openclaw@/i, '');
  const parts = normalized.split(/[.\-+]/).map((part) => part.trim());
  const numbers = parts
    .map((part) => {
      const match = part.match(/\d+/);
      return match ? Number(match[0]) : null;
    })
    .filter((value): value is number => value !== null);

  if (numbers.length === 0) return null;

  const [major, minor, patch] = [numbers[0] ?? null, numbers[1] ?? null, numbers[2] ?? null];
  let format: OpenClawVersionInfo['format'] = 'unknown';
  if (typeof major === 'number' && major >= 2000) {
    format = 'date';
  } else if (typeof major === 'number') {
    format = 'semver';
  }

  return {
    raw: trimmed,
    major,
    minor,
    patch,
    format,
  };
}

function detectOpenClawVersion(
  options: BuildContextOptions
): { version: OpenClawVersionInfo | null; source: VersionSource } {
  const override = options.versionOverride || process.env.OPENCLAW_VERSION;
  if (override) {
    const parsed = parseOpenClawVersion(override);
    if (parsed) {
      return { version: parsed, source: options.versionOverride ? 'cli' : 'env' };
    }
  }

  if (!options.disableVersionDetect) {
    const cliVersion = readVersionFromCli();
    if (cliVersion) {
      const parsed = parseOpenClawVersion(cliVersion);
      if (parsed) {
        return { version: parsed, source: 'cli' };
      }
    }
  }

  const configVersion = readVersionFromConfig(options.config);
  if (configVersion) {
    const parsed = parseOpenClawVersion(configVersion);
    if (parsed) {
      return { version: parsed, source: 'config' };
    }
  }

  if (options.disableVersionDetect) {
    return { version: null, source: 'unknown' };
  }

  const stateVersion = readVersionFromState();
  if (stateVersion) {
    const parsed = parseOpenClawVersion(stateVersion);
    if (parsed) {
      return { version: parsed, source: 'state' };
    }
  }

  const packageVersion = readVersionFromPackage();
  if (packageVersion) {
    const parsed = parseOpenClawVersion(packageVersion);
    if (parsed) {
      return { version: parsed, source: 'package' };
    }
  }

  return { version: null, source: 'unknown' };
}

function readVersionFromConfig(config: OpenClawConfig): string | null {
  for (const field of VERSION_FIELD_CANDIDATES) {
    const value = config[field as keyof OpenClawConfig];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value;
    }
  }
  return null;
}

function readVersionFromState(): string | null {
  const stateDir = getStateDirPath();
  for (const file of STATE_VERSION_FILES) {
    const path = join(stateDir, file);
    if (!fileExists(path)) continue;
    try {
      const content = readFileSync(path, 'utf-8').trim();
      if (!content) continue;
      if (file.endsWith('.json')) {
        const parsed = JSON5.parse(content) as Record<string, unknown>;
        for (const field of VERSION_FIELD_CANDIDATES) {
          const value = parsed[field];
          if (typeof value === 'string' && value.trim().length > 0) {
            return value;
          }
        }
        if (typeof parsed.version === 'string') {
          return parsed.version;
        }
      } else {
        return content.split(/\s+/)[0];
      }
    } catch {
      continue;
    }
  }
  return null;
}

function readVersionFromCli(): string | null {
  const candidates: Array<{ cmd: string; args: string[] }> = [
    { cmd: 'openclaw', args: ['--version'] },
    { cmd: 'openclaw', args: ['version'] },
  ];

  for (const candidate of candidates) {
    try {
      const result = spawnSync(candidate.cmd, candidate.args, {
        encoding: 'utf-8',
        stdio: 'pipe',
        timeout: 1500,
        maxBuffer: 1024 * 1024,
      });
      if (result.error || result.status !== 0) continue;
      const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim();
      if (!output) continue;
      const match = output.match(/v?\d{4}\.\d+\.\d+|v?\d+\.\d+\.\d+/);
      if (match) {
        return match[0];
      }
      const tokens = output.split(/\s+/).filter(Boolean);
      if (tokens.length > 0) {
        return tokens[0];
      }
    } catch {
      continue;
    }
  }
  return null;
}

function readVersionFromPackage(): string | null {
  for (const path of getPackageVersionFiles()) {
    if (!fileExists(path)) continue;
    try {
      const content = readFileSync(path, 'utf-8');
      const parsed = JSON5.parse(content) as { version?: string };
      if (typeof parsed.version === 'string' && parsed.version.trim().length > 0) {
        return parsed.version;
      }
    } catch {
      continue;
    }
  }
  return null;
}

export function detectSchemaVersion(
  config: OpenClawConfig,
  version: OpenClawVersionInfo | null
): SchemaVersion {
  const channelConfigs = Object.values(config.channels ?? {});
  const hasNewDmPolicy = channelConfigs.some((channel) => typeof channel.dmPolicy === 'string');
  const hasLegacyDmPolicy = channelConfigs.some(
    (channel) => typeof channel.dm?.policy === 'string'
  );
  const hasNewGatewayAuth =
    typeof config.gateway?.auth?.token === 'string' || typeof config.gateway?.auth?.mode === 'string';
  const hasLegacyGatewayAuth = typeof config.gateway?.authToken === 'string';
  const hasHooks = typeof config.hooks === 'object' && config.hooks !== null;
  const hasWebhooks = typeof config.webhooks === 'object' && config.webhooks !== null;
  const hasGatewayBind = typeof config.gateway?.bind === 'string';

  if (hasNewDmPolicy || hasNewGatewayAuth || hasHooks || hasGatewayBind) return 'current';
  if (hasLegacyDmPolicy || hasLegacyGatewayAuth || hasWebhooks) return 'legacy';

  if (version?.format === 'date' && typeof version.major === 'number') {
    return version.major >= 2026 ? 'current' : 'legacy';
  }
  if (version?.format === 'semver' && typeof version.major === 'number') {
    return version.major >= 2 ? 'current' : 'legacy';
  }

  return 'unknown';
}

export function resolveGatewayAuthToken(
  config: OpenClawConfig,
  schema: SchemaVersion
): string | undefined {
  if (schema === 'current') {
    return config.gateway?.auth?.token ?? config.gateway?.authToken;
  }
  if (schema === 'legacy') {
    return config.gateway?.authToken ?? config.gateway?.auth?.token;
  }
  return config.gateway?.auth?.token ?? config.gateway?.authToken;
}

export function resolveWebhookConfig(
  config: OpenClawConfig,
  schema: SchemaVersion
): { enabled: boolean; hasAuth: boolean; path: string } | null {
  if (schema === 'legacy') {
    if (!config.webhooks) return null;
    return {
      enabled: config.webhooks.enabled === true,
      hasAuth: config.webhooks.requireAuth === true,
      path: 'webhooks.requireAuth',
    };
  }

  if (schema === 'current') {
    if (!config.hooks) return null;
    return {
      enabled: config.hooks.enabled === true,
      hasAuth: typeof config.hooks.token === 'string' && config.hooks.token.length > 0,
      path: 'hooks.token',
    };
  }

  if (config.hooks) {
    return {
      enabled: config.hooks.enabled === true,
      hasAuth: typeof config.hooks.token === 'string' && config.hooks.token.length > 0,
      path: 'hooks.token',
    };
  }
  if (config.webhooks) {
    return {
      enabled: config.webhooks.enabled === true,
      hasAuth: config.webhooks.requireAuth === true,
      path: 'webhooks.requireAuth',
    };
  }

  return null;
}

export function resolveDmPolicy(
  channel: ChannelConfig,
  schema: SchemaVersion
): ChannelConfig['dmPolicy'] {
  if (schema === 'current') {
    return channel.dmPolicy ?? channel.dm?.policy;
  }
  if (schema === 'legacy') {
    return channel.dm?.policy ?? channel.dmPolicy;
  }
  return channel.dmPolicy ?? channel.dm?.policy;
}

export function formatOpenClawInfo(info: OpenClawInfo): string {
  const version = info.version?.raw ?? 'unknown';
  const source = info.source !== 'unknown' ? `, source: ${info.source}` : '';
  return `OpenClaw: ${version} (schema: ${info.schema}${source})`;
}
