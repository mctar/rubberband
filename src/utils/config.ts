import { readFileSync, writeFileSync, statSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import JSON5 from 'json5';
import type { OpenClawConfig } from './types.js';

export class ConfigError extends Error {
  constructor(
    message: string,
    public code: 'NOT_FOUND' | 'PARSE_ERROR' | 'PERMISSION_DENIED'
  ) {
    super(message);
    this.name = 'ConfigError';
  }
}

export function getConfigPath(): string {
  if (process.env.OPENCLAW_CONFIG_PATH) {
    return process.env.OPENCLAW_CONFIG_PATH;
  }
  return join(getStateDirPath(), 'openclaw.json');
}

export function getStateDirPath(): string {
  if (process.env.OPENCLAW_STATE_DIR) {
    return process.env.OPENCLAW_STATE_DIR;
  }
  return join(homedir(), '.openclaw');
}

export interface LoadConfigResult {
  config: OpenClawConfig | null;
  error: ConfigError | null;
  raw?: string;
}

export function loadConfig(configPath?: string): LoadConfigResult {
  const path = configPath || getConfigPath();
  try {
    const content = readFileSync(path, 'utf-8');
    try {
      const config = JSON5.parse(content) as OpenClawConfig;
      if (typeof config !== 'object' || config === null) {
        return {
          config: null,
          error: new ConfigError(`Config file is not a valid JSON object: ${path}`, 'PARSE_ERROR'),
        };
      }
      return { config, error: null, raw: content };
    } catch (parseErr) {
      const message = parseErr instanceof SyntaxError ? parseErr.message : 'Invalid JSON';
      return {
        config: null,
        error: new ConfigError(`Failed to parse config file: ${message}`, 'PARSE_ERROR'),
      };
    }
  } catch (err) {
    if (err instanceof Error) {
      if ('code' in err && err.code === 'ENOENT') {
        return {
          config: null,
          error: new ConfigError(`Config file not found: ${path}`, 'NOT_FOUND'),
        };
      }
      if ('code' in err && err.code === 'EACCES') {
        return {
          config: null,
          error: new ConfigError(`Permission denied reading config: ${path}`, 'PERMISSION_DENIED'),
        };
      }
    }
    return {
      config: null,
      error: new ConfigError(`Failed to read config file: ${path}`, 'NOT_FOUND'),
    };
  }
}

export function saveConfig(config: OpenClawConfig, configPath?: string): void {
  const path = configPath || getConfigPath();
  writeFileSync(path, JSON.stringify(config, null, 2));
}

export function getFilePermissions(path: string): string | null {
  try {
    const stats = statSync(path);
    const mode = stats.mode & 0o777;
    return mode.toString(8).padStart(3, '0');
  } catch {
    return null;
  }
}

export function setFilePermissions(path: string, mode: number): void {
  chmodSync(path, mode);
}

export function fileExists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}
