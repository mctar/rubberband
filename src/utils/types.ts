export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type SchemaVersion = 'legacy' | 'current' | 'unknown';
export type VersionSource = 'cli' | 'env' | 'config' | 'state' | 'package' | 'unknown';

export interface OpenClawVersionInfo {
  raw: string;
  major: number | null;
  minor: number | null;
  patch: number | null;
  format: 'date' | 'semver' | 'unknown';
}

export interface OpenClawInfo {
  version: OpenClawVersionInfo | null;
  schema: SchemaVersion;
  source: VersionSource;
}

export interface ScanContext {
  openClaw: OpenClawInfo;
  paths: {
    configPath: string;
    stateDir: string;
  };
  waivers?: Waiver[];
}

export interface Finding {
  code: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  fixable?: boolean;
  path?: string;
}

export interface ScanResult {
  findings: Finding[];
  score: number;
  openClaw: OpenClawInfo;
  waivedCount?: number;
  validation?: ValidationIssue[];
}

export interface OpenClawConfig {
  version?: string;
  openclawVersion?: string;
  appVersion?: string;
  gateway?: {
    host?: string;
    port?: number;
    bind?: string;
    authToken?: string;
    auth?: {
      mode?: string;
      token?: string;
    };
  };
  controlUI?: {
    enabled?: boolean;
    dangerousDeviceAuthBypass?: boolean;
  };
  webhooks?: WebhookConfig;
  hooks?: HooksConfig;
  channels?: Record<string, ChannelConfig>;
  approvals?: {
    exec?: {
      enabled?: boolean;
      mode?: 'session' | 'targets' | 'both';
      targets?: string[];
      timeoutSec?: number;
    };
  };
  tools?: {
    profile?: string;
    allow?: string[];
    deny?: string[];
    exec?: ExecToolConfig;
    web?: {
      fetch?: WebFetchConfig;
      search?: WebSearchConfig;
    };
  };
  shell?: {
    enabled?: boolean;
    allowedCommands?: string[];
  };
  browser?: {
    enabled?: boolean;
    sandbox?: boolean;
    headless?: boolean;
  };
  logging?: {
    level?: string;
    file?: string;
  };
  rateLimit?: {
    enabled?: boolean;
  };
  memory?: {
    persistent?: boolean;
    encrypted?: boolean;
    backend?: string;
    qmd?: {
      command?: string;
      includeDefaultMemory?: boolean;
      update?: {
        interval?: string;
      };
    };
  };
  updates?: {
    autoInstall?: boolean;
  };
  skills?: SkillConfig[];
}

export interface WebhookConfig {
  enabled?: boolean;
  requireAuth?: boolean;
}

export interface HooksConfig {
  enabled?: boolean;
  token?: string;
  path?: string;
  maxBodyBytes?: number;
  allowedOrigins?: string[];
  presets?: {
    list?: string[];
    systemPrompt?: string;
    jsonResponse?: boolean;
  };
}

export interface ExecToolConfig {
  security?: 'deny' | 'allowlist' | 'full';
  ask?: 'off' | 'on-miss' | 'always';
  askFallback?: 'deny' | 'allowlist' | 'full';
  safeBins?: string[];
}

export interface WebFetchConfig {
  enabled?: boolean;
  maxRedirects?: number;
  maxChars?: number;
  maxCharsCap?: number;
}

export interface WebSearchConfig {
  enabled?: boolean;
}

export interface ChannelConfig {
  dmPolicy?: 'open' | 'pairing' | 'allowlist';
  dm?: {
    policy?: 'open' | 'pairing' | 'allowlist';
  };
  allowFrom?: string[];
  groups?: Record<string, GroupConfig>;
}

export interface GroupConfig {
  requireMention?: boolean;
}

export interface SkillConfig {
  name: string;
  source?: string;
  verified?: boolean;
  permissions?: string[];
  checksum?: string;
  heartbeat?: {
    url?: string;
  };
}

export interface HardenOptions {
  dryRun: boolean;
  strict: boolean;
}

export interface HardenResult {
  applied: string[];
  skipped: string[];
  errors: string[];
}

export interface ValidationIssue {
  level: 'error' | 'warning';
  code: string;
  message: string;
  path?: string;
  line?: number;
  recommendation?: string;
}

export interface Waiver {
  code: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
  path?: string;
}
