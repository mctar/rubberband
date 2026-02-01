export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  code: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  fixable?: boolean;
}

export interface ScanResult {
  findings: Finding[];
  score: number;
}

export interface OpenClawConfig {
  gateway?: {
    host?: string;
    port?: number;
    authToken?: string;
  };
  controlUI?: {
    enabled?: boolean;
    dangerousDeviceAuthBypass?: boolean;
  };
  webhooks?: {
    enabled?: boolean;
    requireAuth?: boolean;
  };
  channels?: Record<string, ChannelConfig>;
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
  };
  updates?: {
    autoInstall?: boolean;
  };
  skills?: SkillConfig[];
}

export interface ChannelConfig {
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
