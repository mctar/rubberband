import type { OpenClawConfig, ScanContext, ValidationIssue } from '../utils/types.js';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function findLineForKey(raw: string | undefined, key: string): number | undefined {
  if (!raw) return undefined;
  const escaped = escapeRegExp(key);
  const regex = new RegExp(`(^|[^\\w])${escaped}\\s*:`, 'm');
  const match = regex.exec(raw);
  if (!match || match.index === undefined) return undefined;
  const prefix = raw.slice(0, match.index);
  return prefix.split('\n').length;
}

function issue(
  level: ValidationIssue['level'],
  code: string,
  message: string,
  path?: string,
  recommendation?: string,
  raw?: string
): ValidationIssue {
  const key = path ? path.split('.').pop() : undefined;
  const line = key ? findLineForKey(raw, key) : undefined;
  return { level, code, message, path, recommendation, line };
}

export function validateConfig(
  config: OpenClawConfig,
  context: ScanContext,
  raw?: string
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const schema = context.openClaw.schema;
  const channels = Object.entries(config.channels ?? {});
  const hasLegacyDm = channels.some(([, channel]) => channel.dm?.policy !== undefined);
  const hasCurrentDm = channels.some(([, channel]) => channel.dmPolicy !== undefined);

  if (schema === 'current' && hasLegacyDm) {
    issues.push(
      issue(
        'warning',
        'CFG001',
        'Legacy dm.policy detected in current schema.',
        'channels.<channel>.dm.policy',
        'Use channels.<channel>.dmPolicy instead.',
        raw
      )
    );
  }

  if (schema === 'legacy' && hasCurrentDm) {
    issues.push(
      issue(
        'warning',
        'CFG002',
        'dmPolicy detected in legacy schema.',
        'channels.<channel>.dmPolicy',
        'Use channels.<channel>.dm.policy instead.',
        raw
      )
    );
  }

  if (hasLegacyDm && hasCurrentDm) {
    issues.push(
      issue(
        'warning',
        'CFG003',
        'Both dmPolicy and dm.policy are present. This can cause ambiguity.',
        'channels',
        'Use one DM policy format consistently.',
        raw
      )
    );
  }

  if (schema === 'current' && config.webhooks) {
    issues.push(
      issue(
        'warning',
        'CFG004',
        'Legacy webhooks config detected in current schema.',
        'webhooks',
        'Use hooks.* for incoming webhooks.',
        raw
      )
    );
  }

  if (schema === 'legacy' && config.hooks) {
    issues.push(
      issue(
        'warning',
        'CFG005',
        'hooks config detected in legacy schema.',
        'hooks',
        'Use webhooks.* for incoming webhooks.',
        raw
      )
    );
  }

  if (schema === 'current' && config.gateway?.authToken) {
    issues.push(
      issue(
        'warning',
        'CFG006',
        'Legacy gateway.authToken detected in current schema.',
        'gateway.authToken',
        'Use gateway.auth.token instead.',
        raw
      )
    );
  }

  if (schema === 'legacy' && config.gateway?.auth?.token) {
    issues.push(
      issue(
        'warning',
        'CFG007',
        'gateway.auth.token detected in legacy schema.',
        'gateway.auth.token',
        'Use gateway.authToken instead.',
        raw
      )
    );
  }

  if (config.hooks?.enabled && !config.hooks.token) {
    issues.push(
      issue(
        'error',
        'CFG008',
        'hooks.enabled is true but hooks.token is missing.',
        'hooks.token',
        'Set hooks.token or disable hooks.enabled.',
        raw
      )
    );
  }

  return issues;
}
