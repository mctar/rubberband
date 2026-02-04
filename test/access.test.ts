import { describe, it, expect } from 'vitest';
import { scanAccess } from '../src/scanner/access.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanAccess', () => {
  const legacyContext = {
    openClaw: { version: null, schema: 'legacy', source: 'unknown' },
    paths: {
      configPath: '/tmp/rubberband-test-openclaw.json',
      stateDir: '/tmp/rubberband-test-openclaw',
    },
  } as const;
  const currentContext = {
    openClaw: { version: null, schema: 'current', source: 'unknown' },
    paths: {
      configPath: '/tmp/rubberband-test-openclaw.json',
      stateDir: '/tmp/rubberband-test-openclaw',
    },
  } as const;

  it('returns empty array for secure config', () => {
    const config: OpenClawConfig = {
      channels: {
        whatsapp: {
          dmPolicy: 'pairing',
          allowFrom: ['+1234567890'],
          groups: {
            family: { requireMention: true },
          },
        },
      },
    };
    const findings = scanAccess(config, currentContext);
    expect(findings).toHaveLength(0);
  });

  it('detects open DM policy', () => {
    const config: OpenClawConfig = {
      channels: {
        whatsapp: {
          dmPolicy: 'open',
        },
      },
    };
    const findings = scanAccess(config, currentContext);
    const dmFinding = findings.find((f) => f.code === 'ACCESS001');
    expect(dmFinding).toBeDefined();
    expect(dmFinding?.severity).toBe('high');
  });

  it('detects missing allowFrom', () => {
    const config: OpenClawConfig = {
      channels: {
        telegram: {
          dmPolicy: 'pairing',
        },
      },
    };
    const findings = scanAccess(config, currentContext);
    const finding = findings.find((f) => f.code === 'ACCESS002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('detects group without mention requirement', () => {
    const config: OpenClawConfig = {
      channels: {
        discord: {
          dmPolicy: 'allowlist',
          allowFrom: ['user123'],
          groups: {
            general: { requireMention: false },
          },
        },
      },
    };
    const findings = scanAccess(config, currentContext);
    const finding = findings.find((f) => f.code === 'ACCESS003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('handles missing channels', () => {
    const config: OpenClawConfig = {};
    const findings = scanAccess(config, currentContext);
    expect(findings).toHaveLength(0);
  });

  it('checks multiple channels', () => {
    const config: OpenClawConfig = {
      channels: {
        whatsapp: { dmPolicy: 'open' },
        telegram: { dmPolicy: 'open' },
      },
    };
    const findings = scanAccess(config, currentContext);
    const openDmFindings = findings.filter((f) => f.code === 'ACCESS001');
    expect(openDmFindings).toHaveLength(2);
  });

  it('supports legacy dm.policy field', () => {
    const config: OpenClawConfig = {
      channels: {
        sms: { dm: { policy: 'open' } },
      },
    };
    const findings = scanAccess(config, legacyContext);
    const dmFinding = findings.find((f) => f.code === 'ACCESS001');
    expect(dmFinding).toBeDefined();
  });
});
