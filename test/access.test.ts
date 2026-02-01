import { describe, it, expect } from 'vitest';
import { scanAccess } from '../src/scanner/access.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanAccess', () => {
  it('returns empty array for secure config', () => {
    const config: OpenClawConfig = {
      channels: {
        whatsapp: {
          dm: { policy: 'pairing' },
          allowFrom: ['+1234567890'],
          groups: {
            family: { requireMention: true },
          },
        },
      },
    };
    const findings = scanAccess(config);
    expect(findings).toHaveLength(0);
  });

  it('detects open DM policy', () => {
    const config: OpenClawConfig = {
      channels: {
        whatsapp: {
          dm: { policy: 'open' },
        },
      },
    };
    const findings = scanAccess(config);
    const dmFinding = findings.find((f) => f.code === 'ACCESS001');
    expect(dmFinding).toBeDefined();
    expect(dmFinding?.severity).toBe('high');
  });

  it('detects missing allowFrom', () => {
    const config: OpenClawConfig = {
      channels: {
        telegram: {
          dm: { policy: 'pairing' },
        },
      },
    };
    const findings = scanAccess(config);
    const finding = findings.find((f) => f.code === 'ACCESS002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('detects group without mention requirement', () => {
    const config: OpenClawConfig = {
      channels: {
        discord: {
          dm: { policy: 'allowlist' },
          allowFrom: ['user123'],
          groups: {
            general: { requireMention: false },
          },
        },
      },
    };
    const findings = scanAccess(config);
    const finding = findings.find((f) => f.code === 'ACCESS003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('handles missing channels', () => {
    const config: OpenClawConfig = {};
    const findings = scanAccess(config);
    expect(findings).toHaveLength(0);
  });

  it('checks multiple channels', () => {
    const config: OpenClawConfig = {
      channels: {
        whatsapp: { dm: { policy: 'open' } },
        telegram: { dm: { policy: 'open' } },
      },
    };
    const findings = scanAccess(config);
    const openDmFindings = findings.filter((f) => f.code === 'ACCESS001');
    expect(openDmFindings).toHaveLength(2);
  });
});
