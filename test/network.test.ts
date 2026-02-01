import { describe, it, expect } from 'vitest';
import { scanNetwork } from '../src/scanner/network.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanNetwork', () => {
  it('returns empty array for secure config', () => {
    const config: OpenClawConfig = {
      gateway: {
        host: '127.0.0.1',
        port: 18789,
        authToken: 'secret',
      },
    };
    const findings = scanNetwork(config);
    expect(findings).toHaveLength(0);
  });

  it('detects exposed gateway without auth', () => {
    const config: OpenClawConfig = {
      gateway: {
        host: '0.0.0.0',
        port: 18789,
      },
    };
    const findings = scanNetwork(config);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe('NET001');
    expect(findings[0].severity).toBe('critical');
  });

  it('detects exposed gateway with auth (medium severity)', () => {
    const config: OpenClawConfig = {
      gateway: {
        host: '0.0.0.0',
        authToken: 'secret',
      },
    };
    const findings = scanNetwork(config);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe('NET002');
    expect(findings[0].severity).toBe('medium');
  });

  it('detects control UI auth bypass', () => {
    const config: OpenClawConfig = {
      controlUI: {
        enabled: true,
        dangerousDeviceAuthBypass: true,
      },
    };
    const findings = scanNetwork(config);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe('NET003');
    expect(findings[0].severity).toBe('high');
  });

  it('detects webhooks without auth', () => {
    const config: OpenClawConfig = {
      webhooks: {
        enabled: true,
        requireAuth: false,
      },
    };
    const findings = scanNetwork(config);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe('NET004');
    expect(findings[0].severity).toBe('high');
  });

  it('handles empty config', () => {
    const config: OpenClawConfig = {};
    const findings = scanNetwork(config);
    expect(findings).toHaveLength(0);
  });
});
