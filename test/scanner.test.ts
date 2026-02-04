import { describe, it, expect } from 'vitest';
import { runScan, countBySeverity } from '../src/scanner/index.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('runScan', () => {
  const currentContext = {
    openClaw: { version: null, schema: 'current', source: 'unknown' },
    paths: {
      configPath: '/tmp/rubberband-test-openclaw.json',
      stateDir: '/tmp/rubberband-test-openclaw',
    },
  } as const;

  it('returns score of 100 for secure config', () => {
    const config: OpenClawConfig = {
      gateway: { host: '127.0.0.1', auth: { token: 'secret' } },
      rateLimit: { enabled: true },
    };
    const result = runScan(config, currentContext);
    expect(result.score).toBe(100);
    expect(result.findings).toHaveLength(0);
  });

  it('deducts points based on severity', () => {
    const config: OpenClawConfig = {
      gateway: { host: '0.0.0.0' }, // critical: -25
      logging: { level: 'debug' }, // low: -3
    };
    const result = runScan(config, currentContext);
    expect(result.score).toBe(72); // 100 - 25 - 3
  });

  it('score cannot go below 0', () => {
    const config: OpenClawConfig = {
      gateway: { host: '0.0.0.0' },
      controlUI: { enabled: true, dangerousDeviceAuthBypass: true },
      hooks: { enabled: true },
      shell: { enabled: true },
      channels: {
        ch1: { dmPolicy: 'open' },
        ch2: { dmPolicy: 'open' },
      },
    };
    const result = runScan(config, currentContext);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  it('aggregates findings from all scanners', () => {
    const config: OpenClawConfig = {
      gateway: { host: '0.0.0.0' },
      channels: { test: { dmPolicy: 'open' } },
      logging: { level: 'trace' },
    };
    const result = runScan(config, currentContext);
    expect(result.findings.length).toBeGreaterThan(1);

    const codes = result.findings.map((f) => f.code);
    expect(codes).toContain('NET001');
    expect(codes).toContain('ACCESS001');
    expect(codes).toContain('RUN001');
  });
});

describe('countBySeverity', () => {
  it('counts findings by severity', () => {
    const findings = [
      { code: 'A', severity: 'critical' as const, title: '', detail: '', recommendation: '' },
      { code: 'B', severity: 'high' as const, title: '', detail: '', recommendation: '' },
      { code: 'C', severity: 'high' as const, title: '', detail: '', recommendation: '' },
      { code: 'D', severity: 'medium' as const, title: '', detail: '', recommendation: '' },
      { code: 'E', severity: 'low' as const, title: '', detail: '', recommendation: '' },
      { code: 'F', severity: 'low' as const, title: '', detail: '', recommendation: '' },
      { code: 'G', severity: 'low' as const, title: '', detail: '', recommendation: '' },
    ];
    const counts = countBySeverity(findings);
    expect(counts).toEqual({
      critical: 1,
      high: 2,
      medium: 1,
      low: 3,
    });
  });

  it('returns zeros for empty array', () => {
    const counts = countBySeverity([]);
    expect(counts).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  });
});
