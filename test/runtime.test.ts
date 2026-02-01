import { describe, it, expect } from 'vitest';
import { scanRuntime } from '../src/scanner/runtime.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanRuntime', () => {
  it('returns empty array for secure config', () => {
    const config: OpenClawConfig = {
      logging: { level: 'info' },
      rateLimit: { enabled: true },
      browser: { enabled: true, sandbox: true, headless: true },
      shell: { enabled: false },
      memory: { persistent: true, encrypted: true },
    };
    const findings = scanRuntime(config);
    expect(findings).toHaveLength(0);
  });

  it('detects verbose logging', () => {
    const config: OpenClawConfig = {
      logging: { level: 'debug' },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
  });

  it('detects trace logging', () => {
    const config: OpenClawConfig = {
      logging: { level: 'trace' },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN001');
    expect(finding).toBeDefined();
  });

  it('detects disabled rate limiting', () => {
    const config: OpenClawConfig = {
      rateLimit: { enabled: false },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('detects disabled browser sandbox', () => {
    const config: OpenClawConfig = {
      browser: { enabled: true, sandbox: false },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN004');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('detects headed browser mode', () => {
    const config: OpenClawConfig = {
      browser: { enabled: true, sandbox: true, headless: false },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN005');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
  });

  it('detects unrestricted shell execution', () => {
    const config: OpenClawConfig = {
      shell: { enabled: true },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN006');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('detects shell with allowlist (medium)', () => {
    const config: OpenClawConfig = {
      shell: { enabled: true, allowedCommands: ['ls', 'cat'] },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN007');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('detects unencrypted persistent memory', () => {
    const config: OpenClawConfig = {
      memory: { persistent: true, encrypted: false },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN008');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('detects auto-update enabled', () => {
    const config: OpenClawConfig = {
      updates: { autoInstall: true },
    };
    const findings = scanRuntime(config);
    const finding = findings.find((f) => f.code === 'RUN009');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
  });

  it('handles empty config', () => {
    const config: OpenClawConfig = {};
    const findings = scanRuntime(config);
    expect(findings).toHaveLength(0);
  });
});
