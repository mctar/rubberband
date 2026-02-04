import { describe, it, expect } from 'vitest';
import { scanWebTools } from '../src/scanner/web.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanWebTools', () => {
  const context = {
    openClaw: { version: null, schema: 'current', source: 'unknown' },
    paths: { configPath: '/tmp/rubberband-test-openclaw.json', stateDir: '/tmp' },
  } as const;

  it('flags high maxRedirects', () => {
    const config: OpenClawConfig = {
      tools: { web: { fetch: { enabled: true, maxRedirects: 5 } } },
    };
    const findings = scanWebTools(config, context);
    expect(findings.some((f) => f.code === 'WEB001')).toBe(true);
  });

  it('ignores default settings', () => {
    const config: OpenClawConfig = {
      tools: { web: { fetch: { enabled: true, maxRedirects: 3 } } },
    };
    const findings = scanWebTools(config, context);
    expect(findings).toHaveLength(0);
  });
});
