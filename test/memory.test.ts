import { describe, it, expect } from 'vitest';
import { scanMemoryBackend } from '../src/scanner/memory.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanMemoryBackend', () => {
  const context = {
    openClaw: { version: null, schema: 'current', source: 'unknown' },
    paths: { configPath: '/tmp/rubberband-test-openclaw.json', stateDir: '/tmp' },
  } as const;

  it('flags missing qmd binary', () => {
    const config: OpenClawConfig = {
      memory: { backend: 'qmd', qmd: { command: '/tmp/does-not-exist-qmd' } },
    };
    const findings = scanMemoryBackend(config, context);
    expect(findings.some((f) => f.code === 'MEM001')).toBe(true);
  });

  it('ignores non-qmd backend', () => {
    const config: OpenClawConfig = {
      memory: { backend: 'default' },
    };
    const findings = scanMemoryBackend(config, context);
    expect(findings).toHaveLength(0);
  });
});
