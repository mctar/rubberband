import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanApprovals } from '../src/scanner/approvals.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanApprovals', () => {
  let stateDir = '';
  const context = () => ({
    openClaw: { version: null, schema: 'current', source: 'unknown' },
    paths: { configPath: '/tmp/rubberband-test-openclaw.json', stateDir },
  });

  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), 'rubberband-approvals-'));
  });

  afterEach(() => {
    rmSync(stateDir, { recursive: true, force: true });
  });

  it('flags missing approvals file when exec allowed', () => {
    const config: OpenClawConfig = { tools: { exec: { security: 'full' } } };
    const findings = scanApprovals(config, context());
    expect(findings.some((f) => f.code === 'APPROVALS001')).toBe(true);
  });

  it('flags unrestricted defaults in approvals file', () => {
    const approvalsPath = join(stateDir, 'exec-approvals.json');
    writeFileSync(
      approvalsPath,
      JSON.stringify({ defaults: { security: 'full' } }, null, 2)
    );
    const config: OpenClawConfig = { tools: { exec: { security: 'allowlist' } } };
    const findings = scanApprovals(config, context());
    expect(findings.some((f) => f.code === 'APPROVALS002')).toBe(true);
  });
});
