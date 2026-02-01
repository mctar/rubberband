import { describe, it, expect } from 'vitest';
import { scanSkills } from '../src/scanner/skills.js';
import type { OpenClawConfig } from '../src/utils/types.js';

describe('scanSkills', () => {
  it('returns empty array for no skills', () => {
    const config: OpenClawConfig = {};
    const findings = scanSkills(config);
    expect(findings).toHaveLength(0);
  });

  it('returns empty array for verified official skills', () => {
    const config: OpenClawConfig = {
      skills: [
        {
          name: 'calendar',
          source: 'official:calendar',
          verified: true,
        },
      ],
    };
    const findings = scanSkills(config);
    expect(findings).toHaveLength(0);
  });

  it('detects known malicious skills', () => {
    const config: OpenClawConfig = {
      skills: [{ name: 'crypto-miner-helper', source: 'community' }],
    };
    const findings = scanSkills(config);
    expect(findings).toHaveLength(1);
    expect(findings[0].code).toBe('SKILL001');
    expect(findings[0].severity).toBe('critical');
  });

  it('detects risky skills like moltbook', () => {
    const config: OpenClawConfig = {
      skills: [
        {
          name: 'moltbook-skill',
          source: 'community',
          verified: true,
          checksum: 'abc123',
        },
      ],
    };
    const findings = scanSkills(config);
    const finding = findings.find((f) => f.code === 'SKILL002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('detects unverified community skills', () => {
    const config: OpenClawConfig = {
      skills: [
        { name: 'weather', source: 'community:weather', verified: false, checksum: 'xyz' },
        { name: 'news', source: 'community:news', verified: false, checksum: 'abc' },
      ],
    };
    const findings = scanSkills(config);
    const finding = findings.find((f) => f.code === 'SKILL003');
    expect(finding).toBeDefined();
    expect(finding?.detail).toContain('weather');
    expect(finding?.detail).toContain('news');
  });

  it('detects dangerous permissions', () => {
    const config: OpenClawConfig = {
      skills: [
        {
          name: 'file-manager',
          source: 'official:files',
          verified: true,
          permissions: ['filesystem:write', 'shell:execute'],
        },
      ],
    };
    const findings = scanSkills(config);
    const finding = findings.find((f) => f.code === 'SKILL004');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('detects missing checksum for community skills', () => {
    const config: OpenClawConfig = {
      skills: [{ name: 'todo', source: 'community:todo', verified: true }],
    };
    const findings = scanSkills(config);
    const finding = findings.find((f) => f.code === 'SKILL005');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
  });

  it('detects external heartbeat URLs', () => {
    const config: OpenClawConfig = {
      skills: [
        {
          name: 'tracker',
          source: 'official:tracker',
          verified: true,
          heartbeat: { url: 'https://example.com/ping' },
        },
      ],
    };
    const findings = scanSkills(config);
    const finding = findings.find((f) => f.code === 'SKILL006');
    expect(finding).toBeDefined();
  });
});
