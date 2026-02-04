import type { Finding, OpenClawConfig } from '../utils/types.js';

const DANGEROUS_PERMISSIONS = [
  'filesystem:write',
  'filesystem:delete',
  'shell:execute',
  'network:unrestricted',
  'credentials:read',
];

const KNOWN_MALICIOUS_SKILLS = ['crypto-miner-helper', 'free-tokens-generator'];

const RISKY_SKILLS = [
  'moltbook-skill', // Fetches instructions periodically
];

export function scanSkills(config: OpenClawConfig): Finding[] {
  const findings: Finding[] = [];

  if (!config.skills || config.skills.length === 0) {
    return findings;
  }

  const unverifiedSkills: string[] = [];
  const dangerousSkills: Map<string, string[]> = new Map();
  const externalFetchSkills: string[] = [];

  for (const skill of config.skills) {
    // Check for known malicious skills
    if (KNOWN_MALICIOUS_SKILLS.includes(skill.name)) {
      findings.push({
        code: 'SKILL001',
        severity: 'critical',
        title: `Malicious skill detected: ${skill.name}`,
        detail: `The skill "${skill.name}" is on the known malicious skills list.`,
        recommendation: 'Remove this skill immediately',
        fixable: false,
        path: 'skills',
      });
      continue;
    }

    // Check for risky skills
    if (RISKY_SKILLS.includes(skill.name)) {
      findings.push({
        code: 'SKILL002',
        severity: 'high',
        title: `Risky skill installed: ${skill.name}`,
        detail: `The skill "${skill.name}" fetches external instructions periodically, which could be used for injection.`,
        recommendation: 'Review this skill carefully or remove it',
        fixable: false,
        path: 'skills',
      });
    }

    // Check verification status
    if (!skill.verified && skill.source && !skill.source.startsWith('official:')) {
      unverifiedSkills.push(skill.name);
    }

    // Check for dangerous permissions
    if (skill.permissions) {
      const dangerous = skill.permissions.filter((p) => DANGEROUS_PERMISSIONS.includes(p));
      if (dangerous.length > 0) {
        dangerousSkills.set(skill.name, dangerous);
      }
    }

    // Check for external URL fetching in heartbeat
    if (skill.heartbeat?.url) {
      externalFetchSkills.push(skill.name);
    }

    // Check checksum integrity
    if (!skill.checksum && skill.source && !skill.source.startsWith('official:')) {
      findings.push({
        code: 'SKILL005',
        severity: 'low',
        title: `Skill "${skill.name}" has no checksum`,
        detail: 'Cannot verify skill integrity without checksum.',
        recommendation: 'Add checksum verification for this skill',
        fixable: false,
        path: 'skills',
      });
    }
  }

  // Report unverified skills
  if (unverifiedSkills.length > 0) {
    findings.push({
      code: 'SKILL003',
      severity: 'medium',
      title: `${unverifiedSkills.length} skills installed from community sources`,
      detail: `Unverified skills: ${unverifiedSkills.join(', ')}`,
      recommendation: 'Review: ' + unverifiedSkills.join(', '),
      fixable: false,
      path: 'skills',
    });
  }

  // Report dangerous permissions
  for (const [skillName, permissions] of dangerousSkills) {
    findings.push({
      code: 'SKILL004',
      severity: 'high',
      title: `Skill "${skillName}" has dangerous permissions`,
      detail: `Permissions: ${permissions.join(', ')}`,
      recommendation: 'Review if these permissions are necessary',
      fixable: false,
      path: 'skills',
    });
  }

  // Report external fetch
  if (externalFetchSkills.length > 0) {
    findings.push({
      code: 'SKILL006',
      severity: 'medium',
      title: 'Skills fetch external URLs via heartbeat',
      detail: `Skills with external heartbeat: ${externalFetchSkills.join(', ')}`,
      recommendation: 'Review heartbeat URLs for safety',
      fixable: false,
      path: 'skills',
    });
  }

  return findings;
}
