import type { Finding, OpenClawConfig, ScanResult, Severity } from '../utils/types.js';
import { scanNetwork } from './network.js';
import { scanCredentials } from './credentials.js';
import { scanAccess } from './access.js';
import { scanSkills } from './skills.js';
import { scanRuntime } from './runtime.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

export function runScan(config: OpenClawConfig): ScanResult {
  const findings: Finding[] = [];

  // Run all scanners
  findings.push(...scanNetwork(config));
  findings.push(...scanCredentials());
  findings.push(...scanAccess(config));
  findings.push(...scanSkills(config));
  findings.push(...scanRuntime(config));

  // Calculate score (start at 100, deduct for findings)
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY_WEIGHTS[finding.severity];
  }
  score = Math.max(0, score);

  return { findings, score };
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  return counts;
}
