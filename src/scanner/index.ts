import type { Finding, OpenClawConfig, ScanContext, ScanResult, Severity } from '../utils/types.js';
import { scanNetwork } from './network.js';
import { scanCredentials } from './credentials.js';
import { scanAccess } from './access.js';
import { scanSkills } from './skills.js';
import { scanRuntime } from './runtime.js';
import { scanApprovals } from './approvals.js';
import { scanWebTools } from './web.js';
import { scanMemoryBackend } from './memory.js';
import { buildScanContext } from '../utils/openclaw.js';
import { applyWaivers } from '../utils/waivers.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

export function runScan(config: OpenClawConfig, context?: ScanContext): ScanResult {
  const findings: Finding[] = [];
  const resolvedContext = context ?? buildScanContext({ config });

  // Run all scanners
  findings.push(...scanNetwork(config, resolvedContext));
  findings.push(...scanCredentials(resolvedContext));
  findings.push(...scanAccess(config, resolvedContext));
  findings.push(...scanSkills(config));
  findings.push(...scanRuntime(config));
  findings.push(...scanApprovals(config, resolvedContext));
  findings.push(...scanWebTools(config, resolvedContext));
  findings.push(...scanMemoryBackend(config, resolvedContext));

  const { findings: filteredFindings, waivedCount } = applyWaivers(
    findings,
    resolvedContext.waivers ?? []
  );

  // Calculate score (start at 100, deduct for findings)
  let score = 100;
  for (const finding of filteredFindings) {
    score -= SEVERITY_WEIGHTS[finding.severity];
  }
  score = Math.max(0, score);

  return { findings: filteredFindings, score, openClaw: resolvedContext.openClaw, waivedCount };
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
