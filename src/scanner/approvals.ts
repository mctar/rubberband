import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import JSON5 from 'json5';
import type { Finding, OpenClawConfig, ScanContext } from '../utils/types.js';
import { fileExists } from '../utils/config.js';

interface ExecApprovalsFile {
  defaults?: {
    security?: string;
    ask?: string;
    askFallback?: string;
    safeBins?: string[];
  };
  agents?: Record<
    string,
    {
      security?: string;
      ask?: string;
      askFallback?: string;
      safeBins?: string[];
    }
  >;
}

const SECURITY_FULL = new Set(['full']);

function isExecAllowed(config: OpenClawConfig): boolean {
  const deny = config.tools?.deny ?? [];
  if (deny.includes('exec') || deny.includes('all') || deny.includes('*')) {
    return false;
  }

  const execSecurity = config.tools?.exec?.security;
  if (execSecurity === 'deny') return false;
  if (execSecurity === 'allowlist' || execSecurity === 'full') return true;

  const allow = config.tools?.allow ?? [];
  if (allow.includes('exec')) return true;

  if (config.shell?.enabled) return true;

  return false;
}

export function scanApprovals(config: OpenClawConfig, context: ScanContext): Finding[] {
  const findings: Finding[] = [];
  const hasSignals =
    context.openClaw.schema === 'current' ||
    !!config.approvals?.exec ||
    !!config.tools?.exec ||
    !!config.shell?.enabled;

  if (!hasSignals) {
    return findings;
  }

  const approvalsPath = join(context.paths.stateDir, 'exec-approvals.json');
  const execAllowed = isExecAllowed(config);

  if (execAllowed && !fileExists(approvalsPath)) {
    findings.push({
      code: 'APPROVALS001',
      severity: 'high',
      title: 'Exec approvals file missing',
      detail: 'Exec tool appears enabled but no approvals file was found.',
      recommendation: `Create ${approvalsPath} or set tools.exec.security to "deny"`,
      fixable: false,
      path: approvalsPath,
    });
    return findings;
  }

  if (!fileExists(approvalsPath)) {
    return findings;
  }

  try {
    const content = readFileSync(approvalsPath, 'utf-8');
    const approvals = JSON5.parse(content) as ExecApprovalsFile;
    const defaults = approvals.defaults ?? {};

    if (defaults.security && SECURITY_FULL.has(defaults.security)) {
      findings.push({
        code: 'APPROVALS002',
        severity: 'high',
        title: 'Exec approvals allow unrestricted execution',
        detail: 'Default exec approvals security is set to "full".',
        recommendation: 'Set defaults.security to "allowlist" or "deny"',
        fixable: false,
        path: `${approvalsPath}:defaults.security`,
      });
    }

    if (defaults.askFallback && SECURITY_FULL.has(defaults.askFallback)) {
      findings.push({
        code: 'APPROVALS003',
        severity: 'medium',
        title: 'Exec approvals fallback is unrestricted',
        detail: 'Default exec approvals askFallback is set to "full".',
        recommendation: 'Set defaults.askFallback to "deny" or "allowlist"',
        fixable: false,
        path: `${approvalsPath}:defaults.askFallback`,
      });
    }

    if (approvals.agents) {
      for (const [agent, agentConfig] of Object.entries(approvals.agents)) {
        if (agentConfig.security && SECURITY_FULL.has(agentConfig.security)) {
          findings.push({
            code: 'APPROVALS004',
            severity: 'medium',
            title: `Agent ${agent} has unrestricted exec approvals`,
            detail: `Exec approvals for agent "${agent}" are set to "full".`,
            recommendation: 'Set agent security to "allowlist" or "deny"',
            fixable: false,
            path: `${approvalsPath}:agents.${agent}.security`,
          });
        }
      }
    }
  } catch {
    findings.push({
      code: 'APPROVALS005',
      severity: 'medium',
      title: 'Exec approvals file could not be parsed',
      detail: 'Rubberband could not parse exec-approvals.json.',
      recommendation: `Validate ${approvalsPath} for JSON5 syntax errors`,
      fixable: false,
      path: approvalsPath,
    });
  }

  const execApproval = config.approvals?.exec;
  if (execApproval?.enabled) {
    const mode = execApproval.mode ?? 'session';
    if ((mode === 'targets' || mode === 'both') && (!execApproval.targets || execApproval.targets.length === 0)) {
      findings.push({
        code: 'APPROVALS006',
        severity: 'low',
        title: 'Exec approvals enabled without targets',
        detail: 'Exec approvals are enabled in targets mode but no targets are configured.',
        recommendation: 'Set approvals.exec.targets or switch mode to "session"',
        fixable: false,
        path: 'approvals.exec.targets',
      });
    }
  }

  return findings;
}
