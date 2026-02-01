import type { Finding, OpenClawConfig } from '../utils/types.js';

export function scanNetwork(config: OpenClawConfig): Finding[] {
  const findings: Finding[] = [];

  // Check gateway binding
  const host = config.gateway?.host;
  const port = config.gateway?.port || 18789;
  const authToken = config.gateway?.authToken;

  if (host === '0.0.0.0') {
    if (!authToken) {
      findings.push({
        code: 'NET001',
        severity: 'critical',
        title: `Gateway exposed on 0.0.0.0:${port} without auth`,
        detail: 'The gateway is bound to all interfaces and has no authentication configured.',
        recommendation: 'Set gateway.host to 127.0.0.1 or configure auth token',
        fixable: true,
      });
    } else {
      findings.push({
        code: 'NET002',
        severity: 'medium',
        title: `Gateway exposed on 0.0.0.0:${port}`,
        detail:
          'The gateway is bound to all interfaces. Auth is configured but exposure increases attack surface.',
        recommendation: 'Consider binding to 127.0.0.1 if remote access is not needed',
        fixable: true,
      });
    }
  }

  // Check control UI auth bypass
  if (config.controlUI?.enabled && config.controlUI?.dangerousDeviceAuthBypass) {
    findings.push({
      code: 'NET003',
      severity: 'high',
      title: 'Control UI auth bypass enabled',
      detail: 'dangerousDeviceAuthBypass allows unauthenticated access to the control panel.',
      recommendation: 'Set controlUI.dangerousDeviceAuthBypass to false',
      fixable: true,
    });
  }

  // Check webhook authentication
  if (config.webhooks?.enabled && !config.webhooks?.requireAuth) {
    findings.push({
      code: 'NET004',
      severity: 'high',
      title: 'Webhooks enabled without authentication',
      detail: 'Incoming webhooks do not require authentication, allowing injection of commands.',
      recommendation: 'Set webhooks.requireAuth to true',
      fixable: true,
    });
  }

  return findings;
}
