import type { Finding, OpenClawConfig, ScanContext } from '../utils/types.js';
import { resolveGatewayAuthToken, resolveWebhookConfig } from '../utils/openclaw.js';

export function scanNetwork(config: OpenClawConfig, context: ScanContext): Finding[] {
  const findings: Finding[] = [];

  // Check gateway binding
  const host = config.gateway?.host;
  const bind = config.gateway?.bind?.toLowerCase();
  const port = config.gateway?.port || 18789;
  const authToken = resolveGatewayAuthToken(config, context.openClaw.schema);

  const authPath =
    context.openClaw.schema === 'legacy'
      ? 'gateway.authToken'
      : context.openClaw.schema === 'current'
        ? 'gateway.auth.token'
        : config.gateway?.authToken
          ? 'gateway.authToken'
          : 'gateway.auth.token';

  const exposedBindValues = new Set(['lan', 'tailnet', 'public', '0.0.0.0', '::', 'all']);
  const exposed = bind
    ? exposedBindValues.has(bind)
    : host === '0.0.0.0' || host === '::';
  const bindingPath = bind ? 'gateway.bind' : 'gateway.host';

  if (exposed) {
    if (!authToken) {
      findings.push({
        code: 'NET001',
        severity: 'critical',
        title: `Gateway exposed on ${bind ?? host ?? 'public'}:${port} without auth`,
        detail: 'The gateway is bound to all interfaces and has no authentication configured.',
        recommendation: `Set ${bindingPath} to loopback (or 127.0.0.1) or configure ${authPath}`,
        fixable: true,
        path: bindingPath,
      });
    } else {
      findings.push({
        code: 'NET002',
        severity: 'medium',
        title: `Gateway exposed on ${bind ?? host ?? 'public'}:${port}`,
        detail:
          'The gateway is bound to all interfaces. Auth is configured but exposure increases attack surface.',
        recommendation: 'Consider binding to loopback (127.0.0.1) if remote access is not needed',
        fixable: true,
        path: bindingPath,
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
      path: 'controlUI.dangerousDeviceAuthBypass',
    });
  }

  // Check webhook authentication
  const webhooks = resolveWebhookConfig(config, context.openClaw.schema);
  if (webhooks?.enabled && !webhooks?.hasAuth) {
    findings.push({
      code: 'NET004',
      severity: 'high',
      title: 'Webhooks enabled without authentication',
      detail: 'Incoming hooks are enabled without authentication, allowing injection of commands.',
      recommendation:
        webhooks.path === 'hooks.token'
          ? 'Set hooks.token or disable hooks.enabled'
          : `Set ${webhooks.path} to true`,
      fixable: webhooks.path !== 'hooks.token',
      path: webhooks.path,
    });
  }

  return findings;
}
