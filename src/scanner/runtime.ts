import type { Finding, OpenClawConfig } from '../utils/types.js';
import { getFilePermissions } from '../utils/config.js';

export function scanRuntime(config: OpenClawConfig): Finding[] {
  const findings: Finding[] = [];

  // Check logging level
  const logLevel = config.logging?.level;
  if (logLevel === 'debug' || logLevel === 'trace') {
    findings.push({
      code: 'RUN001',
      severity: 'low',
      title: 'Verbose logging may expose message content',
      detail: `Logging level is set to "${logLevel}", which may log sensitive data.`,
      recommendation: 'Set logging.level to "info" in production',
      fixable: true,
      path: 'logging.level',
    });
  }

  // Check log file permissions
  const logFile = config.logging?.file;
  if (logFile) {
    const logPerms = getFilePermissions(logFile);
    if (logPerms && logPerms !== '600' && logPerms !== '640') {
      findings.push({
        code: 'RUN002',
        severity: 'medium',
      title: 'Log file has weak permissions',
      detail: `Log file ${logFile} has permissions ${logPerms}.`,
      recommendation: 'Run: chmod 600 ' + logFile,
      fixable: true,
      path: 'logging.file',
    });
  }
  }

  // Check rate limiting
  if (config.rateLimit && !config.rateLimit.enabled) {
    findings.push({
      code: 'RUN003',
      severity: 'medium',
      title: 'Rate limiting disabled',
      detail: 'No rate limiting allows resource exhaustion and abuse.',
      recommendation: 'Set rateLimit.enabled to true',
      fixable: true,
      path: 'rateLimit.enabled',
    });
  }

  // Check browser sandbox
  if (config.browser?.enabled && !config.browser?.sandbox) {
    findings.push({
      code: 'RUN004',
      severity: 'high',
      title: 'Browser sandbox disabled',
      detail: 'Browser runs without sandboxing, increasing risk of escape.',
      recommendation: 'Set browser.sandbox to true',
      fixable: true,
      path: 'browser.sandbox',
    });
  }

  // Check browser headless mode
  if (config.browser?.enabled && config.browser?.headless === false) {
    findings.push({
      code: 'RUN005',
      severity: 'low',
      title: 'Browser running in headed mode',
      detail: 'Headed browser mode is typically only needed for debugging.',
      recommendation: 'Set browser.headless to true in production',
      fixable: true,
      path: 'browser.headless',
    });
  }

  // Check shell execution
  if (config.shell?.enabled) {
    const allowedCommands = config.shell.allowedCommands;
    if (!allowedCommands || allowedCommands.length === 0) {
      findings.push({
        code: 'RUN006',
        severity: 'critical',
      title: 'Shell execution enabled without restrictions',
      detail: 'Shell access is enabled with no command allowlist.',
      recommendation: 'Configure shell.allowedCommands or disable shell.enabled',
      fixable: true,
      path: 'shell.allowedCommands',
    });
  } else {
    findings.push({
      code: 'RUN007',
      severity: 'medium',
      title: 'Shell execution enabled',
      detail: `Shell is enabled with ${allowedCommands.length} allowed commands.`,
      recommendation: 'Review allowed commands: ' + allowedCommands.join(', '),
      fixable: false,
      path: 'shell.allowedCommands',
    });
  }
  }

  // Check memory encryption
  if (config.memory?.persistent && !config.memory?.encrypted) {
    findings.push({
      code: 'RUN008',
      severity: 'medium',
      title: 'Persistent memory not encrypted',
      detail: 'Memory is persisted without encryption.',
      recommendation: 'Set memory.encrypted to true',
      fixable: true,
      path: 'memory.encrypted',
    });
  }

  // Check auto-update
  if (config.updates?.autoInstall) {
    findings.push({
      code: 'RUN009',
      severity: 'low',
      title: 'Auto-update enabled',
      detail: 'Automatic updates may introduce untested changes.',
      recommendation: 'Consider manual updates for production deployments',
      fixable: false,
      path: 'updates.autoInstall',
    });
  }

  return findings;
}
