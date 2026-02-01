import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '../utils/types.js';
import { getConfigPath, getStateDirPath, getFilePermissions, fileExists } from '../utils/config.js';

const API_KEY_PATTERNS = [
  { name: 'OpenAI', pattern: /sk-[a-zA-Z0-9]{48}/ },
  { name: 'Anthropic', pattern: /sk-ant-[a-zA-Z0-9-]{95}/ },
  { name: 'GitHub', pattern: /gh[ps]_[a-zA-Z0-9]{36}/ },
  { name: 'Slack', pattern: /xox[baprs]-[a-zA-Z0-9-]+/ },
];

export function scanCredentials(): Finding[] {
  const findings: Finding[] = [];
  const configPath = getConfigPath();
  const stateDir = getStateDirPath();

  // Check config file permissions
  const configPerms = getFilePermissions(configPath);
  if (configPerms && configPerms !== '600') {
    findings.push({
      code: 'CRED001',
      severity: 'high',
      title: 'Config file has weak permissions',
      detail: `${configPath} has permissions ${configPerms}, should be 600.`,
      recommendation: `Run: chmod 600 ${configPath}`,
      fixable: true,
    });
  }

  // Check for plaintext secrets in config
  if (fileExists(configPath)) {
    try {
      const content = readFileSync(configPath, 'utf-8');
      for (const { name, pattern } of API_KEY_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            code: 'CRED002',
            severity: 'high',
            title: `${name} API key found in config`,
            detail: `Plaintext ${name} API key detected in openclaw.json.`,
            recommendation: 'Use environment variables or a secrets manager instead',
            fixable: false,
          });
        }
      }
    } catch {
      // Ignore read errors
    }
  }

  // Check .env file permissions
  const envPath = join(stateDir, '.env');
  if (fileExists(envPath)) {
    const envPerms = getFilePermissions(envPath);
    if (envPerms && envPerms !== '600') {
      findings.push({
        code: 'CRED003',
        severity: 'high',
        title: '.env file has weak permissions',
        detail: `${envPath} has permissions ${envPerms}, should be 600.`,
        recommendation: `Run: chmod 600 ${envPath}`,
        fixable: true,
      });
    }
  }

  // Check state directory permissions
  const stateDirPerms = getFilePermissions(stateDir);
  if (stateDirPerms && !stateDirPerms.startsWith('7')) {
    const othersPerms = parseInt(stateDirPerms[2], 10);
    if (othersPerms > 0) {
      findings.push({
        code: 'CRED004',
        severity: 'medium',
        title: 'State directory accessible by others',
        detail: `${stateDir} allows access to other users.`,
        recommendation: `Run: chmod 700 ${stateDir}`,
        fixable: true,
      });
    }
  }

  return findings;
}
