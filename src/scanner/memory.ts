import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { Finding, OpenClawConfig, ScanContext } from '../utils/types.js';

function commandExists(command: string): boolean {
  if (!command) return false;
  if (command.includes('/') || command.includes('\\')) {
    return existsSync(command);
  }
  try {
    const result = spawnSync(command, ['--version'], {
      encoding: 'utf-8',
      stdio: 'pipe',
      timeout: 1500,
      maxBuffer: 1024 * 1024,
    });
    return !result.error && result.status === 0;
  } catch {
    return false;
  }
}

export function scanMemoryBackend(config: OpenClawConfig, _context: ScanContext): Finding[] {
  const findings: Finding[] = [];
  const backend = config.memory?.backend;
  if (!backend || backend.toLowerCase() !== 'qmd') {
    return findings;
  }

  const command = config.memory?.qmd?.command || 'qmd';
  if (!commandExists(command)) {
    findings.push({
      code: 'MEM001',
      severity: 'medium',
      title: 'QMD memory backend not available',
      detail: `memory.backend is set to "qmd" but "${command}" was not found.`,
      recommendation: 'Install qmd or set memory.qmd.command to the correct path',
      fixable: false,
      path: 'memory.qmd.command',
    });
  }

  return findings;
}
