import type { Finding, OpenClawConfig, ScanContext } from '../utils/types.js';

const DEFAULT_MAX_REDIRECTS = 3;

export function scanWebTools(config: OpenClawConfig, _context: ScanContext): Finding[] {
  const findings: Finding[] = [];
  const fetchConfig = config.tools?.web?.fetch;

  if (!fetchConfig) {
    return findings;
  }

  if (fetchConfig.enabled === false) {
    return findings;
  }

  const maxRedirects = fetchConfig.maxRedirects;
  if (typeof maxRedirects === 'number' && maxRedirects > DEFAULT_MAX_REDIRECTS) {
    findings.push({
      code: 'WEB001',
      severity: 'medium',
      title: 'web_fetch allows long redirect chains',
      detail: `tools.web.fetch.maxRedirects is set to ${maxRedirects}, increasing redirect-based SSRF surface.`,
      recommendation: `Keep tools.web.fetch.maxRedirects at ${DEFAULT_MAX_REDIRECTS} or lower`,
      fixable: false,
      path: 'tools.web.fetch.maxRedirects',
    });
  }

  return findings;
}
