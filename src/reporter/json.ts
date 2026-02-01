import type { ScanResult } from '../utils/types.js';
import { countBySeverity } from '../scanner/index.js';

const VERSION = '0.1.0';

interface JsonReport {
  version: string;
  timestamp: string;
  score: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  findings: Array<{
    code: string;
    severity: string;
    title: string;
    detail: string;
    recommendation: string;
    fixable: boolean;
  }>;
}

export function reportJson(result: ScanResult): void {
  const counts = countBySeverity(result.findings);

  const report: JsonReport = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    score: result.score,
    summary: {
      ...counts,
      total: result.findings.length,
    },
    findings: result.findings.map((f) => ({
      code: f.code,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      recommendation: f.recommendation,
      fixable: f.fixable ?? false,
    })),
  };

  console.log(JSON.stringify(report, null, 2));
}
