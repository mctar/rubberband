import type { ScanResult } from '../utils/types.js';
import { countBySeverity } from '../scanner/index.js';

const VERSION = '0.2.1';

interface JsonReport {
  version: string;
  timestamp: string;
  openclaw: {
    version: string | null;
    schema: string;
    source: string;
  };
  validation?: Array<{
    level: string;
    code: string;
    message: string;
    path?: string;
    line?: number;
    recommendation?: string;
  }>;
  score: number;
  waived?: number;
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
    path?: string;
  }>;
}

export function reportJson(result: ScanResult): void {
  const counts = countBySeverity(result.findings);

  const report: JsonReport = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    openclaw: {
      version: result.openClaw.version?.raw ?? null,
      schema: result.openClaw.schema,
      source: result.openClaw.source,
    },
    validation: result.validation?.map((issue) => ({
      level: issue.level,
      code: issue.code,
      message: issue.message,
      path: issue.path,
      line: issue.line,
      recommendation: issue.recommendation,
    })),
    score: result.score,
    waived: result.waivedCount,
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
      path: f.path,
    })),
  };

  console.log(JSON.stringify(report, null, 2));
}
