import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import JSON5 from 'json5';
import type { Finding, ScanContext, Waiver } from './types.js';
import { fileExists } from './config.js';

function getWaiverPath(context: ScanContext): string {
  return join(context.paths.stateDir, 'rubberband', 'waivers.json');
}

function isExpired(waiver: Waiver, now: Date): boolean {
  const expiresAt = new Date(waiver.expiresAt);
  if (Number.isNaN(expiresAt.getTime())) return true;
  return expiresAt.getTime() < now.getTime();
}

export function loadWaivers(context: ScanContext): Waiver[] {
  const path = getWaiverPath(context);
  if (!fileExists(path)) return [];
  try {
    const content = readFileSync(path, 'utf-8');
    const parsed = JSON5.parse(content) as { waivers?: Waiver[] };
    const waivers = parsed.waivers ?? [];
    const now = new Date();
    return waivers.filter((waiver) => !isExpired(waiver, now));
  } catch {
    return [];
  }
}

export function saveWaivers(context: ScanContext, waivers: Waiver[]): void {
  const path = getWaiverPath(context);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ waivers }, null, 2));
}

export function addWaiver(context: ScanContext, waiver: Waiver): Waiver[] {
  const waivers = loadWaivers(context);
  waivers.push(waiver);
  saveWaivers(context, waivers);
  return waivers;
}

export function removeWaiver(
  context: ScanContext,
  code: string,
  path?: string
): { waivers: Waiver[]; removed: number } {
  const waivers = loadWaivers(context);
  const filtered = waivers.filter((waiver) => {
    if (waiver.code !== code) return true;
    if (path && waiver.path !== path) return true;
    return false;
  });
  const removed = waivers.length - filtered.length;
  saveWaivers(context, filtered);
  return { waivers: filtered, removed };
}

function matchesWaiver(finding: Finding, waiver: Waiver): boolean {
  if (finding.code !== waiver.code) return false;
  if (waiver.path) {
    return finding.path === waiver.path;
  }
  return true;
}

export function applyWaivers(
  findings: Finding[],
  waivers: Waiver[]
): { findings: Finding[]; waivedCount: number } {
  if (!waivers || waivers.length === 0) {
    return { findings, waivedCount: 0 };
  }
  const filtered: Finding[] = [];
  let waivedCount = 0;
  for (const finding of findings) {
    const waived = waivers.some((waiver) => matchesWaiver(finding, waiver));
    if (waived) {
      waivedCount++;
      continue;
    }
    filtered.push(finding);
  }
  return { findings: filtered, waivedCount };
}
