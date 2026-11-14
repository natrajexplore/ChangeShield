/** Pure helpers (no Firebase imports) — unit-testable in Node. */
import { CATEGORIES, SEVERITIES, type AuditFinding, type AuditResult, type Severity } from './ai/schemas';

export interface AppSettings {
  cloudModel: string;
  enableCloudAudit: boolean;
  chunkChars: number;
  policyPack: string;
  maxFindings: number;
}

export const DEFAULT_SETTINGS: AppSettings = {
  cloudModel: 'gemini-3.5-flash-lite',
  enableCloudAudit: true,
  chunkChars: 12000,
  policyPack: 'baseline-v1',
  maxFindings: 25,
};

const clampInt = (v: number, lo: number, hi: number, dflt: number) =>
  Number.isFinite(v) && v > 0 ? Math.min(hi, Math.max(lo, Math.round(v))) : dflt;

/**
 * Remote Config values are operator-controlled — bound them so a typo (0, NaN, 1e9)
 * can't create thousands of Nano calls, an empty report, or a Firestore write that
 * the security rules reject (findings <= 50).
 */
export function clampSettings(s: AppSettings): AppSettings {
  return {
    cloudModel: /^[\w.-]{3,64}$/.test(s.cloudModel) ? s.cloudModel : DEFAULT_SETTINGS.cloudModel,
    enableCloudAudit: s.enableCloudAudit,
    chunkChars: clampInt(s.chunkChars, 1000, 20000, DEFAULT_SETTINGS.chunkChars),
    policyPack: (s.policyPack || DEFAULT_SETTINGS.policyPack).slice(0, 64),
    maxFindings: clampInt(s.maxFindings, 1, 50, DEFAULT_SETTINGS.maxFindings),
  };
}

const KEYWORD_STOPLIST = new Set([
  'interface', 'description', 'shutdown', 'vlan', 'router', 'access-list', 'permit', 'deny', 'any', 'host',
  'uplink', 'downlink', 'trunk', 'access', 'management', 'mgmt', 'core', 'distribution', 'edge', 'wan', 'lan',
  'internet', 'isp', 'firewall', 'switch', 'server', 'printer', 'guest', 'voice', 'data', 'native', 'unused',
]);

/** Split on line boundaries so each chunk fits Gemini Nano's context (≈9216 tokens). */
export function chunkLines(text: string, maxChars: number): string[] {
  const lines = text.split('\n');
  const chunks: string[] = [];
  let cur: string[] = [];
  let len = 0;
  for (const line of lines) {
    if (len + line.length + 1 > maxChars && cur.length) {
      chunks.push(cur.join('\n'));
      cur = [];
      len = 0;
    }
    cur.push(line);
    len += line.length + 1;
  }
  if (cur.length) chunks.push(cur.join('\n'));
  return chunks;
}

export function safeJson<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return null;
    try {
      return JSON.parse(m[0]) as T;
    } catch {
      return null;
    }
  }
}

/** Accept a model-suggested value only if it really is a verbatim, non-trivial substring. */
export function acceptCandidate(value: string, chunk: string): boolean {
  const v = value.trim();
  if (v.length < 3 || v.length > 120) return false;
  if (/^<[A-Z_]+_\d+>$/.test(v)) return false;
  if (KEYWORD_STOPLIST.has(v.toLowerCase())) return false;
  if (/^(?:Gi|Te|Fa|Eth|Po|Vl|Lo|Tu|Hu|Fo)[a-zA-Z]*\d/.test(v)) return false; // interface names
  if (/^\d+$/.test(v)) return false;
  return chunk.includes(v);
}

/** 100 = clean. Deductions are capped per severity so one noisy class can't zero the score. */
export function scoreFindings(findings: AuditFinding[]): number {
  const w: Record<string, [number, number]> = { critical: [20, 60], high: [10, 40], medium: [4, 20], low: [1, 8], info: [0, 0] };
  const tally: Record<string, number> = {};
  for (const f of findings) tally[f.severity] = (tally[f.severity] ?? 0) + 1;
  let ded = 0;
  for (const [sev, n] of Object.entries(tally)) {
    const [each, cap] = w[sev] ?? [0, 0];
    ded += Math.min(each * n, cap);
  }
  return Math.max(0, 100 - ded);
}


const str = (v: unknown, max = 4000): string => (typeof v === 'string' ? v : v == null ? '' : String(v)).slice(0, max);

/**
 * Validate / coerce model output. Model JSON is untrusted: unknown severities or
 * categories are mapped to safe enum values (they are used in CSS class names),
 * missing fields become empty strings, duplicates are dropped, and findings are
 * re-numbered and sorted by severity.
 */
export function normaliseAudit(a: unknown, max: number): AuditResult {
  const obj = a as Partial<AuditResult> | null;
  if (!obj || !Array.isArray(obj.findings)) return { summary: 'The model returned no parseable findings.', findings: [] };
  const rank = (s: Severity) => SEVERITIES.indexOf(s);
  const seen = new Set<string>();
  const findings: AuditFinding[] = [];
  for (const raw of obj.findings as unknown[]) {
    if (!raw || typeof raw !== 'object') continue;
    const f = raw as Record<string, unknown>;
    const title = str(f.title, 300).trim();
    if (!title) continue;
    const key = title.toLowerCase().replace(/\W+/g, ' ').trim();
    if (seen.has(key)) continue;
    seen.add(key);
    const sev = str(f.severity).toLowerCase() as Severity;
    const cat = str(f.category).toLowerCase();
    const ref = str(f.reference, 500).trim();
    findings.push({
      id: '',
      title,
      severity: SEVERITIES.includes(sev) ? sev : 'info',
      category: (CATEGORIES as readonly string[]).includes(cat) ? cat : 'hygiene',
      evidence: str(f.evidence),
      why: str(f.why),
      fix: str(f.fix),
      ...(ref ? { reference: ref } : {}),
    });
  }
  findings.sort((x, y) => rank(x.severity) - rank(y.severity));
  return {
    summary: str(obj.summary, 3900),
    findings: findings.slice(0, max).map((f, i) => ({ ...f, id: `CS-${String(i + 1).padStart(3, '0')}` })),
  };
}

/** Model call budgets. A stalled call must fall back, never freeze the UI. */
export const TIMEOUTS = { onDeviceChunkMs: 60_000, cloudAuditMs: 90_000 } as const;

/** Reject if `p` hasn't settled within `ms`. (The underlying call is abandoned, not cancelled.) */
export function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}
