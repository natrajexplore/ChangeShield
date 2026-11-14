/**
 * ChangeShield pipeline
 *
 *   raw config ──► [0] deterministic redaction (local rules)
 *              ──► [1] contextual redaction   (Gemini Nano, ONLY_ON_DEVICE)
 *              ──► [2] leak gate              (local; blocks cloud on any residual secret)
 *              ──► [3] deep audit             (PREFER_IN_CLOUD → on-device fallback)
 *              ──► [4] local re-hydration     (vault never leaves memory)
 */
import type { GenerativeModel } from 'firebase/ai';
import { TokenVault, type TokenKind } from './redact/vault';
import { deterministicRedact, leakGate, detectVendor, redactFreeText, replaceIdentifier, type LeakReport } from './redact/deterministic';
import { createAuditor, createLocalAuditor, createRedactor } from './ai/models';
import { baselineAudit } from './audit/baseline';
import type { AuditResult, PiiKind } from './ai/schemas';
import { acceptCandidate, chunkLines, normaliseAudit, safeJson, scoreFindings, type AppSettings } from './core';

export { acceptCandidate, chunkLines, scoreFindings };

export type RunMode = 'hybrid' | 'local' | 'cloud';
export type Source = 'on_device' | 'in_cloud' | 'local_rules' | 'skipped';

export interface StageEvent {
  stage: 0 | 1 | 2 | 3 | 4;
  status: 'running' | 'done' | 'warn' | 'error';
  source: Source;
  message: string;
}

export interface PipelineResult {
  vendor: string;
  sanitized: string;
  audit: AuditResult;
  score: number;
  leak: LeakReport;
  stats: {
    deterministicTokens: number;
    onDeviceTokens: number;
    freeTextTokens: number;
    rulesHit: Record<string, number>;
    redactionSource: Source;
    auditSource: Source;
    chunks: number;
    elapsedMs: number;
  };
}

const KIND_MAP: Record<PiiKind, TokenKind> = {
  ORG: 'ORG', PERSON: 'PERSON', LOCATION: 'LOCATION', SITE: 'SITE', HOST: 'HOST',
  USER: 'USER', CIRCUIT: 'CIRCUIT', PHONE: 'PHONE', SECRET: 'SECRET', OTHER: 'OTHER',
};

async function onDeviceRedact(
  text: string,
  vault: TokenVault,
  chunkChars: number,
  emit: (e: StageEvent) => void,
): Promise<{ text: string; chunks: number }> {
  const redactor = createRedactor();
  const chunks = chunkLines(text, chunkChars);
  let out = text;
  for (let i = 0; i < chunks.length; i++) {
    emit({ stage: 1, status: 'running', source: 'on_device', message: `Gemini Nano scanning chunk ${i + 1}/${chunks.length}…` });
    const res = await redactor.generateContent(
      `Configuration excerpt:\n"""\n${chunks[i]}\n"""\nList remaining sensitive values as JSON.`,
    );
    if (res.response.inferenceSource && res.response.inferenceSource !== 'on_device') {
      // Defence in depth — ONLY_ON_DEVICE should make this impossible.
      throw new Error('Privacy violation: redaction did not run on-device. Aborting.');
    }
    const parsed = safeJson<{ items: Array<{ value: string; kind: PiiKind }> }>(res.response.text());
    const items = (parsed?.items ?? []).filter((it) => it && typeof it.value === 'string' && acceptCandidate(it.value, chunks[i]));
    items.sort((a, b) => b.value.length - a.value.length);
    for (const it of items) {
      const token = vault.tokenFor(it.value.trim(), KIND_MAP[it.kind] ?? 'OTHER', 'on_device');
      out = replaceIdentifier(out, it.value.trim(), token);
    }
  }
  return { text: out, chunks: chunks.length };
}

/** "ipv4 ×2, rule:snmp-community ×1" — kinds only, never the values. */
export function describeLeaks(leak: LeakReport): string {
  const counts = new Map<string, number>();
  for (const l of leak.leaks) counts.set(l.kind, (counts.get(l.kind) ?? 0) + 1);
  return [...counts].map(([k, n]) => `${k} ×${n}`).join(', ');
}

async function auditPrompt(model: GenerativeModel, vendor: string, policy: string, text: string) {
  const res = await model.generateContent(
    `Vendor/platform: ${vendor}\nPolicy pack: ${policy}\nSanitized configuration:\n"""\n${text}\n"""\nReturn the audit as JSON.`,
  );
  return { text: res.response.text(), source: (res.response.inferenceSource ?? 'in_cloud') as Source };
}

export async function runPipeline(
  raw: string,
  mode: RunMode,
  settings: AppSettings,
  vault: TokenVault,
  emit: (e: StageEvent) => void,
): Promise<PipelineResult> {
  const t0 = performance.now();
  vault.clear();
  const vendor = detectVendor(raw);

  // ---- Stage 0
  emit({ stage: 0, status: 'running', source: 'local_rules', message: 'Applying deterministic secret rules…' });
  const det = deterministicRedact(raw, vault);
  const deterministicTokens = vault.entries().length;
  emit({ stage: 0, status: 'done', source: 'local_rules', message: `${deterministicTokens} values tokenised by rules (${vendor}).` });

  // ---- Stage 1
  let sanitized = det.sanitized;
  let redactionSource: Source = 'on_device';
  let chunks = 0;
  let nanoOk = false;
  if (mode === 'cloud') {
    redactionSource = 'skipped';
  } else {
    try {
      const r = await onDeviceRedact(sanitized, vault, settings.chunkChars, emit);
      sanitized = r.text;
      chunks = r.chunks;
      nanoOk = true;
      emit({ stage: 1, status: 'done', source: 'on_device', message: `Gemini Nano masked ${vault.countBySource('on_device')} contextual identifiers on-device.` });
    } catch (e) {
      if ((e as Error).message.startsWith('Privacy violation')) throw e;
      redactionSource = 'skipped';
    }
  }
  // Without Nano, free-text fields (descriptions, comments, remarks) are masked
  // wholesale so names / sites / circuit IDs can't reach the cloud.
  let freeTextTokens = 0;
  if (!nanoOk) {
    const ft = redactFreeText(sanitized, vault);
    sanitized = ft.sanitized;
    freeTextTokens = ft.count;
    const why = mode === 'cloud' ? 'Cloud mode: on-device contextual redaction skipped' : 'Gemini Nano unavailable';
    emit({ stage: 1, status: 'warn', source: 'local_rules', message: `${why} — masked ${ft.count} free-text field(s) (descriptions/comments) wholesale instead.` });
  }

  // ---- Stage 2
  const leak = leakGate(sanitized, vault);
  if (!leak.ok) {
    emit({ stage: 2, status: 'error', source: 'local_rules', message: `Leak gate BLOCKED cloud upload: ${leak.leaks.length} residual sensitive value(s) (${describeLeaks(leak)}). Audit stays local.` });
  } else {
    emit({ stage: 2, status: 'done', source: 'local_rules', message: 'Leak gate passed — no residual secrets detected.' });
  }

  // ---- Stage 3 — cloud (if allowed) → on-device → deterministic baseline rules
  let audit: AuditResult | null = null;
  let auditSource: Source = 'skipped';
  const cloudBlockReason = !leak.ok ? 'leak gate blocked upload' : !settings.enableCloudAudit ? 'cloud audit disabled' : mode === 'local' ? 'air-gapped mode' : '';
  let reason = cloudBlockReason;
  if (!cloudBlockReason) {
    try {
      emit({ stage: 3, status: 'running', source: 'in_cloud', message: `Deep audit with ${settings.cloudModel} (${mode === 'cloud' ? 'cloud only' : 'hybrid, cloud-preferred'})…` });
      const r = await auditPrompt(createAuditor(settings.cloudModel, mode === 'cloud' ? 'cloud' : 'hybrid'), vendor, settings.policyPack, sanitized);
      const parsed = normaliseAudit(safeJson<AuditResult>(r.text), settings.maxFindings);
      if (parsed.findings.length || parsed.summary) {
        audit = parsed;
        auditSource = r.source;
      } else reason = 'model returned no parseable findings';
    } catch (e) {
      reason = (e as Error).message;
    }
  }
  if (!audit && mode !== 'cloud' && nanoOk) {
    try {
      emit({ stage: 3, status: 'running', source: 'on_device', message: `Running audit on-device (${reason})…` });
      const local = createLocalAuditor();
      const merged: AuditResult = { summary: '', findings: [] };
      const parts = chunkLines(sanitized, Math.min(settings.chunkChars, 9000));
      for (let i = 0; i < parts.length; i++) {
        emit({ stage: 3, status: 'running', source: 'on_device', message: `Gemini Nano auditing chunk ${i + 1}/${parts.length}…` });
        const r = await auditPrompt(local, vendor, settings.policyPack, parts[i]);
        const p = safeJson<AuditResult>(r.text);
        if (Array.isArray(p?.findings)) merged.findings.push(...p.findings);
        if (typeof p?.summary === 'string' && p.summary) merged.summary += (merged.summary ? ' ' : '') + p.summary;
      }
      const parsed = normaliseAudit(merged, settings.maxFindings);
      if (parsed.findings.length || parsed.summary) {
        audit = parsed;
        auditSource = 'on_device';
      } else reason = 'on-device model returned no parseable findings';
    } catch (e) {
      reason = (e as Error).message;
    }
  }
  if (!audit) {
    audit = normaliseAudit(baselineAudit(sanitized, vendor), settings.maxFindings);
    auditSource = 'local_rules';
    emit({ stage: 3, status: 'warn', source: 'local_rules', message: `AI audit unavailable (${reason}) — ran the deterministic baseline rule engine locally: ${audit.findings.length} findings.` });
  } else {
    emit({ stage: 3, status: 'done', source: auditSource, message: `${audit.findings.length} findings (${auditSource === 'in_cloud' ? 'cloud' : 'on-device'}).` });
  }

  // ---- Stage 4
  emit({ stage: 4, status: 'done', source: 'local_rules', message: 'Report ready. Real values can be revealed locally — they never left this browser.' });

  return {
    vendor,
    sanitized,
    audit,
    score: scoreFindings(audit.findings),
    leak,
    stats: {
      deterministicTokens,
      onDeviceTokens: vault.countBySource('on_device'),
      freeTextTokens,
      rulesHit: det.rulesHit,
      redactionSource,
      auditSource,
      chunks,
      elapsedMs: Math.round(performance.now() - t0),
    },
  };
}
