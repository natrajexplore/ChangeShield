import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { TokenVault } from '../src/redact/vault';
import { deterministicRedact, detectVendor, leakGate, redactFreeText } from '../src/redact/deterministic';
import { baselineAudit, BASELINE_CHECK_COUNT } from '../src/audit/baseline';
import { clampSettings, DEFAULT_SETTINGS, normaliseAudit, scoreFindings } from '../src/core';

const ios = readFileSync(new URL('../samples/cisco-iosxe-branch.cfg', import.meta.url), 'utf8');
const pan = readFileSync(new URL('../samples/panos-edge-set.txt', import.meta.url), 'utf8');

const rulesOnly = (cfg: string) => {
  const v = new TokenVault();
  const det = deterministicRedact(cfg, v);
  const ft = redactFreeText(det.sanitized, v);
  return { v, sanitized: ft.sanitized, count: ft.count };
};

describe('free-text fallback redaction (no Gemini Nano)', () => {
  it('masks people, sites and circuit IDs in IOS descriptions', () => {
    const { v, sanitized, count } = rulesOnly(ios);
    for (const s of ['Priya Raman', 'Treasury', 'Airtel', '091BANG623410', 'Koramangala']) expect(sanitized, s).not.toContain(s);
    expect(count).toBeGreaterThanOrEqual(2);
    expect(sanitized).toMatch(/description <FREETEXT_\d+>/);
    expect(leakGate(sanitized, v).ok).toBe(true);
  });

  it('masks quoted PAN-OS comments', () => {
    const { sanitized } = rulesOnly(pan);
    for (const s of ['Arjun', '9840012345', '045CHEN88812', 'Tata Comm']) expect(sanitized, s).not.toContain(s);
    expect(sanitized).toMatch(/comment <FREETEXT_\d+>/);
  });

  it('leaves placeholder-only descriptions alone and re-hydrates nested tokens', () => {
    const v = new TokenVault();
    const det = deterministicRedact('hostname R1\ninterface Gi1\n description R1\n description link to 10.1.1.1 at HQ\n', v);
    const { sanitized } = redactFreeText(det.sanitized, v);
    expect(sanitized).toContain(' description <HOST_1>');
    expect(v.rehydrate(sanitized)).toContain('description link to 10.1.1.1 at HQ');
  });

  it('handles ACL remarks', () => {
    const { sanitized } = rulesOnly('access-list 101 remark Allow Bob Smith laptop\nip access-list extended X\n remark Finance team\n');
    expect(sanitized).not.toContain('Bob Smith');
    expect(sanitized).not.toContain('Finance team');
  });
});

describe('baseline rule auditor', () => {
  it('finds the planted IOS issues', () => {
    const { sanitized } = rulesOnly(ios);
    const r = baselineAudit(sanitized, detectVendor(ios));
    const titles = r.findings.map((f) => f.title).join('\n');
    for (const t of ['Telnet', 'HTTP management', 'AAA not enabled', 'enable password', 'type 0/7', 'MD5-based', 'RW', 'exec-timeout', 'access-class', 'DES/3DES', 'MD5/SHA-1', 'Diffie-Hellman', 'Default, dictionary'])
      expect(titles, t).toContain(t);
    // evidence is sanitized text — no real secret
    expect(JSON.stringify(r)).not.toContain('cisco123');
  });

  it('finds the planted PAN-OS issues and nothing Cisco-specific', () => {
    const { sanitized } = rulesOnly(pan);
    const r = baselineAudit(sanitized, detectVendor(pan));
    const titles = r.findings.map((f) => f.title).join('\n');
    for (const t of ['Telnet enabled', 'HTTP enabled', 'Any-to-any', 'Remote-access', 'log', 'SNMPv2c', 'DES/3DES', 'MD5/SHA-1', 'Diffie-Hellman'])
      expect(titles, t).toContain(t);
    expect(titles).not.toContain('aaa new-model');
  });

  it('clean config yields a high score', () => {
    const r = baselineAudit('hostname <HOST_1>\nip ssh version 2\nservice timestamps log datetime\nline vty 0 4\n access-class MGMT in\n transport input ssh\n', 'Cisco IOS / IOS-XE');
    expect(r.findings).toHaveLength(0);
    expect(scoreFindings(r.findings)).toBe(100);
    expect(BASELINE_CHECK_COUNT).toBeGreaterThan(20);
  });
});

describe('model output hardening', () => {
  it('coerces hostile / malformed findings', () => {
    const r = normaliseAudit(
      {
        summary: 'x'.repeat(10_000),
        findings: [
          { title: 'A', severity: '"><img src=x onerror=alert(1)>', category: 'evil' },
          { title: 'a', severity: 'high' }, // duplicate title
          null,
          { severity: 'high' }, // no title
          { title: 'B', severity: 'CRITICAL', category: 'crypto', evidence: 42, fix: null },
        ],
      },
      25,
    );
    expect(r.summary.length).toBeLessThanOrEqual(3900);
    expect(r.findings).toHaveLength(2);
    expect(r.findings[0]).toMatchObject({ id: 'CS-001', title: 'B', severity: 'critical', category: 'crypto', evidence: '42', fix: '' });
    expect(r.findings[1]).toMatchObject({ title: 'A', severity: 'info', category: 'hygiene', why: '' });
  });

  it('rejects non-object output', () => {
    expect(normaliseAudit(null, 10).findings).toEqual([]);
    expect(normaliseAudit({ findings: 'nope' }, 10).findings).toEqual([]);
  });

  it('clamps Remote Config values', () => {
    const s = clampSettings({ cloudModel: 'bad model!', enableCloudAudit: true, chunkChars: 0, policyPack: '', maxFindings: 1e9 });
    expect(s.cloudModel).toBe(DEFAULT_SETTINGS.cloudModel);
    expect(s.chunkChars).toBe(DEFAULT_SETTINGS.chunkChars);
    expect(s.maxFindings).toBe(50);
    expect(s.policyPack).toBe(DEFAULT_SETTINGS.policyPack);
    expect(clampSettings({ ...DEFAULT_SETTINGS, chunkChars: Number.NaN }).chunkChars).toBe(DEFAULT_SETTINGS.chunkChars);
  });
});
