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

describe('model call timeouts', () => {
  it('rejects a stalled call and passes a fast one through', async () => {
    const { withTimeout } = await import('../src/core');
    await expect(withTimeout(new Promise(() => {}), 20, 'Nano')).rejects.toThrow('Nano timed out');
    await expect(withTimeout(Promise.resolve(7), 1000, 'x')).resolves.toBe(7);
  });
});

describe('merging baseline rule findings into AI reports', () => {
  const f = (title: string, severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'high', category = 'management-plane') => ({
    id: '', title, severity, category, evidence: '', why: '', fix: '',
  });
  const rule = (title: string) => f(title);

  it('recognises AI findings that report the same issue', async () => {
    const { coveredBy } = await import('../src/core');
    const pairs: Array<[string, string]> = [
      ['Telnet allowed on VTY lines', 'Insecure Telnet access permitted to the router'],
      ['SNMP community with write (RW) access', 'SNMP community string grants RW access'],
      ['Idle session timeout disabled (exec-timeout 0 0)', 'No exec-timeout on VTY lines'],
      ['VTY lines not restricted by an access-class', 'VTY lines lack an access-class ACL'],
      ['Weak IKE/IPsec encryption (DES/3DES)', 'IKE policy uses 3DES encryption'],
      ['HTTP management server enabled', 'Unencrypted HTTP server enabled'],
      ['AAA not enabled (no aaa new-model)', 'AAA new-model not configured'],
      // Titles Gemini actually returned on the live site for the Cisco sample:
      ['Idle session timeout disabled (exec-timeout 0 0)', 'VTY Session Timeout Disabled'],
      ['Password encryption service disabled', 'Password Encryption Not Enabled'],
    ];
    for (const [r, a] of pairs) expect(coveredBy(rule(r), f(a)), `${r} ← ${a}`).toBe(true);
  });

  it('matches one combined AI crypto finding to each weak-algorithm rule, by category', async () => {
    const { coveredBy } = await import('../src/core');
    const isakmp = f('Weak ISAKMP Cryptographic Suite (DES, MD5, Group 1)', 'high', 'crypto');
    for (const r of ['Weak IKE/IPsec encryption (DES/3DES)', 'Weak IKE hash / integrity algorithm (MD5/SHA-1)', 'Weak Diffie-Hellman group (1, 2 or 5)'])
      expect(coveredBy(f(r, 'high', 'crypto'), isakmp), r).toBe(true);
    // Same "MD5" word, different issue: password hashing (aaa) is not IKE crypto.
    expect(coveredBy(f('MD5-based (type 5) password hashes', 'medium', 'aaa'), isakmp)).toBe(false);
    expect(coveredBy(f('AAA not enabled (no aaa new-model)', 'high', 'aaa'), f('AAA Not Enabled (Local Authentication Only)', 'high', 'aaa'))).toBe(true);
  });

  it('does not treat a different issue in the same place as covered', async () => {
    const { coveredBy } = await import('../src/core');
    const pairs: Array<[string, string]> = [
      ['SNMPv1/v2c communities in use', 'SNMP community string grants RW access'],
      ['SNMP community with write (RW) access', 'SNMPv2c enabled without ACL'],
      ['VTY lines not restricted by an access-class', 'Telnet allowed on VTY lines'],
      ['Idle session timeout disabled (exec-timeout 0 0)', 'Telnet allowed on VTY lines'],
      ['Weak IKE hash / integrity algorithm (MD5/SHA-1)', 'Weak IKE/IPsec encryption (DES/3DES)'],
      ['MD5-based (type 5) password hashes', 'Cleartext or reversible (type 7) passwords'],
      ['VTY lines not restricted by an access-class', 'Insecure Telnet access permitted'],
      ['SNMP community with write (RW) access', 'Insecure Telnet access permitted'],
      ['NTP without authentication', 'BGP neighbor without password'],
    ];
    for (const [r, a] of pairs) expect(coveredBy(rule(r), f(a)), `${r} ← ${a}`).toBe(false);
  });

  it('adds only missed rule findings, tags them, sorts, caps and renumbers', async () => {
    const { mergeFindings } = await import('../src/core');
    const { sanitized } = rulesOnly(ios);
    const baseline = normaliseAudit(baselineAudit(sanitized, detectVendor(ios)), 50);
    const ai = normaliseAudit(
      { summary: 'AI summary.', findings: [f('Insecure Telnet access permitted', 'critical'), f('BGP neighbor without password', 'medium', 'control-plane')] },
      25,
    );
    const m = mergeFindings(ai, baseline, 50);
    expect(m.added).toBe(baseline.findings.length - 1); // only Telnet was already reported
    expect(m.findings.filter((x) => /telnet/i.test(x.title))).toHaveLength(1);
    expect(m.findings.find((x) => x.title.startsWith('BGP'))?.origin).toBeUndefined();
    expect(m.findings.filter((x) => x.origin === 'rules')).toHaveLength(m.added);
    expect(m.findings.map((x) => x.id)).toEqual(m.findings.map((_, i) => `CS-${String(i + 1).padStart(3, '0')}`));
    const ranks = m.findings.map((x) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(x.severity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    expect(m.summary).toMatch(/^AI summary\. The local baseline rule engine added \d+/);

    const capped = mergeFindings(ai, baseline, 5);
    expect(capped.findings).toHaveLength(5);
    expect(capped.added).toBe(capped.findings.filter((x) => x.origin === 'rules').length);
  });

  it('keeps the note when the AI summary is at the length limit', async () => {
    const { mergeFindings } = await import('../src/core');
    const m = mergeFindings({ summary: 'x'.repeat(3900), findings: [] }, { summary: '', findings: [rule('Telnet allowed on VTY lines')] }, 10);
    expect(m.summary.length).toBeLessThanOrEqual(3900);
    expect(m.summary).toMatch(/added 1 deterministic finding/);
  });

  it('leaves the AI report untouched when nothing was missed', async () => {
    const { mergeFindings } = await import('../src/core');
    const ai = { summary: 'S', findings: [{ ...f('Telnet enabled'), id: 'CS-001' }] };
    const m = mergeFindings(ai, { summary: '', findings: [rule('Telnet allowed on VTY lines')] }, 10);
    expect(m).toEqual({ ...ai, added: 0 });
  });
});
