import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { TokenVault } from '../src/redact/vault';
import { deterministicRedact, leakGate, isMaskLike, detectVendor } from '../src/redact/deterministic';
import { acceptCandidate, chunkLines, scoreFindings } from '../src/core';

const ios = readFileSync(new URL('../samples/cisco-iosxe-branch.cfg', import.meta.url), 'utf8');
const pan = readFileSync(new URL('../samples/panos-edge-set.txt', import.meta.url), 'utf8');

const MUST_NOT_SURVIVE_IOS = [
  '0822455D0A16', 'Sup3rS3cret!', '$1$mERr$hx5rVt7rPNoS4wqbXKX7m0', 'C0ntos0RW', 'public RO',
  '045802150C2E', 'Branch@VPN2026', '094F471A1A0A', 'cisco123', 'BLR-BR-SW01',
  'branch.contoso-finserv.example', 'noc@contoso-finserv.example', '+91 80 4000 1234',
  '203.0.113.45', '198.51.100.7', '10.20.99.2', 'netadmin',
];
const MUST_NOT_SURVIVE_PAN = [
  'CHN-DC-PA01', 'dc.northwind-health.example', '203.0.113.20', '$1$abcdefgh$Hk3s9dP0aQwL2mVx7yZ1t.',
  'Nw@Ike!2026', 'Nw-public', '198.51.100.10', '10.50.0.25', 'Northwind Health Chennai DC',
];

describe('deterministic redaction', () => {
  it('removes every known secret / identifier from the IOS sample', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(ios, v);
    for (const s of MUST_NOT_SURVIVE_IOS) expect(sanitized, s).not.toContain(s.replace(' RO', ''));
    expect(leakGate(sanitized, v).ok).toBe(true);
  });

  it('removes every known secret / identifier from the PAN-OS sample', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(pan, v);
    for (const s of MUST_NOT_SURVIVE_PAN) expect(sanitized, s).not.toContain(s);
    expect(leakGate(sanitized, v).ok).toBe(true);
  });

  it('keeps audit-relevant structure (masks, syntax, weak settings)', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(ios, v);
    for (const keep of ['255.255.255.0', '0.0.0.0 0.0.0.0', 'transport input telnet ssh', 'encr des', 'group 1',
      'no service password-encryption', 'snmp-server community <WEAKSECRET_', 'snmp-server community <SECRET_', ' password <WEAKSECRET_', 'enable password 7 <SECRET_', 'exec-timeout 0 0'])
      expect(sanitized, keep).toContain(keep);
  });

  it('uses consistent tokens and re-hydrates locally', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact(ios, v);
    expect(v.rehydrate(sanitized)).toContain('Branch@VPN2026');
    const t1 = v.tokenFor('BLR-BR-SW01', 'HOST');
    expect(v.tokenFor('BLR-BR-SW01', 'HOST')).toBe(t1);
  });

  it('does not treat key ids / syntax words as secrets', () => {
    const v = new TokenVault();
    const cfg = 'key chain EIGRP\n key 1\n  key-string 7 06070E2B4D\ncrypto key generate rsa modulus 2048\n';
    const { sanitized } = deterministicRedact(cfg, v);
    expect(sanitized).toContain('key chain EIGRP');
    expect(sanitized).toContain(' key 1');
    expect(sanitized).toContain('crypto key generate rsa');
    expect(sanitized).not.toContain('06070E2B4D');
  });

  it('flags weak / default secrets without revealing them', () => {
    const v = new TokenVault();
    const { sanitized } = deterministicRedact('snmp-server community public RO\nusername a secret 0 Xy9!long-pass\n', v);
    expect(sanitized).toContain('community <WEAKSECRET_1> RO');
    expect(sanitized).toContain('secret 0 <SECRET_1>');
    expect(sanitized).not.toContain('public');
  });

  it('leak gate blocks a residual secret', () => {
    const v = new TokenVault();
    v.tokenFor('hunter2pass', 'SECRET');
    const r = leakGate('username x secret 0 hunter2pass\nlogging host 8.8.8.8', v);
    expect(r.ok).toBe(false);
    expect(r.leaks.length).toBeGreaterThanOrEqual(2);
  });
});

describe('helpers', () => {
  it('mask detection', () => {
    expect(isMaskLike('255.255.255.0')).toBe(true);
    expect(isMaskLike('0.0.0.255')).toBe(true);
    expect(isMaskLike('10.0.0.1')).toBe(false);
    expect(isMaskLike('192.168.1.0')).toBe(false);
  });
  it('vendor detection', () => {
    expect(detectVendor(ios)).toBe('Cisco IOS / IOS-XE');
    expect(detectVendor(pan)).toBe('Palo Alto PAN-OS');
  });
  it('rejects hallucinated or trivial on-device candidates', () => {
    const chunk = ' description Desk of Priya Raman - Treasury';
    expect(acceptCandidate('Priya Raman', chunk)).toBe(true);
    expect(acceptCandidate('John Doe', chunk)).toBe(false);
    expect(acceptCandidate('GigabitEthernet1/0/1', 'interface GigabitEthernet1/0/1')).toBe(false);
    expect(acceptCandidate('<HOST_1>', '<HOST_1>')).toBe(false);
  });
  it('chunks on line boundaries', () => {
    const c = chunkLines(Array.from({ length: 100 }, (_, i) => `line ${i}`).join('\n'), 100);
    expect(c.length).toBeGreaterThan(5);
    expect(c.every((x) => x.length <= 100)).toBe(true);
  });
  it('scores with per-severity caps', () => {
    const f = (severity: 'critical' | 'low') => ({ id: '', title: '', severity, category: '', evidence: '', why: '', fix: '' });
    expect(scoreFindings([])).toBe(100);
    expect(scoreFindings(Array(10).fill(f('critical')))).toBe(40);
    expect(scoreFindings([f('low')])).toBe(99);
  });
});
