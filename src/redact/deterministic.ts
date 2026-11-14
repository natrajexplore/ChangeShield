/**
 * Stage 0 — deterministic, rule-based redaction (runs locally, no AI).
 *
 * This is the safety net that guarantees well-known secret formats never leave
 * the device, even if the on-device model is unavailable or misses something.
 * Covers common Cisco IOS/IOS-XE/NX-OS/ASA, Palo Alto PAN-OS (set format),
 * Juniper Junos (set format) and FortiOS patterns.
 */
import { TokenVault, type TokenKind } from './vault';

const MASK_OCTETS = new Set([0, 128, 192, 224, 240, 248, 252, 254, 255]);

/** Netmasks / wildcard masks are not sensitive and are needed for the audit. */
export function isMaskLike(ip: string): boolean {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((x) => Number.isNaN(x) || x > 255)) return false;
  if (ip === '0.0.0.0' || ip === '255.255.255.255') return true;
  if (!o.every((x) => MASK_OCTETS.has(x))) return false;
  return o[0] === 255 || o[3] === 255; // netmask or wildcard
}

export function isPrivateIPv4(ip: string): boolean {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) // CGNAT
  );
}

/** Words that follow a "key"/"password" keyword but are syntax, not secrets. */
const NOT_A_SECRET = new Set([
  'chain', 'generate', 'config-key', 'exchange', 'zeroize', 'pubkey-chain', 'encryption',
  'export', 'import', 'string', 'min-length', 'lifetime', 'aes', 'hidden', 'level',
  'expire', 'policy', 'recovery', 'encrypted', 'type', 'sha', 'md5', 'none', 'ascii', 'ascii-text',
]);

interface SecretRule {
  name: string;
  /** Group 1 = prefix kept verbatim, group 2 = secret value replaced. */
  re: RegExp;
  kind: TokenKind;
}

/** Values that are vendor defaults / dictionary words — flagged so the auditor can call them out. */
const WEAK_SECRETS = new Set([
  'public', 'private', 'cisco', 'cisco123', 'admin', 'admin123', 'password', 'password1', 'changeme', 'secret',
  'test', 'test123', 'default', 'letmein', 'welcome', 'welcome1', 'paloalto', 'juniper', 'fortinet', 'manager',
  'community', 'snmp', 'qwerty', '123456', '12345678', 'p@ssw0rd', 'passw0rd',
]);

/** Weak = known default/dictionary value, or a short cleartext value (type-7 / hashes are judged by type). */
export function isWeakSecret(value: string): boolean {
  const v = value.replace(/^"|"$/g, '');
  if (WEAK_SECRETS.has(v.toLowerCase())) return true;
  if (/^[0-9A-F]{8,}$/i.test(v) || v.startsWith('$') || v.startsWith('ENC')) return false;
  return v.length < 8;
}

const SECRET_RULES: SecretRule[] = [
  // enable secret 9 $9$..., enable password 7 0822455D0A16
  { name: 'enable', re: /^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d)?\s+)(\S+)/gim, kind: 'SECRET' },
  // username admin privilege 15 secret 9 $9$...
  { name: 'username-secret', re: /^(\s*username\s+\S+.*?\b(?:secret|password)(?:\s+\d)?\s+)(\S+)/gim, kind: 'SECRET' },
  // snmp-server community public RO
  { name: 'snmp-community', re: /^(\s*snmp-server\s+community\s+)(\S+)/gim, kind: 'SECRET' },
  // snmp-server host 10.1.1.1 version 2c MYCOMMUNITY
  { name: 'snmp-host', re: /^(\s*snmp-server\s+host\s+\S+(?:\s+(?:informs|traps))?\s+version\s+(?:1|2c)\s+)(\S+)/gim, kind: 'SECRET' },
  // snmpv3 auth/priv passphrases
  { name: 'snmpv3-auth', re: /(\bauth\s+(?:md5|sha\S*)\s+)(\S+)/gi, kind: 'SECRET' },
  { name: 'snmpv3-priv', re: /(\bpriv\s+(?:des|3des|aes(?:\s+\d+)?)\s+)(\S+)/gi, kind: 'SECRET' },
  // tacacs/radius keys (old + new syntax)
  { name: 'aaa-key', re: /^(\s*(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key(?:\s+\d)?\s+)(\S+)/gim, kind: 'SECRET' },
  { name: 'aaa-key-new', re: /^(\s*key(?:\s+\d)?\s+)(\S+)\s*$/gim, kind: 'SECRET' },
  // key-string 7 xxx (key chains)
  { name: 'key-string', re: /(\bkey-string(?:\s+\d)?\s+)(\S+)/gi, kind: 'SECRET' },
  // crypto isakmp key XYZ address 1.2.3.4 / pre-shared-key
  { name: 'isakmp-key', re: /(\bcrypto\s+isakmp\s+key(?:\s+\d)?\s+)(\S+)/gi, kind: 'SECRET' },
  { name: 'psk', re: /(\bpre-shared-key\s+(?:(?:local|remote|address\s+\S+)\s+)?(?:key\s+)?(?:\d\s+)?)(\S+)/gi, kind: 'SECRET' },
  // OSPF / NTP / BGP / HSRP authentication
  { name: 'md5-key', re: /(\bmessage-digest-key\s+\d+\s+md5(?:\s+\d)?\s+)(\S+)/gi, kind: 'SECRET' },
  { name: 'auth-key', re: /(\bauthentication-key(?:\s+\d+\s+md5)?(?:\s+\d)?\s+)(\S+)/gi, kind: 'SECRET' },
  { name: 'bgp-password', re: /(\bneighbor\s+\S+\s+password(?:\s+\d)?\s+)(\S+)/gi, kind: 'SECRET' },
  { name: 'hsrp-auth', re: /(\bstandby\s+(?:\d+\s+)?authentication\s+(?:md5\s+key-string\s+(?:\d\s+)?|text\s+)?)(\S+)/gi, kind: 'SECRET' },
  // WLAN / wireless PSK (Cisco WLC / 9800, FortiOS)
  { name: 'wlan-psk', re: /(\b(?:security\s+wpa\s+akm\s+psk\s+set-key\s+ascii\s+\d\s+|wpa-psk\s+ascii\s+\d\s+|passphrase\s+))(\S+)/gi, kind: 'SECRET' },
  // PAN-OS / Junos / FortiOS set-format
  { name: 'phash', re: /(\bphash\s+)(\S+)/gi, kind: 'HASH' },
  { name: 'junos-secret', re: /(\b(?:encrypted-password|secret|authentication-key|pre-shared-key\s+ascii-text)\s+)("[^"]*"|\S+)/gi, kind: 'SECRET' },
  { name: 'fortios-set', re: /(\bset\s+(?:password|passwd|psksecret|secret|key|auth-pwd|priv-pwd)\s+)(ENC\s+\S+|\S+)/gi, kind: 'SECRET' },
  { name: 'snmp-location', re: /^(\s*snmp-server\s+location\s+)(.+?)\s*$/gim, kind: 'LOCATION' },
  { name: 'snmp-contact', re: /^(\s*snmp-server\s+contact\s+)(.+?)\s*$/gim, kind: 'PERSON' },
  { name: 'panos-snmp', re: /(\bsnmp-community-string\s+)(\S+)/gi, kind: 'SECRET' },
  { name: 'login-banner', re: /(\blogin-banner\s+)("[^"]*"|\S+)/gi, kind: 'BANNER' },
  // generic "password <value>" at end of line (line password, ppp, etc.)
  { name: 'generic-password', re: /^(\s*(?:password|ppp\s+chap\s+password|ppp\s+pap\s+sent-username\s+\S+\s+password)(?:\s+\d)?\s+)(\S+)\s*$/gim, kind: 'SECRET' },
];

const PEM_BLOCK = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
/** Cisco "certificate ... <hex lines> quit" blocks. */
const CISCO_CERT_BLOCK = /(^\s*certificate\s+(?:self-signed\s+|ca\s+)?\S+\s*\n)((?:\s+[0-9A-F]{8}(?:\s+[0-9A-F]{1,8})*\s*\n)+)(\s*quit)/gim;
const UNIX_HASH = /\$(?:1|5|6|8|9|14|sha512|2[aby]?)\$[^\s"']+/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
// Full (uncompressed) and common compressed IPv6. Requires >=4 groups to avoid timestamps.
const IPV6 = /\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{0,4}/g;
const BANNER = /(^\s*banner\s+(?:motd|login|exec|incoming)\s+)(\^C|\S)([\s\S]*?)\2/gim;
const PHONE = /(?<![\w.])\+\d[\d\s-]{8,}\d\b/g;

export interface DeterministicResult {
  sanitized: string;
  rulesHit: Record<string, number>;
}

export function deterministicRedact(raw: string, vault: TokenVault): DeterministicResult {
  let text = raw.replace(/\r\n/g, '\n');
  const rulesHit: Record<string, number> = {};
  const hit = (name: string) => (rulesHit[name] = (rulesHit[name] ?? 0) + 1);

  // 1. Whole key / certificate blocks
  text = text.replace(PEM_BLOCK, (m) => (hit('pem'), vault.tokenFor(m, 'KEYBLOCK')));
  text = text.replace(CISCO_CERT_BLOCK, (_m, head: string, body: string, tail: string) => {
    hit('cisco-cert');
    return `${head}  ${vault.tokenFor(body.trim(), 'KEYBLOCK')}\n${tail}`;
  });

  // 2. Banner text (often contains company names / legal text) — keep that a banner exists
  text = text.replace(BANNER, (_m, head: string, delim: string, body: string) => {
    hit('banner');
    return `${head}${delim}${vault.tokenFor(body, 'BANNER')}${delim}`;
  });

  // 3. Keyword-anchored secrets
  for (const rule of SECRET_RULES) {
    text = text.replace(rule.re, (m, prefix: string, value: string) => {
      if (value.startsWith('<') && value.endsWith('>')) return m; // already a token
      if (NOT_A_SECRET.has(value.toLowerCase())) return m;
      if (/^\d{1,3}$/.test(value)) return m; // encryption type / key id, not a secret
      hit(rule.name);
      const kind: TokenKind = rule.kind === 'SECRET' && isWeakSecret(value) ? 'WEAKSECRET' : rule.kind;
      return prefix + vault.tokenFor(value, kind);
    });
  }

  // 4. Stray crypt-style hashes anywhere
  text = text.replace(UNIX_HASH, (m) => (hit('hash'), vault.tokenFor(m, 'HASH')));

  // 5. Identity: hostname, domain, local usernames — then replace every other occurrence
  const identities: Array<[RegExp, TokenKind]> = [
    [/^\s*(?:hostname|switchname|set\s+(?:deviceconfig\s+system\s+)?hostname|set\s+system\s+host-name)\s+("?)([^\s"]+)\1/gim, 'HOST'],
    [/^\s*(?:ip\s+domain[-\s]name|domain-name|set\s+deviceconfig\s+system\s+domain|set\s+system\s+domain-name)\s+(?:vrf\s+\S+\s+)?("?)([^\s"]+)\1/gim, 'DOMAIN'],
    [/^\s*username\s+("?)([^\s"]+)\1/gim, 'USER'],
    [/^\s*set\s+mgt-config\s+users\s+("?)([^\s"]+)\1/gim, 'USER'],
    [/^\s*set\s+system\s+login\s+user\s+("?)([^\s"]+)\1/gim, 'USER'],
  ];
  const found: Array<[string, TokenKind]> = [];
  for (const [re, kind] of identities) {
    for (const m of text.matchAll(re)) {
      const v = m[2];
      if (v && !v.startsWith('<') && v.length >= 2) found.push([v, kind]);
    }
  }
  // Longest first so "core-sw01.corp.example" is replaced before "corp.example"
  found.sort((a, b) => b[0].length - a[0].length);
  for (const [value, kind] of found) {
    const token = vault.tokenFor(value, kind);
    text = replaceIdentifier(text, value, token);
    hit(kind.toLowerCase());
  }

  // 6. E-mail addresses and phone numbers
  text = text.replace(EMAIL, (m) => (hit('email'), vault.tokenFor(m, 'EMAIL')));
  text = text.replace(PHONE, (m) => (hit('phone'), vault.tokenFor(m, 'PHONE')));

  // 7. IP addresses (keep masks / wildcards / 0.0.0.0 so the audit still makes sense)
  text = text.replace(IPV4, (ip) => {
    if (isMaskLike(ip)) return ip;
    hit('ipv4');
    return vault.tokenFor(ip, isPrivateIPv4(ip) ? 'IP_PRIV' : 'IP_PUB');
  });
  text = text.replace(IPV6, (ip) => {
    if (!/[0-9a-f]/i.test(ip) || ip === '::') return ip;
    if (/^\d{1,2}:\d{2}:\d{2}$/.test(ip)) return ip; // time of day
    hit('ipv6');
    return vault.tokenFor(ip, 'IPV6');
  });

  return { sanitized: text, rulesHit };
}

/**
 * Free-text fields (descriptions, comments, ACL remarks, aliases) are where
 * people, customers, sites and circuit IDs live. Normally Gemini Nano masks the
 * sensitive parts on-device; when Nano is NOT available (or the user chose
 * rules-only Cloud mode) we mask these fields wholesale so no free text can
 * reach the cloud. Lines whose value is already only placeholders are kept.
 */
const FREE_TEXT_RULES: Array<{ name: string; re: RegExp }> = [
  // set-format / quoted: PAN-OS `comment "..."`, Junos `description "..."`, FortiOS `set comments "..."`
  { name: 'quoted-text', re: /(\b(?:description|comments?|alias|remark)\s+)("[^"\n]*")/gi },
  // IOS / NX-OS / ASA line-level: ` description ...`, ` remark ...`, `access-list X remark ...`
  { name: 'line-text', re: /^(\s*(?:description|remark|alias|(?:ipv6\s+)?access-list\s+\S+\s+(?:extended\s+)?remark)\s+)([^"\n].*?)\s*$/gim },
  // FortiOS unquoted single word: `set comments FOO`
  { name: 'set-text', re: /^(\s*set\s+(?:description|comments?|alias)\s+)([^"\s]\S*)\s*$/gim },
];

export function redactFreeText(text: string, vault: TokenVault): { sanitized: string; count: number } {
  let count = 0;
  let out = text;
  for (const rule of FREE_TEXT_RULES) {
    out = out.replace(rule.re, (m, prefix: string, value: string) => {
      const meaningful = value.replace(/<[A-Z_]+_\d+>/g, '').replace(/["\s\-–:,.;/()]+/g, '');
      if (!meaningful) return m;
      count++;
      return prefix + vault.tokenFor(value, 'FREETEXT');
    });
  }
  return { sanitized: out, count };
}

/** Replace an identifier only where it is not part of a larger word/token. */
export function replaceIdentifier(text: string, value: string, token: string): string {
  const esc = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return text.replace(new RegExp(`(?<![\\w.-])${esc}(?![\\w-])`, 'g'), token);
}

export interface LeakReport {
  ok: boolean;
  leaks: Array<{ kind: string; sample: string }>;
}

/**
 * Stage 2 — the leak gate. Runs on the sanitized text right before anything is
 * sent to the cloud. If it finds residual secrets it BLOCKS the cloud call.
 */
export function leakGate(sanitized: string, vault: TokenVault): LeakReport {
  const leaks: LeakReport['leaks'] = [];
  const push = (kind: string, sample: string) =>
    leaks.push({ kind, sample: sample.length > 6 ? `${sample.slice(0, 3)}…(${sample.length} chars)` : '***' });

  for (const m of sanitized.matchAll(PEM_BLOCK)) push('pem-block', m[0]);
  for (const m of sanitized.matchAll(UNIX_HASH)) push('hash', m[0]);
  for (const m of sanitized.matchAll(EMAIL)) push('email', m[0]);
  for (const m of sanitized.matchAll(IPV4)) if (!isMaskLike(m[0])) push('ipv4', m[0]);

  // Any original value we already tokenized must not re-appear anywhere.
  for (const e of vault.entries()) {
    if (e.original.length >= 4 && sanitized.includes(e.original)) push(`vault:${e.kind}`, e.original);
  }
  // Re-run the keyword rules: a secret position that still holds a non-token value is a leak.
  for (const rule of SECRET_RULES) {
    for (const m of sanitized.matchAll(rule.re)) {
      const v = m[2];
      if (v && !/^<[A-Z_]+_\d+>$/.test(v) && !/^\d{1,3}$/.test(v) && !NOT_A_SECRET.has(v.toLowerCase())) push(`rule:${rule.name}`, v);
    }
  }
  return { ok: leaks.length === 0, leaks };
}

/** Rough vendor detection — used only to steer the audit prompt. */
export function detectVendor(raw: string): string {
  if (/^\s*set\s+(deviceconfig|rulebase|network\s+interface|mgt-config)\b/m.test(raw)) return 'Palo Alto PAN-OS';
  if (/^\s*set\s+(system|interfaces|security|protocols)\s/m.test(raw)) return 'Juniper Junos';
  if (/^\s*config\s+(system|firewall)\s/m.test(raw)) return 'Fortinet FortiOS';
  if (/^\s*ASA Version|^\s*:\s*Saved|^\s*access-list\s+\S+\s+extended/m.test(raw)) return 'Cisco ASA';
  if (/^\s*feature\s+\S+|^\s*switchname\s/m.test(raw)) return 'Cisco NX-OS';
  if (/^\s*(wlan|wireless\s+profile|ap\s+profile)\s/m.test(raw)) return 'Cisco Catalyst 9800 WLC';
  if (/^\s*(hostname|interface|router|ip\s+route|line\s+vty)\b/m.test(raw)) return 'Cisco IOS / IOS-XE';
  return 'Unknown vendor';
}
