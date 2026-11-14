/**
 * Baseline rule auditor — deterministic, runs 100% locally, no AI.
 *
 * Used as the last-resort audit when neither cloud Gemini nor Gemini Nano is
 * available (air-gapped laptop without Nano, Firebase not configured, kill
 * switch on + no Nano, or the model returned nothing parseable). It works on
 * the SANITIZED text, so evidence lines contain placeholders exactly like the
 * AI audit does and re-hydrate the same way.
 */
import type { AuditFinding, AuditResult, Severity } from '../ai/schemas';

type Family = 'cisco' | 'panos' | 'junos' | 'fortios' | 'any';

interface Check {
  family: Family[];
  title: string;
  severity: Severity;
  category: AuditFinding['category'];
  why: string;
  fix: string;
  reference?: string;
  /** Line regex (any matching line is evidence) or a custom evidence function. */
  match: RegExp | ((lines: string[], text: string) => string[]);
}

export function vendorFamily(vendor: string): Family {
  if (/^Cisco/.test(vendor)) return 'cisco';
  if (/PAN-OS/.test(vendor)) return 'panos';
  if (/Junos/.test(vendor)) return 'junos';
  if (/FortiOS/.test(vendor)) return 'fortios';
  return 'any';
}

const linesMatching = (lines: string[], re: RegExp) => lines.filter((l) => re.test(l));

const CHECKS: Check[] = [
  // ---- Cross-vendor ----------------------------------------------------------
  {
    family: ['any'],
    title: 'Default, dictionary or short secret in use',
    severity: 'critical',
    category: 'aaa',
    match: /<WEAKSECRET_\d+>/,
    why: 'A local check found a vendor-default, dictionary or < 8 character password/community/key. These are the first values attackers try.',
    fix: 'Replace every <WEAKSECRET_n> value with a unique random secret of 16+ characters stored in a password manager / vault.',
    reference: 'CIS Benchmarks — password and SNMP community requirements',
  },
  {
    family: ['any'],
    title: 'Weak IKE/IPsec encryption (DES/3DES)',
    severity: 'high',
    category: 'crypto',
    match: /\b(?:encr|encryption)\s+(?:des|3des)\b/i,
    why: 'DES and 3DES are deprecated (Sweet32, brute force) and must not protect VPN traffic.',
    fix: 'Cisco: `crypto isakmp policy 10` → `encr aes 256`\nPAN-OS: `set network ike crypto-profiles ike-crypto-profiles <name> encryption aes-256-cbc`',
    reference: 'NIST SP 800-131A Rev.2',
  },
  {
    family: ['any'],
    title: 'Weak IKE hash / integrity algorithm (MD5/SHA-1)',
    severity: 'medium',
    category: 'crypto',
    match: /^\s*(?:set\s.*\b)?(?:hash|authentication-algorithm)\s+(?:md5|sha1)\b/i,
    why: 'MD5 and SHA-1 are collision-prone and no longer acceptable for IKE integrity.',
    fix: 'Cisco: `hash sha256` (or sha384)\nPAN-OS: `set network ike crypto-profiles ike-crypto-profiles <name> hash sha256`',
    reference: 'NIST SP 800-131A Rev.2',
  },
  {
    family: ['any'],
    title: 'Weak Diffie-Hellman group (1, 2 or 5)',
    severity: 'high',
    category: 'crypto',
    match: /^\s*group\s+[125]\s*$|\bdh-group\s+group[125]\b/i,
    why: 'DH groups 1/2/5 (768–1536-bit MODP) are within reach of well-resourced attackers (Logjam).',
    fix: 'Cisco: `group 19` (or 20/21)\nPAN-OS: `set network ike crypto-profiles ike-crypto-profiles <name> dh-group group19`',
    reference: 'RFC 8247 — IKEv2 algorithm requirements',
  },

  // ---- Cisco IOS / IOS-XE / NX-OS / ASA --------------------------------------
  {
    family: ['cisco'],
    title: 'Telnet allowed on VTY lines',
    severity: 'critical',
    category: 'management-plane',
    match: /^\s*transport\s+input\s+.*\b(?:telnet|all)\b/i,
    why: 'Telnet sends credentials and session data in cleartext over the network.',
    fix: 'line vty 0 15\n transport input ssh\nip ssh version 2',
    reference: 'Cisco IOS XE Hardening Guide — management plane',
  },
  {
    family: ['cisco'],
    title: 'HTTP management server enabled',
    severity: 'high',
    category: 'management-plane',
    match: /^\s*ip\s+http\s+server\s*$/i,
    why: 'The cleartext HTTP web UI exposes credentials and has a history of critical vulnerabilities (e.g. CVE-2023-20198).',
    fix: 'no ip http server\n! if the web UI is not needed at all:\nno ip http secure-server',
    reference: 'Cisco PSIRT cisco-sa-iosxe-webui-privesc-j22SaA4z',
  },
  {
    family: ['cisco'],
    title: 'AAA not enabled (no aaa new-model)',
    severity: 'high',
    category: 'aaa',
    match: /^\s*no\s+aaa\s+new-model\b/i,
    why: 'Without AAA there is no centralised authentication, per-command authorisation or accounting.',
    fix: 'aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\naaa accounting exec default start-stop group tacacs+',
    reference: 'Cisco IOS XE Hardening Guide — AAA',
  },
  {
    family: ['cisco'],
    title: '`enable password` used instead of `enable secret`',
    severity: 'high',
    category: 'aaa',
    match: /^\s*enable\s+password\b/i,
    why: '`enable password` is stored in cleartext or reversible type 7, which can be decoded instantly.',
    fix: 'no enable password\nenable algorithm-type scrypt secret <new-strong-secret>',
  },
  {
    family: ['cisco'],
    title: 'Cleartext or reversible (type 0/7) passwords',
    severity: 'high',
    category: 'aaa',
    match: /\b(?:password|key)\s+[07]\s+</i,
    why: 'Type 0 is cleartext and type 7 is a trivially reversible obfuscation — anyone with the config has the password.',
    fix: 'username <user> privilege 15 algorithm-type scrypt secret <new-secret>\n! for keys: key config-key password-encrypt + password encryption aes',
  },
  {
    family: ['cisco'],
    title: 'MD5-based (type 5) password hashes',
    severity: 'medium',
    category: 'aaa',
    match: /\bsecret\s+5\s+/i,
    why: 'Type 5 (salted MD5) hashes are cheap to brute-force with modern GPUs.',
    fix: 'username <user> algorithm-type scrypt secret <new-secret>   ! type 9',
  },
  {
    family: ['cisco'],
    title: 'Password encryption service disabled',
    severity: 'medium',
    category: 'hygiene',
    match: /^\s*no\s+service\s+password-encryption\b/i,
    why: 'Line and legacy passwords are stored in cleartext and leak via screenshots, backups and tickets.',
    fix: 'service password-encryption\n! better: key config-key password-encrypt + password encryption aes',
  },
  {
    family: ['cisco'],
    title: 'SNMP community with write (RW) access',
    severity: 'high',
    category: 'management-plane',
    match: /^\s*snmp-server\s+community\s+\S+\s+RW\b/i,
    why: 'An RW community lets anyone who learns it reconfigure the device or pull its config over UDP.',
    fix: 'no snmp-server community <community> RW\n! use SNMPv3 authPriv for any write use-case',
  },
  {
    family: ['cisco'],
    title: 'SNMPv1/v2c communities in use',
    severity: 'medium',
    category: 'management-plane',
    match: /^\s*snmp-server\s+(?:community\s|host\s+\S+\s+(?:informs\s+|traps\s+)?version\s+(?:1|2c)\b)/i,
    why: 'SNMPv1/v2c communities travel in cleartext and provide no per-user authentication.',
    fix: 'snmp-server group NMS v3 priv access SNMP-ACL\nsnmp-server user nms NMS v3 auth sha <auth> priv aes 256 <priv>\nno snmp-server community <community>',
  },
  {
    family: ['cisco'],
    title: 'Idle session timeout disabled (exec-timeout 0 0)',
    severity: 'medium',
    category: 'management-plane',
    match: /^\s*exec-timeout\s+0(?:\s+0)?\s*$/i,
    why: 'Abandoned privileged sessions stay open forever and can be hijacked.',
    fix: 'line vty 0 15\n exec-timeout 10 0\nline con 0\n exec-timeout 10 0',
  },
  {
    family: ['cisco'],
    title: 'VTY lines not restricted by an access-class',
    severity: 'high',
    category: 'management-plane',
    match: (lines, text) => (/^\s*access-class\s/im.test(text) ? [] : linesMatching(lines, /^\s*line\s+vty\b/i)),
    why: 'Any host that can reach the device can attempt to log in to the management plane.',
    fix: 'ip access-list standard MGMT-ONLY\n permit <mgmt-subnet> <wildcard>\nline vty 0 15\n access-class MGMT-ONLY in',
  },
  {
    family: ['cisco'],
    title: 'SSH version 2 not enforced',
    severity: 'medium',
    category: 'management-plane',
    match: (lines, text) =>
      /^\s*ip\s+ssh\s+version\s+2/im.test(text) ? [] : linesMatching(lines, /^\s*transport\s+input\s+.*\bssh\b/i),
    why: 'Without `ip ssh version 2` the device may negotiate the broken SSHv1 protocol.',
    fix: 'ip ssh version 2',
  },
  {
    family: ['cisco'],
    title: 'Log timestamps not configured',
    severity: 'low',
    category: 'logging',
    match: (lines, text) => (/^\s*service\s+timestamps\s+log\b/im.test(text) ? [] : linesMatching(lines, /^\s*(?:logging\s|service\s+timestamps)/i).slice(0, 2)),
    why: 'Syslog messages without timestamps cannot be correlated during incident response.',
    fix: 'service timestamps log datetime msec localtime show-timezone',
  },
  {
    family: ['cisco'],
    title: 'NTP without authentication',
    severity: 'low',
    category: 'control-plane',
    match: (lines, text) => (/^\s*ntp\s+authenticate\b/im.test(text) ? [] : linesMatching(lines, /^\s*ntp\s+server\b/i)),
    why: 'Unauthenticated NTP can be spoofed, breaking log correlation and certificate validation.',
    fix: 'ntp authentication-key 1 hmac-sha2-256 <key>\nntp authenticate\nntp trusted-key 1\nntp server <server> key 1',
  },

  // ---- Palo Alto PAN-OS ------------------------------------------------------
  {
    family: ['panos'],
    title: 'Telnet enabled on the management interface',
    severity: 'critical',
    category: 'management-plane',
    match: /\bdisable-telnet\s+no\b/i,
    why: 'Telnet exposes administrator credentials in cleartext.',
    fix: 'set deviceconfig system service disable-telnet yes',
    reference: 'Palo Alto Networks — Best Practices for Securing Administrative Access',
  },
  {
    family: ['panos'],
    title: 'HTTP enabled on the management interface',
    severity: 'high',
    category: 'management-plane',
    match: /\bdisable-http\s+no\b/i,
    why: 'Cleartext HTTP management exposes session cookies and credentials.',
    fix: 'set deviceconfig system service disable-http yes',
    reference: 'Palo Alto Networks — Best Practices for Securing Administrative Access',
  },
  {
    family: ['panos'],
    title: 'Any-to-any allow security rule',
    severity: 'critical',
    category: 'segmentation',
    match: /\brules\s+\S+\s+from\s+any\s+to\s+any\b.*\bsource\s+any\b.*\bdestination\s+any\b.*\bapplication\s+any\b.*\baction\s+allow\b/i,
    why: 'An allow-all rule defeats zone segmentation and App-ID — every application can flow between every zone.',
    fix: 'delete rulebase security rules <rule>\n! replace with least-privilege rules: explicit zones, addresses, App-ID and service application-default',
  },
  {
    family: ['panos'],
    title: 'Remote-access protocol allowed from untrust',
    severity: 'high',
    category: 'segmentation',
    match: /\bfrom\s+untrust\b.*\bapplication\s+(?:ms-rdp|ssh|telnet|vnc|ms-ds-smb|smb|msrpc)\b.*\baction\s+allow\b/i,
    why: 'Exposing RDP/SSH/SMB directly to the Internet is a top ransomware initial-access vector.',
    fix: 'set rulebase security rules <rule> action deny\n! publish via GlobalProtect / a bastion with MFA instead',
  },
  {
    family: ['panos'],
    title: 'Session-end logging disabled on a security rule',
    severity: 'medium',
    category: 'logging',
    match: /\blog-end\s+no\b/i,
    why: 'Without traffic logs there is no forensic trail for the sessions this rule allows.',
    fix: 'set rulebase security rules <rule> log-end yes\nset rulebase security rules <rule> log-setting <forwarding-profile>',
  },
  {
    family: ['panos'],
    title: 'SNMPv2c enabled',
    severity: 'medium',
    category: 'management-plane',
    match: /\bsnmp-setting\b.*\bversion\s+v2c\b/i,
    why: 'SNMPv2c communities are sent in cleartext.',
    fix: 'set deviceconfig system snmp-setting access-setting version v3 views ... users ... authpwd <auth> privpwd <priv>',
  },

  // ---- Juniper Junos ---------------------------------------------------------
  {
    family: ['junos'],
    title: 'Telnet service enabled',
    severity: 'critical',
    category: 'management-plane',
    match: /^\s*set\s+system\s+services\s+telnet\b/i,
    why: 'Telnet exposes credentials in cleartext.',
    fix: 'delete system services telnet\nset system services ssh protocol-version v2',
  },
  {
    family: ['junos'],
    title: 'HTTP web management enabled',
    severity: 'high',
    category: 'management-plane',
    match: /^\s*set\s+system\s+services\s+web-management\s+http\b/i,
    why: 'Cleartext HTTP management exposes credentials and sessions.',
    fix: 'delete system services web-management http',
  },

  // ---- Fortinet FortiOS ------------------------------------------------------
  {
    family: ['fortios'],
    title: 'Telnet / HTTP administrative access on an interface',
    severity: 'high',
    category: 'management-plane',
    match: /^\s*set\s+allowaccess\b.*\b(?:telnet|http)\b/i,
    why: 'Cleartext management protocols expose administrator credentials.',
    fix: 'config system interface\n edit <port>\n  set allowaccess ping https ssh\n next\nend',
  },
];

export const BASELINE_CHECK_COUNT = CHECKS.length;

/** Run the deterministic checks against SANITIZED config text. */
export function baselineAudit(sanitized: string, vendor: string): AuditResult {
  const fam = vendorFamily(vendor);
  const lines = sanitized.split('\n');
  const findings: AuditFinding[] = [];
  let ran = 0;
  for (const c of CHECKS) {
    if (!c.family.includes('any') && fam !== 'any' && !c.family.includes(fam)) continue;
    ran++;
    const ev = typeof c.match === 'function' ? c.match(lines, sanitized) : linesMatching(lines, c.match);
    if (!ev.length) continue;
    const shown = ev.slice(0, 4).map((l) => l.trim());
    if (ev.length > 4) shown.push(`… and ${ev.length - 4} more line(s)`);
    findings.push({
      id: '',
      title: c.title,
      severity: c.severity,
      category: c.category,
      evidence: shown.join('\n'),
      why: c.why,
      fix: c.fix,
      ...(c.reference ? { reference: c.reference } : {}),
    });
  }
  const crit = findings.filter((f) => f.severity === 'critical').length;
  return {
    summary:
      `Baseline rule engine (no AI) ran ${ran} deterministic checks locally and found ${findings.length} issue(s)` +
      (crit ? `, ${crit} critical.` : '.') +
      ' AI-assisted audit was unavailable, so contextual issues may be missed.',
    findings,
  };
}
