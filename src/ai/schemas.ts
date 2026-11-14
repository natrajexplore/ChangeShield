/** JSON Schemas shared by the on-device (Prompt API responseConstraint) and cloud (responseJsonSchema) paths. */

export const PII_KINDS = ['ORG', 'PERSON', 'LOCATION', 'SITE', 'HOST', 'USER', 'CIRCUIT', 'PHONE', 'SECRET', 'OTHER'] as const;
export type PiiKind = (typeof PII_KINDS)[number];

export const REDACTION_SCHEMA = {
  type: 'object',
  properties: {
    items: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          value: { type: 'string' },
          kind: { type: 'string', enum: [...PII_KINDS] },
        },
        required: ['value', 'kind'],
      },
    },
  },
  required: ['items'],
} as const;

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = ['management-plane', 'control-plane', 'data-plane', 'aaa', 'crypto', 'logging', 'segmentation', 'hygiene'] as const;

export const AUDIT_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          severity: { type: 'string', enum: [...SEVERITIES] },
          category: {
            type: 'string',
            enum: [...CATEGORIES],
          },
          evidence: { type: 'string' },
          why: { type: 'string' },
          fix: { type: 'string' },
          reference: { type: 'string' },
        },
        required: ['id', 'title', 'severity', 'category', 'evidence', 'why', 'fix'],
      },
    },
  },
  required: ['summary', 'findings'],
} as const;

export interface AuditFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  evidence: string;
  why: string;
  fix: string;
  reference?: string;
  /** Set to 'rules' when the baseline rule engine added this finding to an AI report. */
  origin?: 'rules';
}

export interface AuditResult {
  summary: string;
  findings: AuditFinding[];
}
