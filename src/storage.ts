/**
 * Firestore persistence — stores ONLY the sanitized report (placeholders kept).
 * The TokenVault (real values) is never written anywhere.
 */
import { addDoc, collection, getDocs, limit, orderBy, query, serverTimestamp } from 'firebase/firestore';
import { ensureSignedIn, getFirebase } from './firebase';
import type { PipelineResult } from './pipeline';

export interface SavedAudit {
  id: string;
  vendor: string;
  score: number;
  findingCount: number;
  auditSource: string;
  createdAt?: { toDate(): Date } | null;
}

function db() {
  const fb = getFirebase();
  if (!fb) throw new Error('Firebase is not configured — saving is disabled in local demo mode');
  return fb.db;
}

export async function saveAudit(r: PipelineResult): Promise<string> {
  const store = db();
  const user = await ensureSignedIn();
  // Bounds mirror firestore.rules so a long model summary can't make the write fail.
  const ref = await addDoc(collection(store, 'users', user.uid, 'audits'), {
    vendor: r.vendor.slice(0, 100),
    score: Math.round(r.score),
    summary: r.audit.summary.slice(0, 3900),
    findings: r.audit.findings.slice(0, 50), // sanitized — contains placeholders only
    findingCount: r.audit.findings.length,
    auditSource: r.stats.auditSource,
    redactionSource: r.stats.redactionSource,
    tokensMasked: r.stats.deterministicTokens + r.stats.onDeviceTokens + r.stats.freeTextTokens,
    createdAt: serverTimestamp(),
    schema: 1,
  });
  return ref.id;
}

export async function listAudits(n = 10): Promise<SavedAudit[]> {
  const store = db();
  const user = await ensureSignedIn();
  const q = query(collection(store, 'users', user.uid, 'audits'), orderBy('createdAt', 'desc'), limit(n));
  const snap = await getDocs(q);
  return snap.docs.map((d) => ({ id: d.id, ...(d.data() as Omit<SavedAudit, 'id'>) }));
}
