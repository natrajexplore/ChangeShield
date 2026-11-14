import './style.css';
import { ensureSignedIn, firebaseStatus, loadSettings } from './firebase';
import { createRedactor, probeNano, type NanoAvailability } from './ai/models';
import { runPipeline, type PipelineResult, type RunMode, type StageEvent } from './pipeline';
import { TokenVault } from './redact/vault';
import { listAudits, saveAudit } from './storage';
import iosSample from '../samples/cisco-iosxe-branch.cfg?raw';
import panSample from '../samples/panos-edge-set.txt?raw';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const raw = $<HTMLTextAreaElement>('raw');
const stagesEl = $<HTMLOListElement>('stages');
const summaryEl = $<HTMLDivElement>('summary');
const findingsEl = $<HTMLDivElement>('findings');
const sanitizedEl = $<HTMLPreElement>('sanitized');
const reveal = $<HTMLInputElement>('reveal');
const saveBtn = $<HTMLButtonElement>('save');
const exportBtn = $<HTMLButtonElement>('export');
const runBtn = $<HTMLButtonElement>('run');
const prepBtn = $<HTMLButtonElement>('prep');
const dl = $<HTMLProgressElement>('dl');
const charCount = $<HTMLSpanElement>('char-count');

const vault = new TokenVault();
const fbStatus = firebaseStatus();
let last: PipelineResult | null = null;

const STAGE_NAMES = ['Deterministic rules', 'On-device contextual redaction', 'Leak gate', 'Deep audit', 'Local re-hydration'];
const SOURCE_LABEL: Record<string, string> = {
  on_device: 'ON-DEVICE · Gemini Nano',
  in_cloud: 'CLOUD · Gemini',
  local_rules: 'LOCAL · rules',
  skipped: 'SKIPPED',
};
const AUDIT_WHERE: Record<string, string> = {
  in_cloud: 'in the cloud',
  on_device: 'on-device',
  local_rules: 'locally by the baseline rule engine',
  skipped: 'nowhere',
};

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
/** Escape, then highlight placeholders so users see exactly what was masked. */
function showText(s: string): string {
  const text = reveal.checked ? vault.rehydrate(s) : s;
  return esc(text).replace(/&lt;([A-Z_]+)_(\d+)&gt;/g, '<mark class="tok" title="masked $1">&lt;$1_$2&gt;</mark>');
}

function renderStage(e: StageEvent) {
  let li = stagesEl.querySelector<HTMLLIElement>(`li[data-stage="${e.stage}"]`);
  if (!li) {
    li = document.createElement('li');
    li.dataset.stage = String(e.stage);
    stagesEl.appendChild(li);
  }
  li.className = `stage ${e.status}`;
  li.innerHTML = `<div><strong>${STAGE_NAMES[e.stage]}</strong><span class="src src-${e.source}">${SOURCE_LABEL[e.source]}</span></div><p>${esc(e.message)}</p>`;
}

function resetReport(message = 'Run an audit to see findings.') {
  last = null;
  summaryEl.className = 'summary empty';
  summaryEl.textContent = message;
  findingsEl.innerHTML = '';
  sanitizedEl.textContent = '';
  saveBtn.disabled = exportBtn.disabled = true;
}

function render() {
  if (!last) return;
  const r = last;
  const sevCount = (s: string) => r.audit.findings.filter((f) => f.severity === s).length;
  const scoreClass = r.score >= 80 ? 'good' : r.score >= 50 ? 'mid' : 'bad';
  summaryEl.className = 'summary';
  summaryEl.innerHTML = `
    <div class="score s${scoreClass}" role="img" aria-label="Security score ${r.score} out of 100"><span>${r.score}</span><small>/100</small></div>
    <div class="meta">
      <p><strong>${esc(r.vendor)}</strong> · ${r.audit.findings.length} findings ·
        <span class="sev critical">${sevCount('critical')} critical</span>
        <span class="sev high">${sevCount('high')} high</span>
        <span class="sev medium">${sevCount('medium')} medium</span>
        <span class="sev low">${sevCount('low')} low</span></p>
      <p class="muted">${r.stats.deterministicTokens} values masked by rules · ${r.stats.onDeviceTokens} by Gemini Nano on-device${
        r.stats.freeTextTokens ? ` · ${r.stats.freeTextTokens} free-text fields masked wholesale` : ''
      } · audit ran <strong>${AUDIT_WHERE[r.stats.auditSource]}</strong>${
        r.stats.rulesAdded ? ` + ${r.stats.rulesAdded} from the baseline rule engine` : ''
      } · ${(r.stats.elapsedMs / 1000).toFixed(1)}s</p>
      <p>${showText(r.audit.summary)}</p>
    </div>`;
  findingsEl.innerHTML = r.audit.findings.length
    ? r.audit.findings
        .map(
          (f, i) => `
    <article class="finding ${f.severity}">
      <header><span class="sev ${f.severity}">${f.severity}</span><h3>${esc(f.id)} · ${showText(f.title)}</h3>${f.origin === 'rules' ? '<span class="origin" title="The AI missed this; the local baseline rule engine found it">rule engine</span>' : ''}<span class="cat">${esc(f.category)}</span></header>
      <p class="why">${showText(f.why)}</p>
      <div class="cols">
        <div><h4>Evidence</h4><pre>${showText(f.evidence)}</pre></div>
        <div><h4>Fix <button class="copy" type="button" data-fix="${i}" aria-label="Copy fix for ${esc(f.id)}">Copy</button></h4><pre>${showText(f.fix)}</pre></div>
      </div>
      ${f.reference ? `<p class="ref">${esc(f.reference)}</p>` : ''}
    </article>`,
        )
        .join('')
    : '<p class="muted">No findings — nothing matched the audit checks.</p>';
  sanitizedEl.innerHTML = showText(r.sanitized);
}

function toMarkdown(r: PipelineResult, rehydrate: boolean): string {
  const t = (s: string) => (rehydrate ? vault.rehydrate(s) : s);
  const lines = [
    `# ConfigShield audit — ${r.vendor}`,
    '',
    `Score: **${r.score}/100** · Findings: ${r.audit.findings.length} · Audit: ${r.stats.auditSource} · Redaction: rules + ${r.stats.redactionSource}`,
    `Generated: ${new Date().toISOString()}`,
    '',
    rehydrate ? '> ⚠️ Contains REAL values — handle as confidential.' : '> Sanitized report — placeholders only.',
    '',
    t(r.audit.summary),
    '',
  ];
  for (const f of r.audit.findings) {
    lines.push(`## ${f.id} [${f.severity.toUpperCase()}] ${t(f.title)}${f.origin === 'rules' ? ' _(baseline rule engine)_' : ''}`, '', `*${f.category}* — ${t(f.why)}`, '', '**Evidence**', '```', t(f.evidence), '```', '**Fix**', '```', t(f.fix), '```');
    if (f.reference) lines.push('', `Reference: ${f.reference}`);
    lines.push('');
  }
  return lines.join('\n');
}

async function refreshHistory() {
  const el = $('history');
  if (!fbStatus.ok) {
    el.innerHTML = '<li class="muted">Saved history needs Firebase — not configured (local demo mode).</li>';
    return;
  }
  try {
    const items = await listAudits();
    el.innerHTML = items.length
      ? items
          .map(
            (a) =>
              `<li><strong>${Number(a.score) || 0}/100</strong> ${esc(String(a.vendor ?? ''))} · ${Number(a.findingCount) || 0} findings · ${esc(String(a.auditSource ?? ''))} · ${esc(a.createdAt?.toDate().toLocaleString() ?? 'just now')}</li>`,
          )
          .join('')
      : '<li class="muted">No saved reports yet.</li>';
  } catch (e) {
    el.innerHTML = `<li class="muted">History unavailable: ${esc((e as Error).message)}</li>`;
  }
}

let nanoState: NanoAvailability = 'unsupported';
async function updateNanoChip() {
  nanoState = await probeNano();
  const chip = $('nano-chip');
  chip.textContent = `Gemini Nano: ${nanoState}`;
  chip.className = `chip ${nanoState === 'available' ? 'ok' : nanoState === 'unsupported' || nanoState === 'unavailable' ? 'bad' : 'warn'}`;
  chip.title =
    nanoState === 'unsupported'
      ? 'Prompt API not found. Use Chrome 139+ and enable chrome://flags/#prompt-api-for-gemini-nano-multimodal-input'
      : '';
}

let preparing: Promise<void> | null = null;
/** Must be started from a user gesture (click) — Chrome requirement. Concurrent calls share one download. */
function prepareDevice(): Promise<void> {
  preparing ??= (async () => {
    prepBtn.disabled = true;
    try {
      if (!fbStatus.ok) return; // AI Logic SDK needs Firebase; rules-only pipeline still works
      const a = await probeNano();
      if (a === 'unsupported' || a === 'unavailable') return;
      dl.hidden = false;
      await createRedactor().initializeDeviceModel((p) => (dl.value = p));
    } catch (e) {
      console.warn('initializeDeviceModel failed', e);
    } finally {
      dl.hidden = true;
      prepBtn.disabled = false;
      void updateNanoChip();
    }
  })().finally(() => (preparing = null));
  return preparing;
}

prepBtn.addEventListener('click', () => void prepareDevice());

async function run() {
  if (runBtn.disabled) return;
  if (!raw.value.trim()) {
    raw.focus();
    return;
  }
  runBtn.disabled = true;
  runBtn.textContent = 'Auditing…';
  stagesEl.innerHTML = '';
  resetReport('Working…');
  try {
    const mode = (document.querySelector<HTMLInputElement>('input[name=mode]:checked')?.value ?? 'hybrid') as RunMode;
    // Start the model download first, while we're still inside the click's user activation.
    const prep = mode !== 'cloud' ? prepareDevice() : Promise.resolve();
    const settings = await loadSettings();
    await prep;
    last = await runPipeline(raw.value, mode, settings, vault, renderStage);
    render();
    exportBtn.disabled = false;
    saveBtn.disabled = !fbStatus.ok;
  } catch (e) {
    resetReport();
    summaryEl.className = 'summary error';
    summaryEl.textContent = (e as Error).message;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = 'Redact & audit';
  }
}

runBtn.addEventListener('click', () => void run());
raw.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    void run();
  }
});
const updateCount = () => {
  const n = raw.value.length;
  charCount.textContent = n ? `${n.toLocaleString()} chars · ${raw.value.split('\n').length.toLocaleString()} lines` : '';
};
raw.addEventListener('input', updateCount);

reveal.addEventListener('change', render);

findingsEl.addEventListener('click', async (ev) => {
  const btn = (ev.target as HTMLElement).closest<HTMLButtonElement>('button.copy');
  if (!btn || !last) return;
  const f = last.audit.findings[Number(btn.dataset.fix)];
  if (!f) return;
  try {
    await navigator.clipboard.writeText(reveal.checked ? vault.rehydrate(f.fix) : f.fix);
    btn.textContent = 'Copied ✓';
  } catch {
    btn.textContent = 'Copy failed';
  }
  setTimeout(() => (btn.textContent = 'Copy'), 1500);
});

saveBtn.addEventListener('click', async () => {
  if (!last) return;
  saveBtn.disabled = true;
  try {
    await saveAudit(last);
    saveBtn.textContent = 'Saved ✓';
    void refreshHistory();
  } catch (e) {
    saveBtn.textContent = 'Save failed';
    console.error(e);
  } finally {
    setTimeout(() => {
      saveBtn.textContent = 'Save sanitized report';
      saveBtn.disabled = !last || !fbStatus.ok;
    }, 2000);
  }
});

exportBtn.addEventListener('click', () => {
  if (!last) return;
  const md = toMarkdown(last, reveal.checked);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }));
  a.download = `configshield-${reveal.checked ? 'CONFIDENTIAL' : 'sanitized'}-${Date.now()}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoking synchronously can cancel the download in some browsers.
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
});

function loadText(text: string) {
  raw.value = text;
  updateCount();
  resetReport();
  stagesEl.innerHTML = '';
}
$('load-ios').addEventListener('click', () => loadText(iosSample));
$('load-pan').addEventListener('click', () => loadText(panSample));
$<HTMLInputElement>('file').addEventListener('change', async (ev) => {
  const input = ev.target as HTMLInputElement;
  const f = input.files?.[0];
  input.value = ''; // allow re-selecting the same file
  if (!f) return;
  if (f.size > 2_000_000) {
    resetReport(`"${f.name}" is ${(f.size / 1e6).toFixed(1)} MB — configs over 2 MB are not supported.`);
    return;
  }
  loadText(await f.text());
});

// Boot
void updateNanoChip();
const authChip = $('auth-chip');
if (!fbStatus.ok) {
  authChip.textContent = 'Firebase: not configured · local demo mode';
  authChip.className = 'chip warn';
  authChip.title = `${fbStatus.reason ?? ''}. Rule-based redaction and the baseline auditor still run fully in your browser. See README to enable Gemini.`;
  saveBtn.title = 'Requires Firebase';
  void refreshHistory();
} else {
  ensureSignedIn()
    .then((u) => {
      authChip.textContent = `Auth: anonymous ${u.uid.slice(0, 6)}…`;
      authChip.className = 'chip ok';
      void refreshHistory();
    })
    .catch((e) => {
      authChip.textContent = 'Auth: offline';
      authChip.className = 'chip warn';
      console.warn(e);
    });
  void loadSettings(); // warm the Remote Config cache
}
