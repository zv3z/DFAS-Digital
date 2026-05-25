/**
 * DFAS Engine Runner
 * Maps module slug → real engine call → normalized AnalysisResult
 */
import {
  PhishingEngine, UrlEngine, EmailEngine,
  HashEngine, IOCEngine, TimelineEngine,
  NetLogEngine, ATTACKEngine,
} from './dfas-core';
import type { Finding, ThreatLevel, Severity } from './types';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyObj = any;

export interface AnalysisResult {
  pct: number;
  threat: ThreatLevel;
  verdictTitle: string;
  verdictDesc: string;
  findings: FindingItem[];
  meta: MetaItem[];
  stats: StatItem[];
  raw?: unknown;
}

export interface FindingItem {
  sev: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  desc: string;
  evidence: string;
}

export interface MetaItem {
  k: string;
  v: string;
}

export interface StatItem {
  label: string;
  value: string;
}

// ── Helpers ───────────────────────────────────────
function toFindings(arr: Finding[] | AnyObj[]): FindingItem[] {
  return (arr || []).map((f: AnyObj) => ({
    sev: f.sev as FindingItem['sev'],
    title: f.rule || f.label || '—',
    desc: f.det || '',
    evidence: f.ev || '',
  }));
}

function asThreatlevel(t: string): ThreatLevel {
  return t as ThreatLevel;
}

function threatToVerdict(threat: string, pct: number): { title: string; desc: string } {
  if (threat === 'crit') return { title: `تهديد حرج · ${pct}%`, desc: 'تم اكتشاف مؤشرات خطرة جداً. يُنصح بعزل المدخل وعدم التفاعل معه.' };
  if (threat === 'warn') return { title: `تهديد محتمل · ${pct}%`, desc: 'وُجدت مؤشرات مشبوهة تستدعي مزيداً من التحقيق.' };
  return { title: `نظيف · ${pct}%`, desc: 'لم يُكتشف ما يثير القلق في هذا المدخل.' };
}

const analysisId = () => 'ANL-' + new Date().toISOString().slice(0,10).replace(/-/g,'') + '-' + Math.random().toString(36).slice(2,6).toUpperCase();

// ── MOD-01 Phishing ───────────────────────────────
async function runPhishing(input: string): Promise<AnalysisResult> {
  const r = PhishingEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings: toFindings(r.findings),
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'المحرك', v:'PhishingEngine v3.5 · 47 مؤشر' },
      { k:'عدد الكلمات', v: String(r.meta.words) },
      { k:'روابط مُكتشفة', v: String(r.meta.urls.length) },
      { k:'علامات التعجب', v: String(r.meta.exclamations) },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'المؤشرات', value: String(r.findings.length) },
      { label:'النتيجة', value: String(r.score) },
      { label:'ثقة', value: r.pct + '%' },
    ],
    raw: r,
  };
}

// ── MOD-02 URL ────────────────────────────────────
async function runUrl(input: string): Promise<AnalysisResult> {
  const r = UrlEngine.analyze(input.trim());
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings: toFindings(r.findings),
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'المحرك', v:'UrlEngine v4.3 · 13 معيار' },
      { k:'البروتوكول', v: r.parsed.protocol },
      { k:'النطاق', v: r.parsed.hostname },
      { k:'المسار', v: r.parsed.path },
      { k:'Shannon Entropy', v: r.entropy.toFixed(3) + ' bits' },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'المعايير المُكتشفة', value: String(r.findings.length) },
      { label:'إنتروبيا النطاق', value: r.entropy.toFixed(2) },
      { label:'ثقة', value: r.pct + '%' },
    ],
    raw: r,
  };
}

// ── MOD-04 Email Headers ──────────────────────────
async function runEmail(input: string): Promise<AnalysisResult> {
  const r = EmailEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings: toFindings(r.findings),
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'من', v: r.headers.from },
      { k:'الرد على', v: r.headers.replyTo },
      { k:'SPF', v: r.auth.spf },
      { k:'DKIM', v: r.auth.dkim },
      { k:'DMARC', v: r.auth.dmarc },
      { k:'عدد نقاط التمرير', v: String(r.hops.length) },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'المؤشرات', value: String(r.findings.length) },
      { label:'نقاط التمرير', value: String(r.hops.length) },
      { label:'ثقة', value: r.pct + '%' },
    ],
    raw: r,
  };
}

// ── MOD-05 Hash / Fingerprint ─────────────────────
async function runHash(file: File | null, text: string): Promise<AnalysisResult> {
  let r: any;
  if (file) {
    r = await HashEngine.analyzeFile(file);
  } else {
    r = await HashEngine.analyzeText(text);
  }
  const threat: ThreatLevel = r.knownMalware ? 'crit' : 'safe';
  const pct = r.knownMalware ? 99 : 5;
  const v = threatToVerdict(threat, pct);
  return {
    pct, threat,
    verdictTitle: v.title,
    verdictDesc: r.knownMalware ? '⚠ البصمة مطابقة لقاعدة بيانات البرمجيات الخبيثة!' : v.desc,
    findings: r.knownMalware ? [{sev:'CRITICAL' as const, title:'بصمة خبيثة مُكتشفة', desc:'SHA-256 مطابق لبرمجية خبيثة في قاعدة البيانات', evidence:r.sha256}] : [],
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'SHA-256', v: (r.sha256||'').slice(0,40)+'…' },
      { k:'SHA-1', v: (r.sha1||'').slice(0,40)+'…' },
      { k:'MD5', v: r.md5 || '—' },
      { k:'الحجم', v: r.size ? `${(r.size/1024).toFixed(1)} KB` : `${r.bytes} bytes` },
      { k:'النوع', v: r.type || r.name || '—' },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'SHA-256', value: (r.sha256||'').slice(0,12)+'…' },
      { label:'الحجم', value: r.size ? (r.size/1024).toFixed(0)+'KB' : r.bytes+'B' },
      { label:'حالة', value: r.knownMalware ? 'خبيث ⚠' : 'نظيف ✓' },
    ],
    raw: r,
  };
}

// ── MOD-06 IOC Scanner ────────────────────────────
async function runIOC(input: string): Promise<AnalysisResult> {
  const r = IOCEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = r.results.map((res: any) => ({
    sev: res.sev,
    title: res.label,
    desc: `${res.count} مؤشر مُكتشف — الفئة: ${res.cat}`,
    evidence: res.samples.map((s: any) => `${s.value}${s.extra ? ' — '+s.extra : ''}`).join('\n'),
  }));
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings,
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'المحرك', v:'IOCEngine v2.0' },
      { k:'إجمالي المؤشرات', v: String(r.stats.total) },
      { k:'CRITICAL', v: String(r.stats.bySeverity.CRITICAL||0) },
      { k:'HIGH', v: String(r.stats.bySeverity.HIGH||0) },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'إجمالي IOCs', value: String(r.stats.total) },
      { label:'أنواع مُكتشفة', value: String(r.results.length) },
      { label:'ثقة', value: r.pct + '%' },
    ],
    raw: r,
  };
}

// ── MOD-08 Timeline ───────────────────────────────
async function runTimeline(input: string): Promise<AnalysisResult> {
  const r = TimelineEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = r.anomalies.map((a: any) => ({
    sev: (a.type === 'future' ? 'CRITICAL' : a.type === 'gap' ? 'HIGH' : 'MEDIUM') as FindingItem['sev'],
    title: a.type === 'future' ? 'طابع زمني مستقبلي' : a.type === 'gap' ? `فجوة زمنية: ${a.gapH} ساعة` : `نشاط في ساعات غير معتادة (${a.hour}:00)`,
    desc: a.type === 'gap' ? 'انقطاع كبير في الخط الزمني قد يُشير إلى حذف سجلات' : a.type === 'future' ? 'طابع زمني يتجاوز الوقت الحالي — مؤشر تلاعب' : 'نشاط بين منتصف الليل والفجر',
    evidence: a.event ? a.event.raw : '',
  }));
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings,
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'المحرك', v:'TimelineEngine v1.0' },
      { k:'الأحداث المُكتشفة', v: String(r.total) },
      { k:'الشذوذات', v: String(r.anomalies.length) },
      { k:'الامتداد الزمني', v: r.span + ' ساعة' },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'الأحداث', value: String(r.total) },
      { label:'الشذوذات', value: String(r.anomalies.length) },
      { label:'المدة', value: r.span + 'h' },
    ],
    raw: r,
  };
}

// ── MOD-09 Network Logs ───────────────────────────
async function runNetLog(input: string): Promise<AnalysisResult> {
  const r = NetLogEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings: toFindings(r.findings as Finding[]),
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'المحرك', v:'NetLogEngine v1.5' },
      { k:'إجمالي الطلبات', v: String(r.stats.totalReq) },
      { k:'الطلبات المُحللة', v: String(r.stats.parsed) },
      { k:'مسارات استغلال', v: String(r.stats.exploitPaths) },
      { k:'ماسحات مُكتشفة', v: String(r.stats.scannerCount) },
    ],
    stats: [
      { label:'الطلبات', value: String(r.stats.totalReq) },
      { label:'محاولات استغلال', value: String(r.stats.exploitPaths) },
      { label:'ماسحات', value: String(r.stats.scannerCount) },
    ],
    raw: r,
  };
}

// ── MOD-10 MITRE ATT&CK ───────────────────────────
async function runMitre(input: string): Promise<AnalysisResult> {
  const r = ATTACKEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = r.techniques.map((t: any) => ({
    sev: t.confidence >= 80 ? 'CRITICAL' : t.confidence >= 50 ? 'HIGH' : 'MEDIUM' as FindingItem['sev'],
    title: `${t.id} · ${t.name}`,
    desc: t.desc,
    evidence: `Tactic: ${(r.TACTICS as AnyObj)[t.tactic]?.ar || t.tactic} · Confidence: ${t.confidence}%`,
  }));
  return {
    pct: r.pct, threat: asThreatlevel(r.threat),
    verdictTitle: v.title, verdictDesc: v.desc,
    findings,
    meta: [
      { k:'معرّف التحليل', v: analysisId() },
      { k:'المحرك', v:'ATT&CK Mapper v1.0' },
      { k:'التقنيات المُكتشفة', v: String(r.total) },
      { k:'التكتيكات المُكتشفة', v: String(r.tacticCount) },
      { k:'مرحلة kill chain', v: String(r.killChainStage + 1) + '/' + '13' },
      { k:'التصنيف', v:'TLP:AMBER' },
    ],
    stats: [
      { label:'التقنيات', value: String(r.total) },
      { label:'التكتيكات', value: String(r.tacticCount) },
      { label:'ثقة', value: r.pct + '%' },
    ],
    raw: r,
  };
}

// ── SAMPLE DATA for each module ───────────────────
export const SAMPLES: Record<string, string> = {
  phishing: PhishingEngine.SAMPLE,
  url: UrlEngine.SAMPLE,
  email: EmailEngine.SAMPLE,
  ioc: IOCEngine.SAMPLE,
  timeline: TimelineEngine.SAMPLE,
  network: NetLogEngine.SAMPLE,
  mitre: ATTACKEngine.SAMPLE_TEXT,
};

// ── Unified Run Function ──────────────────────────
export async function runEngine(
  slug: string,
  input: string,
  file: File | null = null,
): Promise<AnalysisResult> {
  switch (slug) {
    case 'phishing':   return runPhishing(input);
    case 'url':        return runUrl(input);
    case 'email':      return runEmail(input);
    case 'fingerprint':return runHash(file, input);
    case 'ioc':        return runIOC(input);
    case 'timeline':   return runTimeline(input);
    case 'network':    return runNetLog(input);
    case 'mitre':      return runMitre(input);
    // MOD-03 (Image) & MOD-07 (Stego) need canvas — handled in component
    default:
      return { pct:0, threat:'safe', verdictTitle:'وحدة تجريبية', verdictDesc:'هذه الوحدة تعمل مع ملفات الصور مباشرة.', findings:[], meta:[], stats:[] };
  }
}
