/**
 * DFAS Engine Runner
 * Maps module slug → real engine call → normalized AnalysisResult
 */
import {
  PhishingEngine,
  UrlEngine,
  EmailEngine,
  HashEngine,
  IOCEngine,
  TimelineEngine,
  NetLogEngine,
  ATTACKEngine,
  ImageEngine,
  StegoEngine,
} from "./dfas-core";
import {
  MemoryEngine,
  DiskEngine,
  PcapEngine,
  EndpointEngine,
  YaraEnhancement,
} from "./dfas-forensics-engines";
import type { Finding, ThreatLevel, Severity } from "./types";

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
  sev: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
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
    sev: f.sev as FindingItem["sev"],
    title: f.rule || f.label || "—",
    desc: f.det || "",
    evidence: f.ev || "",
  }));
}

function asThreatlevel(t: string): ThreatLevel {
  return t as ThreatLevel;
}

function threatToVerdict(threat: string, pct: number): { title: string; desc: string } {
  if (threat === "crit")
    return {
      title: `تهديد حرج · ${pct}%`,
      desc: "تم اكتشاف مؤشرات خطرة جداً. يُنصح بعزل المدخل وعدم التفاعل معه.",
    };
  if (threat === "warn")
    return {
      title: `تهديد محتمل · ${pct}%`,
      desc: "وُجدت مؤشرات مشبوهة تستدعي مزيداً من التحقيق.",
    };
  return { title: `نظيف · ${pct}%`, desc: "لم يُكتشف ما يثير القلق في هذا المدخل." };
}

const analysisId = () =>
  "ANL-" +
  new Date().toISOString().slice(0, 10).replace(/-/g, "") +
  "-" +
  Math.random().toString(36).slice(2, 6).toUpperCase();

// ── MOD-01 Phishing ───────────────────────────────
async function runPhishing(input: string): Promise<AnalysisResult> {
  const r = PhishingEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: toFindings(r.findings),
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "PhishingEngine v3.5 · 47 مؤشر" },
      { k: "عدد الكلمات", v: String(r.meta.words) },
      { k: "روابط مُكتشفة", v: String(r.meta.urls.length) },
      { k: "علامات التعجب", v: String(r.meta.exclamations) },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "المؤشرات", value: String(r.findings.length) },
      { label: "النتيجة", value: String(r.score) },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-02 URL ────────────────────────────────────
async function runUrl(input: string): Promise<AnalysisResult> {
  const r = UrlEngine.analyze(input.trim());
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: toFindings(r.findings),
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "UrlEngine v4.3 · 13 معيار" },
      { k: "البروتوكول", v: r.parsed.protocol },
      { k: "النطاق", v: r.parsed.hostname },
      { k: "المسار", v: r.parsed.path },
      { k: "Shannon Entropy", v: r.entropy.toFixed(3) + " bits" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "المعايير المُكتشفة", value: String(r.findings.length) },
      { label: "إنتروبيا النطاق", value: r.entropy.toFixed(2) },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-04 Email Headers ──────────────────────────
async function runEmail(input: string): Promise<AnalysisResult> {
  const r = EmailEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: toFindings(r.findings),
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "من", v: r.headers.from },
      { k: "الرد على", v: r.headers.replyTo },
      { k: "SPF", v: r.auth.spf },
      { k: "DKIM", v: r.auth.dkim },
      { k: "DMARC", v: r.auth.dmarc },
      { k: "عدد نقاط التمرير", v: String(r.hops.length) },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "المؤشرات", value: String(r.findings.length) },
      { label: "نقاط التمرير", value: String(r.hops.length) },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-05 Hash / Fingerprint ─────────────────────
async function runHash(file: File | null, text: string): Promise<AnalysisResult> {
  let r: AnyObj;
  if (file) {
    r = await HashEngine.analyzeFile(file);
  } else {
    r = await HashEngine.analyzeText(text);
  }
  const threat: ThreatLevel = r.knownMalware ? "crit" : "safe";
  const pct = r.knownMalware ? 99 : 5;
  const v = threatToVerdict(threat, pct);
  return {
    pct,
    threat,
    verdictTitle: v.title,
    verdictDesc: r.knownMalware ? "⚠ البصمة مطابقة لقاعدة بيانات البرمجيات الخبيثة!" : v.desc,
    findings: r.knownMalware
      ? [
          {
            sev: "CRITICAL" as const,
            title: "بصمة خبيثة مُكتشفة",
            desc: "SHA-256 مطابق لبرمجية خبيثة في قاعدة البيانات",
            evidence: r.sha256,
          },
        ]
      : [],
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "SHA-256", v: (r.sha256 || "").slice(0, 40) + "…" },
      { k: "SHA-1", v: (r.sha1 || "").slice(0, 40) + "…" },
      { k: "MD5", v: r.md5 || "—" },
      { k: "الحجم", v: r.size ? `${(r.size / 1024).toFixed(1)} KB` : `${r.bytes} bytes` },
      { k: "النوع", v: r.type || r.name || "—" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "SHA-256", value: (r.sha256 || "").slice(0, 12) + "…" },
      { label: "الحجم", value: r.size ? (r.size / 1024).toFixed(0) + "KB" : r.bytes + "B" },
      { label: "حالة", value: r.knownMalware ? "خبيث ⚠" : "نظيف ✓" },
    ],
    raw: r,
  };
}

// ── MOD-06 IOC Scanner ────────────────────────────
async function runIOC(input: string): Promise<AnalysisResult> {
  const r = IOCEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = r.results.map((res: AnyObj) => ({
    sev: res.sev,
    title: res.label,
    desc: `${res.count} مؤشر مُكتشف — الفئة: ${res.cat}`,
    evidence: res.samples
      .map((s: AnyObj) => `${s.value}${s.extra ? " — " + s.extra : ""}`)
      .join("\n"),
  }));
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "IOCEngine v2.0" },
      { k: "إجمالي المؤشرات", v: String(r.stats.total) },
      { k: "CRITICAL", v: String(r.stats.bySeverity.CRITICAL || 0) },
      { k: "HIGH", v: String(r.stats.bySeverity.HIGH || 0) },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "إجمالي IOCs", value: String(r.stats.total) },
      { label: "أنواع مُكتشفة", value: String(r.results.length) },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-08 Timeline ───────────────────────────────
async function runTimeline(input: string): Promise<AnalysisResult> {
  const r = TimelineEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = r.anomalies.map((a: AnyObj) => ({
    sev: (a.type === "future"
      ? "CRITICAL"
      : a.type === "gap"
        ? "HIGH"
        : "MEDIUM") as FindingItem["sev"],
    title:
      a.type === "future"
        ? "طابع زمني مستقبلي"
        : a.type === "gap"
          ? `فجوة زمنية: ${a.gapH} ساعة`
          : `نشاط في ساعات غير معتادة (${a.hour}:00)`,
    desc:
      a.type === "gap"
        ? "انقطاع كبير في الخط الزمني قد يُشير إلى حذف سجلات"
        : a.type === "future"
          ? "طابع زمني يتجاوز الوقت الحالي — مؤشر تلاعب"
          : "نشاط بين منتصف الليل والفجر",
    evidence:
      a.type === "gap" && Array.isArray(a.events)
        ? `${a.events[0]?.raw ?? ""} → ${a.events[1]?.raw ?? ""}`
        : a.event
          ? a.event.raw
          : "",
  }));
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "TimelineEngine v1.0" },
      { k: "الأحداث المُكتشفة", v: String(r.total) },
      { k: "الشذوذات", v: String(r.anomalies.length) },
      { k: "الامتداد الزمني", v: r.span + " ساعة" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "الأحداث", value: String(r.total) },
      { label: "الشذوذات", value: String(r.anomalies.length) },
      { label: "المدة", value: r.span + "h" },
    ],
    raw: r,
  };
}

// ── MOD-09 Network Logs ───────────────────────────
async function runNetLog(input: string): Promise<AnalysisResult> {
  const r = NetLogEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: toFindings(r.findings as Finding[]),
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "NetLogEngine v1.5" },
      { k: "إجمالي الطلبات", v: String(r.stats.totalReq) },
      { k: "الطلبات المُحللة", v: String(r.stats.parsed) },
      { k: "مسارات استغلال", v: String(r.stats.exploitPaths) },
      { k: "ماسحات مُكتشفة", v: String(r.stats.scannerCount) },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "الطلبات", value: String(r.stats.totalReq) },
      { label: "محاولات استغلال", value: String(r.stats.exploitPaths) },
      { label: "ماسحات", value: String(r.stats.scannerCount) },
    ],
    raw: r,
  };
}

// ── MOD-10 MITRE ATT&CK ───────────────────────────
async function runMitre(input: string): Promise<AnalysisResult> {
  const r = ATTACKEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = r.techniques.map((t: AnyObj) => ({
    sev:
      t.confidence >= 80
        ? "CRITICAL"
        : t.confidence >= 50
          ? "HIGH"
          : ("MEDIUM" as FindingItem["sev"]),
    title: `${t.id} · ${t.name}`,
    desc: t.desc,
    evidence: `Tactic: ${(r.TACTICS as AnyObj)[t.tactic]?.ar || t.tactic} · Confidence: ${t.confidence}%`,
  }));
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "ATT&CK Mapper v1.0" },
      { k: "التقنيات المُكتشفة", v: String(r.total) },
      { k: "التكتيكات المُكتشفة", v: String(r.tacticCount) },
      { k: "مرحلة kill chain", v: String(r.killChainStage + 1) + "/" + "13" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "التقنيات", value: String(r.total) },
      { label: "التكتيكات", value: String(r.tacticCount) },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-03 Image Forensics ────────────────────────
async function runImage(file: File | null): Promise<AnalysisResult> {
  const r = file ? await ImageEngine.analyze(file) : ImageEngine.analyzeDemo();
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = (r.indicators || []).map((ind: AnyObj) => ({
    sev: ind.sev as FindingItem["sev"],
    title: ind.rule || ind.label || "—",
    desc: ind.det || "",
    evidence: ind.ev || "",
  }));
  const meta = r.meta || {};
  const t = meta.tags || {};
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "ImageEngine v3.0 · EXIF + Binary Sigs" },
      { k: "اسم الملف", v: meta.name || "—" },
      { k: "الحجم", v: meta.size ? `${(meta.size / 1024).toFixed(1)} KB` : "—" },
      { k: "التنسيق", v: r.magic || meta.type || "—" },
      { k: "الكاميرا", v: [t.Make, t.Model].filter(Boolean).join(" ") || "—" },
      { k: "برنامج التحرير", v: t.Software || "لا يوجد" },
      { k: "تاريخ الالتقاط", v: t.DateTimeOriginal || "—" },
      { k: "GPS", v: meta.gps ? `${meta.gps.lat}°N, ${meta.gps.lon}°E` : "غير موجود" },
      { k: "جودة JPEG", v: meta.jpegQuality !== null ? `~${meta.jpegQuality}%` : "—" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "المؤشرات", value: String(findings.length) },
      { label: "جودة JPEG", value: meta.jpegQuality ? meta.jpegQuality + "%" : "N/A" },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-07 Steganography ──────────────────────────
async function runStego(file: File | null): Promise<AnalysisResult> {
  const r = file ? await StegoEngine.analyze(file) : StegoEngine.analyzeSimulated();
  const v = threatToVerdict(r.threat, r.pct);
  const findings: FindingItem[] = (r.indicators || []).map((ind: AnyObj) => ({
    sev: ind.sev as FindingItem["sev"],
    title: ind.label || "—",
    desc: ind.det || "",
    evidence: ind.ev || "",
  }));
  const s = r.stats || {};
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "StegoEngine v2.0 · LSB + Chi² + Entropy" },
      { k: "الأبعاد", v: s.width && s.height ? `${s.width} × ${s.height} px` : "—" },
      { k: "إجمالي البكسلات", v: s.pixels ? String(s.pixels) : "—" },
      { k: "Shannon Entropy", v: s.entropy || "—" },
      { k: "Chi-Square", v: s.chi || "—" },
      { k: "LSB-R Ratio", v: s.lsbR ? (s.lsbR.ratio * 100).toFixed(1) + "%" : "—" },
      { k: "LSB-G Ratio", v: s.lsbG ? (s.lsbG.ratio * 100).toFixed(1) + "%" : "—" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "المؤشرات", value: String(findings.length) },
      { label: "Entropy", value: s.entropy || "—" },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-11 Memory Forensics ───────────────────────
async function runMemory(input: string): Promise<AnalysisResult> {
  const r = MemoryEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  // Also run YARA enhancement
  const yaraHits = YaraEnhancement.scan(input);
  const yaraFindings: FindingItem[] = yaraHits.map((hit: AnyObj) => ({
    sev: hit.sev as FindingItem["sev"],
    title: `[YARA] ${hit.rule} — ${hit.category}`,
    desc: hit.description,
    evidence: hit.matchedStrings.slice(0, 2).join(" | "),
  }));
  const allFindings = [
    ...(r.findings || []).map((f: AnyObj) => ({
      sev: f.sev as FindingItem["sev"],
      title: f.label || "—",
      desc: f.det || "",
      evidence: f.ev || "",
    })),
    ...yaraFindings,
  ];
  const adjustedPct = Math.min(r.pct + yaraHits.length * 5, 99);
  return {
    pct: adjustedPct,
    threat: asThreatlevel(adjustedPct >= 70 ? "crit" : adjustedPct >= 35 ? "warn" : "safe"),
    verdictTitle: threatToVerdict(
      adjustedPct >= 70 ? "crit" : adjustedPct >= 35 ? "warn" : "safe",
      adjustedPct,
    ).title,
    verdictDesc: v.desc,
    findings: allFindings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "MemoryEngine v1.0 · Volatility3-inspired" },
      { k: "مخرجات Volatility", v: r.isVolatilityOutput ? "✓ مُكتشفة" : "لا" },
      { k: "عمليات مُكتشفة", v: String(r.processCount) },
      { k: "مؤشرات حقن", v: String(r.stats.injectionIndicators) },
      { k: "تطابقات YARA", v: String(yaraHits.length) },
      { k: "التصنيف", v: "TLP:RED" },
    ],
    stats: [
      { label: "إجمالي المؤشرات", value: String(allFindings.length) },
      {
        label: "حرجة",
        value: String(
          r.stats.critical + yaraHits.filter((h: AnyObj) => h.sev === "CRITICAL").length,
        ),
      },
      { label: "ثقة", value: adjustedPct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-12 Disk Image Analyzer ────────────────────
async function runDisk(file: File | null, input: string): Promise<AnalysisResult> {
  const r = await DiskEngine.analyze(file || input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: (r.findings || []).map((f: AnyObj) => ({
      sev: f.sev as FindingItem["sev"],
      title: f.label || "—",
      desc: f.det || "",
      evidence: f.ev || "",
    })),
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "DiskEngine v1.0 · Sleuth Kit-inspired" },
      { k: "نظام الملفات", v: r.detectedFS || "غير معروف" },
      { k: "حجم الملف", v: r.fileSize ? `${(r.fileSize / 1024 / 1024).toFixed(2)} MB` : "—" },
      { k: "الإنتروبيا", v: r.entropy !== undefined ? r.entropy.toFixed(3) + " bits" : "—" },
      { k: "مخرجات TSK", v: r.isTSKOutput ? "✓ مُكتشفة" : "لا" },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "إجمالي المؤشرات", value: String(r.stats.totalFindings) },
      { label: "نظام الملفات", value: r.detectedFS || "—" },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-13 PCAP / Network Traffic ────────────────
async function runPcap(input: string): Promise<AnalysisResult> {
  const r = PcapEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: (r.findings || []).map((f: AnyObj) => ({
      sev: f.sev as FindingItem["sev"],
      title: f.label || "—",
      desc: f.det || "",
      evidence: f.ev || "",
    })),
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "PcapEngine v1.0 · Tshark-inspired" },
      { k: "إجمالي الحزم", v: r.stats.totalPackets !== null ? String(r.stats.totalPackets) : "—" },
      { k: "عناوين IP الفريدة", v: String(r.stats.uniqueIPs) },
      { k: "IPs خبيثة مُكتشفة", v: String(r.stats.badIPs) },
      { k: "أهداف C2 Beacon", v: String(r.stats.beaconTargets) },
      { k: "التصنيف", v: "TLP:AMBER" },
    ],
    stats: [
      { label: "IPs خبيثة", value: String(r.stats.badIPs) },
      { label: "C2 Beacons", value: String(r.stats.beaconTargets) },
      { label: "ثقة", value: r.pct + "%" },
    ],
    raw: r,
  };
}

// ── MOD-14 Endpoint Telemetry ─────────────────────
async function runEndpoint(input: string): Promise<AnalysisResult> {
  const r = EndpointEngine.analyze(input);
  const v = threatToVerdict(r.threat, r.pct);
  // Also run YARA enhancement
  const yaraHits = YaraEnhancement.scan(input);
  const allFindings = [
    ...(r.findings || []).map((f: AnyObj) => ({
      sev: f.sev as FindingItem["sev"],
      title: f.label || "—",
      desc: f.det || "",
      evidence: f.ev || "",
    })),
    ...yaraHits.map((hit: AnyObj) => ({
      sev: hit.sev as FindingItem["sev"],
      title: `[YARA] ${hit.rule}`,
      desc: hit.description,
      evidence: hit.matchedStrings.slice(0, 2).join(" | "),
    })),
  ];
  return {
    pct: r.pct,
    threat: asThreatlevel(r.threat),
    verdictTitle: v.title,
    verdictDesc: v.desc,
    findings: allFindings,
    meta: [
      { k: "معرّف التحليل", v: analysisId() },
      { k: "المحرك", v: "EndpointEngine v1.0 · Velociraptor-inspired" },
      { k: "مؤشرات الاستمرارية", v: String(r.stats.persistenceIndicators) },
      { k: "مؤشرات سرقة بيانات الاعتماد", v: String(r.stats.credentialIndicators) },
      { k: "تقنيات MITRE ATT&CK", v: String(r.stats.mitreMapping.length) },
      { k: "تطابقات YARA", v: String(yaraHits.length) },
      { k: "التصنيف", v: "TLP:RED" },
    ],
    stats: [
      { label: "إجمالي المؤشرات", value: String(allFindings.length) },
      { label: "تقنيات ATT&CK", value: String(r.stats.mitreMapping.length) },
      { label: "ثقة", value: r.pct + "%" },
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
  memory: MemoryEngine.SAMPLE,
  disk: DiskEngine.SAMPLE,
  pcap: PcapEngine.SAMPLE,
  endpoint: EndpointEngine.SAMPLE,
};

// ── Unified Run Function ──────────────────────────
export async function runEngine(
  slug: string,
  input: string,
  file: File | null = null,
): Promise<AnalysisResult> {
  switch (slug) {
    case "phishing":
      return runPhishing(input);
    case "url":
      return runUrl(input);
    case "email":
      return runEmail(input);
    case "fingerprint":
      return runHash(file, input);
    case "ioc":
      return runIOC(input);
    case "timeline":
      return runTimeline(input);
    case "network":
      return runNetLog(input);
    case "mitre":
      return runMitre(input);
    case "image":
      return runImage(file);
    case "stego":
      return runStego(file);
    case "memory":
      return runMemory(input);
    case "disk":
      return runDisk(file, input);
    case "pcap":
      return runPcap(input);
    case "endpoint":
      return runEndpoint(input);
    default:
      return {
        pct: 0,
        threat: "safe",
        verdictTitle: "وحدة غير معرّفة",
        verdictDesc: "هذه الوحدة غير مدعومة حالياً.",
        findings: [],
        meta: [],
        stats: [],
      };
  }
}
