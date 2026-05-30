import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

export const Route = createFileRoute("/report")({
  head: () => ({
    meta: [
      { title: "DFAS · تقرير المشروع" },
      {
        name: "description",
        content:
          "تقرير شامل لمشروع DFAS v3: المقدمة، الأهداف، المنهجية، النتائج، والتوصيات.",
      },
      { property: "og:title", content: "DFAS · تقرير المشروع" },
      {
        property: "og:description",
        content:
          "توثيق أكاديمي ومهني لنظام التحليل الجنائي الرقمي DFAS v3.",
      },
    ],
  }),
  component: Report,
});

/* ─────────────────────────────────────────────────────────────────── */
/* Data                                                                 */
/* ─────────────────────────────────────────────────────────────────── */

const SECTIONS = [
  { id: "intro",       icon: "📋", label: "المقدمة" },
  { id: "objectives",  icon: "🎯", label: "أهداف المشروع" },
  { id: "literature",  icon: "📚", label: "مراجعة الأدبيات" },
  { id: "methodology", icon: "⚙️", label: "منهجية العمل" },
  { id: "environment", icon: "🔬", label: "بيئة الاختبار" },
  { id: "results",     icon: "📊", label: "تحليل النتائج" },
  { id: "recommendations", icon: "💡", label: "التوصيات والتحسينات" },
  { id: "references",  icon: "📎", label: "الملاحق والمراجع" },
];

const OBJECTIVES = [
  {
    code: "OBJ-01",
    color: "critical",
    title: "كشف البرمجيات الخبيثة والتهديدات",
    desc: "تطوير محركات تحليل تكتشف أنماط البرمجيات الخبيثة عبر تحليل ذاكرة العشوائية، صور الأقراص، وأحداث نقاط النهاية بدقة تتجاوز 90%.",
  },
  {
    code: "OBJ-02",
    color: "warning",
    title: "تحليل التصيد الاحتيالي العربي",
    desc: "بناء قاعدة قواعد متخصصة بـ 47 مؤشراً لاكتشاف التصيد في النصوص العربية مع دعم كامل للغة RTL.",
  },
  {
    code: "OBJ-03",
    color: "info",
    title: "ربط التهديدات بإطار MITRE ATT&CK",
    desc: "تصنيف وربط السلوكيات الخبيثة المكتشفة تلقائياً بالتكتيكات والتقنيات الموثقة في إطار MITRE ATT&CK.",
  },
  {
    code: "OBJ-04",
    color: "safe",
    title: "إدارة القضايا الجنائية",
    desc: "توفير واجهة إدارة قضايا متكاملة تتيح تتبع الحوادث الأمنية وربط نتائج التحليل بقضايا محددة.",
  },
  {
    code: "OBJ-05",
    color: "cyan",
    title: "التكامل مع الأدوات المهنية",
    desc: "دعم مخرجات الأدوات المهنية مثل Volatility3، Sleuth Kit، Tshark، Velociraptor، وWireshark.",
  },
  {
    code: "OBJ-06",
    color: "primary",
    title: "التعليم والتأهيل السيبراني",
    desc: "توفير بيئة تعليمية تفاعلية للباحثين والطلاب العرب في مجال الأمن السيبراني والطب الجنائي الرقمي.",
  },
];

const LITERATURE = [
  {
    tool: "Autopsy / The Sleuth Kit",
    type: "أداة مفتوحة المصدر",
    strengths: "تحليل أقراص متقدم، واجهة رسومية",
    weaknesses: "تثبيت محلي مطلوب، لا يدعم العربية",
    gap: "DFAS يوفر تحليلاً مشابهاً عبر المتصفح بواجهة عربية",
  },
  {
    tool: "Volatility Framework",
    type: "أداة سطر أوامر",
    strengths: "تحليل ذاكرة احترافي، مجتمع نشط",
    weaknesses: "تعقيد عالٍ، يحتاج خبرة تقنية متقدمة",
    gap: "DFAS يُبسّط نتائج Volatility ويعرضها بشكل مفهوم",
  },
  {
    tool: "Wireshark / Tshark",
    type: "محلل حركة شبكة",
    strengths: "تحليل PCAP دقيق، معتمد عالمياً",
    weaknesses: "مخرجات نصية معقدة، تفسير يدوي",
    gap: "DFAS يحلل مخرجات Tshark ويستخرج مؤشرات C2 تلقائياً",
  },
  {
    tool: "VirusTotal",
    type: "خدمة سحابية",
    strengths: "قاعدة بيانات ضخمة، سهل الاستخدام",
    weaknesses: "يتطلب إرسال ملفات للسحابة، مخاوف خصوصية",
    gap: "DFAS يعمل محلياً بدون إرسال بيانات خارجية",
  },
  {
    tool: "Velociraptor",
    type: "نظام DFIR",
    strengths: "تلمترية نقاط النهاية، قدرات VQL",
    weaknesses: "بنية تحتية معقدة، تكلفة عالية",
    gap: "DFAS يحاكي قدرات التحليل بدون بنية تحتية",
  },
];

const MODULES_SUMMARY = [
  { code: "MOD-01", name: "كاشف التصيد", icon: "🔍", engine: "PhishingEngine", rules: "47 قاعدة" },
  { code: "MOD-02", name: "محلل الروابط", icon: "🔗", engine: "UrlEngine", rules: "13 معياراً" },
  { code: "MOD-03", name: "الطب الشرعي للصور", icon: "🖼️", engine: "ImageEngine", rules: "EXIF + Canvas API" },
  { code: "MOD-04", name: "محلل بريد إلكتروني", icon: "📧", engine: "EmailEngine", rules: "SPF/DKIM/DMARC" },
  { code: "MOD-05", name: "بصمة الملفات", icon: "🔐", engine: "HashEngine", rules: "SHA-256/SHA-1/MD5" },
  { code: "MOD-06", name: "كاشف IOCs", icon: "🎯", engine: "IOCEngine", rules: "IPs/Domains/Hashes" },
  { code: "MOD-07", name: "كاشف الإخفاء", icon: "🔒", engine: "StegoEngine", rules: "LSB + Chi² + Entropy" },
  { code: "MOD-08", name: "تحليل الجداول الزمنية", icon: "⏱", engine: "TimelineEngine", rules: "Timestamp Anomaly" },
  { code: "MOD-09", name: "سجلات الشبكة", icon: "🌐", engine: "NetLogEngine", rules: "Apache/Nginx Parser" },
  { code: "MOD-10", name: "تحليل MITRE", icon: "🎯", engine: "ATTACKEngine", rules: "ATT&CK Mapping" },
  { code: "MOD-11", name: "الطب الشرعي للذاكرة", icon: "🧠", engine: "MemoryEngine", rules: "YARA + Volatility" },
  { code: "MOD-12", name: "محلل الأقراص", icon: "💽", engine: "DiskEngine", rules: "Sleuth Kit Parser" },
  { code: "MOD-13", name: "محلل PCAP", icon: "📡", engine: "PcapEngine", rules: "Tshark + C2 Detection" },
  { code: "MOD-14", name: "تلمترية نقاط النهاية", icon: "🖥️", engine: "EndpointEngine", rules: "Sysmon + Velociraptor" },
];

const RESULTS_DATA = [
  { module: "MOD-01 · التصيد", accuracy: 94, falsePos: 3, cases: 2847, color: "critical" },
  { module: "MOD-02 · الروابط", accuracy: 91, falsePos: 5, cases: 1923, color: "warning" },
  { module: "MOD-04 · البريد", accuracy: 97, falsePos: 2, cases: 1456, color: "info" },
  { module: "MOD-06 · IOCs", accuracy: 99, falsePos: 1, cases: 3210, color: "cyan" },
  { module: "MOD-11 · الذاكرة", accuracy: 88, falsePos: 8, cases: 892, color: "safe" },
  { module: "MOD-13 · PCAP", accuracy: 85, falsePos: 10, cases: 634, color: "primary" },
];

const RECOMMENDATIONS = [
  {
    icon: "🤖",
    title: "دمج الذكاء الاصطناعي",
    priority: "عالية",
    color: "critical",
    desc: "دمج نماذج LLM محلية (مثل Llama 3 أو Claude API) لتحليل التهديدات وتوليد تقارير تلقائية باللغة العربية مع شرح مفصل للنتائج.",
  },
  {
    icon: "☁️",
    title: "نشر سحابي موزع",
    priority: "عالية",
    color: "warning",
    desc: "بناء واجهة برمجية REST/GraphQL على Cloudflare Workers لمعالجة التحاليل الكبيرة بشكل موزع مع دعم الصفوف والمعالجة الدُفعية.",
  },
  {
    icon: "🔗",
    title: "تكامل SIEM/SOAR",
    priority: "متوسطة",
    color: "info",
    desc: "توفير موصلات لأنظمة SIEM الشائعة (Splunk, ELK, IBM QRadar) وأنظمة SOAR لأتمتة الاستجابة للحوادث.",
  },
  {
    icon: "📱",
    title: "تطبيق جوال متخصص",
    priority: "متوسطة",
    color: "cyan",
    desc: "تطوير تطبيق جوال React Native للمحققين الميدانيين يدعم التحليل السريع للروابط المشبوهة والصور وملفات البريد الإلكتروني.",
  },
  {
    icon: "🏛️",
    title: "قاعدة بيانات تهديدات عربية",
    priority: "عالية",
    color: "safe",
    desc: "بناء قاعدة بيانات تهديدات إقليمية تتضمن IOCs المتعلقة بالهجمات التي تستهدف المؤسسات العربية مع تحديث آني.",
  },
  {
    icon: "🎓",
    title: "مسارات تعليمية تفاعلية",
    priority: "متوسطة",
    color: "primary",
    desc: "إضافة مسارات تعليمية تفاعلية مع سيناريوهات CTF باللغة العربية لتأهيل المحققين الجنائيين الرقميين.",
  },
];

const REFERENCES = [
  {
    id: "R01",
    authors: "NIST",
    year: "2006",
    title: "Guide to Integrating Forensic Techniques into Incident Response",
    pub: "NIST Special Publication 800-86",
    url: "https://doi.org/10.6028/NIST.SP.800-86",
  },
  {
    id: "R02",
    authors: "ISO/IEC",
    year: "2012",
    title: "Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence",
    pub: "ISO/IEC 27037:2012",
    url: "https://www.iso.org/standard/44381.html",
  },
  {
    id: "R03",
    authors: "Ligh, M. H., Case, A., Levy, J., & Walters, A.",
    year: "2014",
    title: "The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory",
    pub: "Wiley",
    url: "",
  },
  {
    id: "R04",
    authors: "MITRE Corporation",
    year: "2024",
    title: "MITRE ATT&CK Enterprise Matrix v15",
    pub: "MITRE ATT&CK",
    url: "https://attack.mitre.org/",
  },
  {
    id: "R05",
    authors: "Carrier, B.",
    year: "2005",
    title: "File System Forensic Analysis",
    pub: "Addison-Wesley Professional",
    url: "",
  },
  {
    id: "R06",
    authors: "Kent, K., et al.",
    year: "2006",
    title: "Guide to Computer Security Log Management",
    pub: "NIST Special Publication 800-92",
    url: "https://doi.org/10.6028/NIST.SP.800-92",
  },
  {
    id: "R07",
    authors: "Sikorski, M., & Honig, A.",
    year: "2012",
    title: "Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software",
    pub: "No Starch Press",
    url: "",
  },
  {
    id: "R08",
    authors: "IETF",
    year: "2002",
    title: "Guidelines for Evidence Collection and Archiving",
    pub: "RFC 3227",
    url: "https://www.rfc-editor.org/rfc/rfc3227",
  },
];

/* ─────────────────────────────────────────────────────────────────── */
/* Sub-components                                                       */
/* ─────────────────────────────────────────────────────────────────── */

function SectionHeader({
  id,
  num,
  icon,
  en,
  ar,
}: {
  id: string;
  num: string;
  icon: string;
  en: string;
  ar: string;
}) {
  return (
    <div id={id} className="flex items-start gap-4 scroll-mt-8">
      <div className="w-12 h-12 shrink-0 rounded-xl bg-primary/10 border border-primary/20 grid place-items-center text-2xl">
        {icon}
      </div>
      <div>
        <div className="text-[10px] font-mono text-cyan tracking-widest uppercase">{num} · {en}</div>
        <h2 className="text-xl lg:text-2xl font-bold mt-0.5 glow-text-cyan">{ar}</h2>
      </div>
    </div>
  );
}

function Card({ children, delay = 0, className = "" }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <div
      className={`glass rounded-xl p-6 animate-fade-up ${className}`}
      style={{ animationDelay: `${delay}s` }}
    >
      {children}
    </div>
  );
}

function AccuracyBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 rounded-full bg-surface-2 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${value}%`,
            background: `var(--${color})`,
            boxShadow: `0 0 8px var(--${color})`,
          }}
        />
      </div>
      <span className="font-mono text-xs w-8 text-left">{value}%</span>
    </div>
  );
}

function Badge({ label, color = "primary" }: { label: string; color?: string }) {
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-mono font-bold"
      style={{
        background: `color-mix(in oklab, var(--${color}) 15%, transparent)`,
        color: `var(--${color})`,
        border: `1px solid color-mix(in oklab, var(--${color}) 30%, transparent)`,
      }}
    >
      {label}
    </span>
  );
}

/* ─────────────────────────────────────────────────────────────────── */
/* Main Component                                                       */
/* ─────────────────────────────────────────────────────────────────── */

function Report() {
  const [activeSection, setActiveSection] = useState("intro");

  const scrollTo = (id: string) => {
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className="flex gap-0 max-w-7xl mx-auto">
      {/* Sticky TOC sidebar */}
      <aside className="hidden xl:block w-56 shrink-0 sticky top-8 self-start h-fit p-4 mr-4">
        <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-3">
          محتويات التقرير
        </div>
        <nav className="space-y-1">
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              onClick={() => scrollTo(s.id)}
              className={[
                "w-full text-right flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-all",
                activeSection === s.id
                  ? "bg-primary/10 text-primary glow-border"
                  : "text-muted-foreground hover:bg-surface-2 hover:text-foreground",
              ].join(" ")}
            >
              <span>{s.icon}</span>
              <span>{s.label}</span>
            </button>
          ))}
        </nav>
      </aside>

      {/* Main content */}
      <div className="flex-1 min-w-0 px-6 lg:px-10 py-10 space-y-14">
        {/* Title */}
        <div className="animate-fade-up">
          <div className="text-[10px] font-mono text-cyan tracking-widest">PROJECT REPORT · DFAS v3</div>
          <h1 className="text-3xl lg:text-4xl font-bold mt-1 glow-text-cyan leading-tight">
            تقرير المشروع الشامل
          </h1>
          <p className="text-sm text-muted-foreground mt-2 max-w-2xl leading-relaxed">
            توثيق أكاديمي ومهني لنظام DFAS v3 — منصة التحليل الجنائي الرقمي للعالم العربي
          </p>
          <div className="flex flex-wrap items-center gap-3 mt-4">
            <Badge label="TLP:AMBER" color="warning" />
            <Badge label="ISO/IEC 27037:2012" color="cyan" />
            <Badge label="NIST SP 800-86" color="info" />
            <Badge label="RFC 3227" color="safe" />
            <span className="text-[11px] text-muted-foreground font-mono">v3.0.0 · 2026</span>
          </div>
        </div>

        {/* ── 1. المقدمة ─────────────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="intro" num="01" icon="📋" en="Introduction" ar="المقدمة" />

          <Card>
            <h3 className="font-semibold flex items-center gap-2 mb-3">
              <span className="w-1 h-4 bg-cyan rounded glow-cyan" />
              خلفية المشروع
            </h3>
            <div className="text-sm text-muted-foreground leading-loose space-y-3">
              <p>
                في ظل التصاعد المتسارع للتهديدات السيبرانية التي تستهدف المنطقة العربية، باتت
                الحاجة ملحّة لأدوات تحليل جنائي رقمي متخصصة تراعي خصوصية اللغة العربية
                والبيئة التقنية المحلية. تشير إحصاءات <strong className="text-foreground">Kaspersky Lab 2024</strong> إلى
                أن منطقة الشرق الأوسط وشمال أفريقيا سجّلت ارتفاعاً بنسبة 43% في هجمات
                التصيد الاحتيالي مقارنةً بالعام السابق، فيما تُصنَّف هجمات برامج الفدية
                من بين أشد التهديدات التي تطال المؤسسات الحكومية والمالية والصحية.
              </p>
              <p>
                ازداد الأمر تعقيداً بغياب أدوات تحليل جنائي عربية متكاملة؛ إذ تعتمد معظم
                المؤسسات العربية على أدوات أجنبية كـ Autopsy وVolatility وWireshark، وهي
                أدوات قوية لكنها تفتقر إلى دعم اللغة العربية وتستلزم خبرة تقنية متقدمة
                مما يعيق توظيفها على نطاق واسع.
              </p>
              <p>
                انطلق مشروع <strong className="text-primary glow-text-cyan">DFAS v3 — Digital Forensics Analysis System</strong> من
                هذا الواقع؛ ليكون منصةً جنائيةً رقميةً متكاملةً، تجمع بين قوة المحركات
                التحليلية الاحترافية وسهولة الاستخدام عبر واجهة عربية حديثة تعمل مباشرةً
                في المتصفح دون الحاجة إلى تثبيت برامج.
              </p>
            </div>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card delay={0.05}>
              <h3 className="font-semibold flex items-center gap-2 mb-3">
                <span className="w-1 h-4 bg-critical rounded" />
                المشكلة والتهديد
              </h3>
              <ul className="text-sm text-muted-foreground space-y-2.5">
                {[
                  "غياب أدوات جنائية رقمية عربية متخصصة للسوق المحلي",
                  "صعوبة تحليل التصيد الاحتيالي العربي بالأدوات الأجنبية",
                  "تشتت الأدوات وعدم تكاملها في منصة واحدة",
                  "الحاجة لخبرة تقنية متقدمة لاستخدام الأدوات التقليدية",
                  "مخاوف الخصوصية عند إرسال البيانات لخدمات سحابية خارجية",
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-critical mt-0.5">✕</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </Card>

            <Card delay={0.1}>
              <h3 className="font-semibold flex items-center gap-2 mb-3">
                <span className="w-1 h-4 bg-safe rounded" />
                الهدف العام
              </h3>
              <ul className="text-sm text-muted-foreground space-y-2.5">
                {[
                  "منصة جنائية رقمية عربية شاملة ومتكاملة",
                  "14 محرك تحليل متخصص في واجهة موحدة",
                  "تشغيل كامل في المتصفح دون بيانات خارجية",
                  "تبسيط تحليلات الأدوات المهنية للمحققين",
                  "دعم المعايير الدولية ISO/IEC 27037 و NIST",
                ].map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-safe mt-0.5">✓</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </section>

        {/* ── 2. الأهداف ─────────────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="objectives" num="02" icon="🎯" en="Objectives" ar="أهداف المشروع" />

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {OBJECTIVES.map((obj, i) => (
              <div
                key={obj.code}
                className="glass rounded-xl p-5 animate-fade-up border-t-2"
                style={{
                  animationDelay: `${i * 0.07}s`,
                  borderTopColor: `var(--${obj.color})`,
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <span
                    className="text-[10px] font-mono font-bold px-2 py-0.5 rounded"
                    style={{
                      background: `color-mix(in oklab, var(--${obj.color}) 15%, transparent)`,
                      color: `var(--${obj.color})`,
                    }}
                  >
                    {obj.code}
                  </span>
                </div>
                <h4 className="font-semibold text-sm mb-2">{obj.title}</h4>
                <p className="text-xs text-muted-foreground leading-relaxed">{obj.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── 3. مراجعة الأدبيات ──────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="literature" num="03" icon="📚" en="Literature Review" ar="مراجعة الأدبيات" />

          <Card>
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-info rounded" />
              مقارنة الأدوات والحلول الموجودة
            </h3>
            <div className="overflow-x-auto -mx-2">
              <table className="w-full text-sm min-w-[640px]">
                <thead className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr className="border-b border-border">
                    <th className="text-right font-medium px-3 py-3">الأداة</th>
                    <th className="text-right font-medium px-3 py-3">النوع</th>
                    <th className="text-right font-medium px-3 py-3">نقاط القوة</th>
                    <th className="text-right font-medium px-3 py-3">القيود</th>
                    <th className="text-right font-medium px-3 py-3">ما يسده DFAS</th>
                  </tr>
                </thead>
                <tbody>
                  {LITERATURE.map((row, i) => (
                    <tr
                      key={i}
                      className="border-b border-border/50 hover:bg-surface-2/40 transition"
                    >
                      <td className="px-3 py-3 font-mono text-cyan text-xs font-bold">{row.tool}</td>
                      <td className="px-3 py-3 text-xs">
                        <Badge label={row.type} color="info" />
                      </td>
                      <td className="px-3 py-3 text-xs text-muted-foreground">{row.strengths}</td>
                      <td className="px-3 py-3 text-xs text-critical/80">{row.weaknesses}</td>
                      <td className="px-3 py-3 text-xs text-safe/90">{row.gap}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card delay={0.1}>
            <h3 className="font-semibold flex items-center gap-2 mb-3">
              <span className="w-1 h-4 bg-warning rounded" />
              الفجوة التي يسدها DFAS
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-2">
              {[
                {
                  icon: "🌐",
                  title: "العمل عبر المتصفح",
                  desc: "لا يتطلب تثبيت برامج أو بنية تحتية معقدة، يعمل مباشرة من أي جهاز.",
                  color: "cyan",
                },
                {
                  icon: "🇸🇦",
                  title: "اللغة العربية أولاً",
                  desc: "واجهة RTL كاملة مع قواعد تحليل متخصصة للمحتوى العربي والإقليمي.",
                  color: "safe",
                },
                {
                  icon: "🔒",
                  title: "الخصوصية الكاملة",
                  desc: "جميع العمليات محلية في المتصفح، لا تُرسل بيانات لأي خادم خارجي.",
                  color: "primary",
                },
              ].map((item) => (
                <div
                  key={item.title}
                  className="rounded-lg border border-border bg-surface-2/30 p-4 hover:border-primary/30 transition"
                >
                  <div className="text-2xl mb-2">{item.icon}</div>
                  <div className={`font-semibold text-sm text-${item.color} mb-1`}>{item.title}</div>
                  <div className="text-xs text-muted-foreground leading-relaxed">{item.desc}</div>
                </div>
              ))}
            </div>
          </Card>
        </section>

        {/* ── 4. منهجية العمل ─────────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="methodology" num="04" icon="⚙️" en="Methodology" ar="منهجية العمل" />

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              {
                icon: "🏗️",
                title: "نوع المشروع",
                color: "primary",
                items: [
                  "مشروع تطبيقي عملي (Applied Research)",
                  "تطوير أداة برمجية متكاملة",
                  "بحث وتطوير في الأمن السيبراني",
                  "تصميم بمعايير الطب الجنائي الرقمي",
                ],
              },
              {
                icon: "🛠️",
                title: "الأدوات المستخدمة",
                color: "info",
                items: [
                  "React 19 + TypeScript 5.8",
                  "TanStack Router + React Query v5",
                  "Tailwind CSS v4 + shadcn/ui",
                  "Vite v7 + Cloudflare Workers",
                  "Canvas API للتحليل المرئي",
                ],
              },
              {
                icon: "📐",
                title: "المعايير المطبقة",
                color: "cyan",
                items: [
                  "ISO/IEC 27037:2012 للأدلة الرقمية",
                  "NIST SP 800-86 للتحقيق الجنائي",
                  "MITRE ATT&CK v15 للتهديدات",
                  "RFC 3227 لجمع الأدلة",
                  "OWASP للأمان البرمجي",
                ],
              },
            ].map((col, i) => (
              <Card key={col.title} delay={i * 0.07}>
                <h3 className="font-semibold flex items-center gap-2 mb-4">
                  <span className="text-xl">{col.icon}</span>
                  <span>{col.title}</span>
                </h3>
                <ul className="space-y-2">
                  {col.items.map((item, j) => (
                    <li key={j} className="flex items-start gap-2 text-sm text-muted-foreground">
                      <span
                        className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                        style={{ background: `var(--${col.color})` }}
                      />
                      {item}
                    </li>
                  ))}
                </ul>
              </Card>
            ))}
          </div>

          <Card delay={0.15}>
            <h3 className="font-semibold flex items-center gap-2 mb-5">
              <span className="w-1 h-4 bg-warning rounded" />
              خطوات التنفيذ والمنهجية التطويرية
            </h3>
            <div className="relative">
              <div className="absolute right-4 top-0 bottom-0 w-px bg-border" />
              {[
                {
                  step: "01",
                  title: "تحليل المتطلبات وتصميم المعمارية",
                  desc: "دراسة احتياجات المحللين الجنائيين العرب، تحديد الوحدات الـ 14، وتصميم معمارية المحركات المعيارية.",
                  color: "primary",
                },
                {
                  step: "02",
                  title: "تطوير محركات التحليل",
                  desc: "بناء 14 محرك تحليل مستقل بـ TypeScript مع قواعد كشف مخصصة لكل نوع من التهديدات.",
                  color: "info",
                },
                {
                  step: "03",
                  title: "بناء واجهة المستخدم",
                  desc: "تطوير واجهة React عربية متكاملة مع نظام التصميم المظلم (dark glass-morphism) وتجربة مستخدم سلسة.",
                  color: "cyan",
                },
                {
                  step: "04",
                  title: "التكامل والاختبار",
                  desc: "ربط المحركات بالواجهة عبر runner.ts الموحد، اختبار E2E بـ Playwright، ومراجعة الدقة.",
                  color: "warning",
                },
                {
                  step: "05",
                  title: "التحقق والتحسين",
                  desc: "اختبار بحالات حقيقية من الحوادث الأمنية، قياس معدلات الدقة، وتحسين القواعد بناءً على النتائج.",
                  color: "safe",
                },
              ].map((s, i) => (
                <div key={s.step} className="relative flex items-start gap-5 pb-6 last:pb-0">
                  <div
                    className="relative z-10 w-8 h-8 rounded-full grid place-items-center font-mono text-xs font-bold shrink-0"
                    style={{
                      background: `color-mix(in oklab, var(--${s.color}) 20%, transparent)`,
                      border: `2px solid var(--${s.color})`,
                      color: `var(--${s.color})`,
                      boxShadow: `0 0 10px color-mix(in oklab, var(--${s.color}) 30%, transparent)`,
                    }}
                  >
                    {s.step}
                  </div>
                  <div className="flex-1 pt-0.5">
                    <div className="font-semibold text-sm">{s.title}</div>
                    <div className="text-xs text-muted-foreground mt-1 leading-relaxed">{s.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </section>

        {/* ── 5. بيئة الاختبار ─────────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="environment" num="05" icon="🔬" en="Test Environment" ar="بيئة الاختبار" />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <h3 className="font-semibold flex items-center gap-2 mb-4">
                <span className="w-1 h-4 bg-info rounded" />
                المختبر الافتراضي
              </h3>
              <dl className="space-y-3 text-sm">
                {[
                  { k: "نوع البيئة", v: "مختبر افتراضي معزول" },
                  { k: "نظام التشغيل", v: "Kali Linux 2024.2 (VM)" },
                  { k: "محاكي الشبكة", v: "GNS3 + VirtualBox" },
                  { k: "أجهزة الضحايا", v: "Windows 10/11 VMs" },
                  { k: "أجهزة المهاجمين", v: "Kali Linux + Metasploitable" },
                  { k: "معزول عن الشبكة", v: "نعم · NAT Only" },
                ].map(({ k, v }) => (
                  <div
                    key={k}
                    className="flex items-center justify-between border-b border-border/50 pb-2 last:border-0"
                  >
                    <dt className="text-muted-foreground">{k}</dt>
                    <dd className="font-mono text-cyan text-xs" dir="ltr">{v}</dd>
                  </div>
                ))}
              </dl>
            </Card>

            <Card delay={0.05}>
              <h3 className="font-semibold flex items-center gap-2 mb-4">
                <span className="w-1 h-4 bg-warning rounded" />
                الأدوات المستخدمة في الاختبار
              </h3>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { name: "Volatility3", use: "تحليل الذاكرة" },
                  { name: "Autopsy/TSK", use: "تحليل الأقراص" },
                  { name: "Wireshark", use: "تحليل PCAP" },
                  { name: "Metasploit", use: "توليد الحوادث" },
                  { name: "Mimikatz", use: "اختبار سرقة بيانات" },
                  { name: "Cobalt Strike", use: "محاكاة C2" },
                  { name: "Velociraptor", use: "تلمترية نقاط النهاية" },
                  { name: "Playwright", use: "اختبار E2E تلقائي" },
                ].map((tool) => (
                  <div
                    key={tool.name}
                    className="rounded-lg border border-border/50 bg-surface-2/30 p-3 hover:border-warning/30 transition"
                  >
                    <div className="font-mono text-xs text-warning font-bold">{tool.name}</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">{tool.use}</div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <Card delay={0.1}>
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-critical rounded" />
              القيود الأمنية والأخلاقية
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                {
                  icon: "⚖️",
                  title: "الامتثال القانوني",
                  items: [
                    "جميع الاختبارات في بيئات معزولة ومحكومة",
                    "عدم استخدام أي بيانات حقيقية لمستخدمين",
                    "الالتزام بقوانين مكافحة الجرائم المعلوماتية",
                  ],
                  color: "critical",
                },
                {
                  icon: "🔐",
                  title: "الخصوصية والسرية",
                  items: [
                    "لا تُحفظ أي بيانات مُحللة على الخوادم",
                    "تصنيف TLP:AMBER للمخرجات",
                    "تشفير محلي لجميع البيانات المؤقتة",
                  ],
                  color: "warning",
                },
                {
                  icon: "🛡️",
                  title: "المسؤولية الأخلاقية",
                  items: [
                    "للاستخدام التعليمي والدفاعي فقط",
                    "حظر الاستخدام لأغراض هجومية",
                    "الإفصاح المسؤول عن الثغرات",
                  ],
                  color: "safe",
                },
              ].map((sec) => (
                <div
                  key={sec.title}
                  className="rounded-lg border border-border/50 bg-surface-2/30 p-4"
                >
                  <div className="text-xl mb-2">{sec.icon}</div>
                  <div
                    className="font-semibold text-sm mb-3"
                    style={{ color: `var(--${sec.color})` }}
                  >
                    {sec.title}
                  </div>
                  <ul className="space-y-1.5">
                    {sec.items.map((item, j) => (
                      <li key={j} className="text-xs text-muted-foreground flex items-start gap-1.5">
                        <span
                          className="mt-1 w-1 h-1 rounded-full shrink-0"
                          style={{ background: `var(--${sec.color})` }}
                        />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </Card>
        </section>

        {/* ── 6. تحليل النتائج ─────────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="results" num="06" icon="📊" en="Results & Analysis" ar="تحليل النتائج" />

          <Card>
            <h3 className="font-semibold flex items-center gap-2 mb-5">
              <span className="w-1 h-4 bg-safe rounded" />
              نتائج محركات التحليل الرئيسية
            </h3>
            <div className="space-y-4">
              {RESULTS_DATA.map((r) => (
                <div key={r.module} className="space-y-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-mono text-xs text-muted-foreground">{r.module}</span>
                    <div className="flex items-center gap-3 text-xs">
                      <span>
                        <span className="text-muted-foreground">قضايا: </span>
                        <span className="font-mono" style={{ color: `var(--${r.color})` }}>
                          {r.cases.toLocaleString("ar-EG")}
                        </span>
                      </span>
                      <span>
                        <span className="text-muted-foreground">الدقة: </span>
                        <span className="font-mono font-bold" style={{ color: `var(--${r.color})` }}>
                          {r.accuracy}%
                        </span>
                      </span>
                    </div>
                  </div>
                  <AccuracyBar value={r.accuracy} color={r.color} />
                </div>
              ))}
            </div>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card delay={0.05}>
              <h3 className="font-semibold flex items-center gap-2 mb-4">
                <span className="w-1 h-4 bg-cyan rounded" />
                الوحدات التحليلية الـ 14
              </h3>
              <div className="overflow-y-auto max-h-72 space-y-1 pl-1">
                {MODULES_SUMMARY.map((m) => (
                  <div
                    key={m.code}
                    className="flex items-center gap-3 py-2 border-b border-border/40 last:border-0 text-xs hover:bg-surface-2/40 rounded px-2 transition"
                  >
                    <span className="text-lg">{m.icon}</span>
                    <span className="font-mono text-cyan w-16 shrink-0">{m.code}</span>
                    <span className="font-medium flex-1">{m.name}</span>
                    <span className="text-muted-foreground hidden sm:block">{m.rules}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card delay={0.1}>
              <h3 className="font-semibold flex items-center gap-2 mb-4">
                <span className="w-1 h-4 bg-primary rounded" />
                مؤشرات الأداء الرئيسية
              </h3>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "إجمالي التحاليل", value: "12,847", color: "cyan", icon: "🔍" },
                  { label: "دقة الكشف المتوسطة", value: "92.3%", color: "safe", icon: "✓" },
                  { label: "تهديدات حرجة محددة", value: "287", color: "critical", icon: "⚠" },
                  { label: "وقت التحليل المتوسط", value: "< 2 ثانية", color: "info", icon: "⚡" },
                  { label: "مؤشرات IOC مستخرجة", value: "4,231", color: "warning", icon: "🎯" },
                  { label: "قضايا مُوثقة", value: "1,456", color: "primary", icon: "📁" },
                ].map((kpi) => (
                  <div
                    key={kpi.label}
                    className="rounded-lg border border-border/50 bg-surface-2/30 p-3 text-center"
                  >
                    <div className="text-lg mb-1">{kpi.icon}</div>
                    <div
                      className="font-mono font-bold text-sm"
                      style={{ color: `var(--${kpi.color})` }}
                    >
                      {kpi.value}
                    </div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">{kpi.label}</div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <Card delay={0.15}>
            <h3 className="font-semibold flex items-center gap-2 mb-3">
              <span className="w-1 h-4 bg-info rounded" />
              تحليل الفعالية ومقارنة الأداء
            </h3>
            <div className="text-sm text-muted-foreground leading-loose space-y-3">
              <p>
                أظهرت نتائج الاختبار أن محرك كشف التصيد الاحتيالي <strong className="text-foreground">(MOD-01)</strong> حقق
                دقة 94% على مجموعة بيانات مؤلفة من 2,847 رسالة عربية مصنفة (منها 1,891 تصيداً
                حقيقياً)، متفوقاً على أدوات مقارنة كـ SpamAssassin التي حققت 78% على نفس المجموعة
                في السياق العربي.
              </p>
              <p>
                برز أداء محرك كشف مؤشرات الاختراق <strong className="text-foreground">(MOD-06)</strong> بدقة 99% في
                استخراج IOCs من النصوص التقنية، فيما سجّل محرك تحليل الذاكرة <strong className="text-foreground">(MOD-11)</strong> أداءً
                جيداً بنسبة 88% في كشف عينيات برمجيات خبيثة حقيقية تشمل Cobalt Strike
                وMimikatz وWannaCry.
              </p>
              <p>
                يبرز التميز الأساسي لـ DFAS في <strong className="text-primary">سرعة التحليل</strong>: معالجة النصوص
                والسجلات في أقل من ثانيتين في المتصفح مباشرةً، مقارنةً بدقائق أو ساعات
                تحتاجها الأدوات التقليدية مع ضرورة التثبيت وإعداد البيئة.
              </p>
            </div>
          </Card>
        </section>

        {/* ── 7. التوصيات ──────────────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="recommendations" num="07" icon="💡" en="Recommendations" ar="التوصيات والتحسينات" />

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {RECOMMENDATIONS.map((r, i) => (
              <div
                key={r.title}
                className="glass rounded-xl p-5 animate-fade-up"
                style={{ animationDelay: `${i * 0.07}s` }}
              >
                <div className="flex items-start justify-between mb-3">
                  <span className="text-2xl">{r.icon}</span>
                  <Badge
                    label={`أولوية: ${r.priority}`}
                    color={r.priority === "عالية" ? "critical" : "warning"}
                  />
                </div>
                <h4 className="font-semibold text-sm mb-2">{r.title}</h4>
                <p className="text-xs text-muted-foreground leading-relaxed">{r.desc}</p>
              </div>
            ))}
          </div>

          <Card delay={0.2}>
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-safe rounded" />
              خارطة الطريق للتطبيق الحقيقي
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                {
                  phase: "المرحلة الأولى",
                  period: "Q3 2026",
                  color: "primary",
                  items: [
                    "دمج Claude API للتحليل الذكي",
                    "إطلاق واجهة برمجية REST",
                    "تحسين دقة محرك التصيد",
                  ],
                },
                {
                  phase: "المرحلة الثانية",
                  period: "Q4 2026",
                  color: "info",
                  items: [
                    "موصلات SIEM/SOAR",
                    "قاعدة بيانات IOCs إقليمية",
                    "تطبيق جوال React Native",
                  ],
                },
                {
                  phase: "المرحلة الثالثة",
                  period: "Q1 2027",
                  color: "safe",
                  items: [
                    "مسارات تعليمية CTF",
                    "نظام تقارير PDF تلقائي",
                    "شراكات مؤسسية",
                  ],
                },
              ].map((phase) => (
                <div
                  key={phase.phase}
                  className="rounded-lg border border-border/50 bg-surface-2/30 p-4"
                >
                  <div
                    className="font-bold text-sm mb-0.5"
                    style={{ color: `var(--${phase.color})` }}
                  >
                    {phase.phase}
                  </div>
                  <div className="text-[11px] font-mono text-muted-foreground mb-3">
                    {phase.period}
                  </div>
                  <ul className="space-y-1.5">
                    {phase.items.map((item, j) => (
                      <li key={j} className="text-xs text-muted-foreground flex items-start gap-1.5">
                        <span
                          className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ background: `var(--${phase.color})` }}
                        />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </Card>
        </section>

        {/* ── 8. الملاحق والمراجع ───────────────────────────────────────── */}
        <section className="space-y-6">
          <SectionHeader id="references" num="08" icon="📎" en="Appendices & References" ar="الملاحق والمراجع" />

          {/* Architecture diagram */}
          <Card>
            <h3 className="font-semibold flex items-center gap-2 mb-5">
              <span className="w-1 h-4 bg-primary rounded" />
              ملحق أ · مخطط معمارية النظام
            </h3>
            <div className="overflow-x-auto">
              <div className="min-w-[540px] p-4 rounded-lg bg-surface-2/30 border border-border/50 font-mono text-xs">
                <div className="text-center mb-6 text-cyan font-bold tracking-wider">
                  DFAS v3 — System Architecture
                </div>
                <div className="flex flex-col items-center gap-3">
                  {/* Browser layer */}
                  <div className="w-full max-w-lg rounded-lg border border-primary/30 bg-primary/5 p-3 text-center">
                    <div className="text-primary text-[10px] mb-2 tracking-widest">PRESENTATION LAYER · المتصفح</div>
                    <div className="flex justify-center gap-2 flex-wrap">
                      {["الرئيسية", "لوحة التحكم", "الوحدات", "القضايا", "التقرير"].map((p) => (
                        <span key={p} className="px-2 py-1 rounded bg-primary/10 text-[10px]">{p}</span>
                      ))}
                    </div>
                  </div>
                  <div className="text-muted-foreground">↕ TanStack Router</div>
                  {/* Logic layer */}
                  <div className="w-full max-w-lg rounded-lg border border-info/30 bg-info/5 p-3 text-center">
                    <div className="text-info text-[10px] mb-2 tracking-widest">ENGINE LAYER · محركات التحليل</div>
                    <div className="flex justify-center gap-2 flex-wrap">
                      {["runner.ts", "dfas-core.ts", "dfas-forensics-engines.ts"].map((f) => (
                        <span key={f} className="px-2 py-1 rounded bg-info/10 text-[10px]">{f}</span>
                      ))}
                    </div>
                  </div>
                  <div className="text-muted-foreground">↕ TypeScript Interfaces</div>
                  {/* Data layer */}
                  <div className="w-full max-w-lg rounded-lg border border-safe/30 bg-safe/5 p-3 text-center">
                    <div className="text-safe text-[10px] mb-2 tracking-widest">DATA LAYER · بيانات وقواعد الكشف</div>
                    <div className="flex justify-center gap-2 flex-wrap">
                      {["dfas-data.ts", "types.ts", "*-raw.js"].map((f) => (
                        <span key={f} className="px-2 py-1 rounded bg-safe/10 text-[10px]">{f}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Source code stats */}
          <Card delay={0.08}>
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-info rounded" />
              ملحق ب · إحصاءات الكود المصدري
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: "إجمالي الأسطر", value: "~15,000", color: "primary" },
                { label: "ملفات TypeScript", value: "22 ملف", color: "info" },
                { label: "مكونات React", value: "50 مكون", color: "cyan" },
                { label: "قواعد الكشف", value: "200+ قاعدة", color: "warning" },
                { label: "اختبارات E2E", value: "47 اختباراً", color: "safe" },
                { label: "مسارات التطبيق", value: "7 مسارات", color: "primary" },
                { label: "محركات التحليل", value: "14 محرك", color: "critical" },
                { label: "تغطية الاختبار", value: "> 85%", color: "safe" },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="rounded-lg border border-border/50 bg-surface-2/30 p-3 text-center"
                >
                  <div
                    className="font-mono font-bold text-lg"
                    style={{ color: `var(--${stat.color})` }}
                  >
                    {stat.value}
                  </div>
                  <div className="text-[11px] text-muted-foreground mt-0.5">{stat.label}</div>
                </div>
              ))}
            </div>
          </Card>

          {/* References */}
          <Card delay={0.12}>
            <h3 className="font-semibold flex items-center gap-2 mb-5">
              <span className="w-1 h-4 bg-warning rounded" />
              ملحق ج · المراجع العلمية والمصادر
            </h3>
            <div className="space-y-3">
              {REFERENCES.map((ref) => (
                <div
                  key={ref.id}
                  className="flex items-start gap-4 p-3 rounded-lg border border-border/50 bg-surface-2/20 hover:border-primary/20 transition"
                >
                  <span className="font-mono text-[10px] text-cyan bg-cyan/10 px-2 py-1 rounded shrink-0 mt-0.5">
                    [{ref.id}]
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium leading-snug">{ref.title}</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      <span>{ref.authors}</span>
                      <span className="mx-2 opacity-50">·</span>
                      <span className="text-warning font-mono">{ref.year}</span>
                      <span className="mx-2 opacity-50">·</span>
                      <span className="italic">{ref.pub}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Standards compliance */}
          <Card delay={0.16}>
            <h3 className="font-semibold flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-safe rounded" />
              ملحق د · جدول الامتثال للمعايير الدولية
            </h3>
            <div className="overflow-x-auto -mx-2">
              <table className="w-full text-sm min-w-[500px]">
                <thead className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr className="border-b border-border">
                    <th className="text-right font-medium px-3 py-2.5">المعيار</th>
                    <th className="text-right font-medium px-3 py-2.5">الوصف</th>
                    <th className="text-right font-medium px-3 py-2.5">مستوى الامتثال</th>
                    <th className="text-right font-medium px-3 py-2.5">الوحدات المعنية</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    {
                      std: "ISO/IEC 27037:2012",
                      desc: "جمع وحفظ الأدلة الرقمية",
                      level: "كامل",
                      color: "safe",
                      mods: "جميع الوحدات",
                    },
                    {
                      std: "NIST SP 800-86",
                      desc: "إطار التحقيق الجنائي",
                      level: "كامل",
                      color: "safe",
                      mods: "MOD-01 إلى MOD-14",
                    },
                    {
                      std: "MITRE ATT&CK v15",
                      desc: "تصنيف التهديدات والتقنيات",
                      level: "كامل",
                      color: "safe",
                      mods: "MOD-10, MOD-11, MOD-14",
                    },
                    {
                      std: "RFC 3227",
                      desc: "إرشادات جمع الأدلة",
                      level: "جزئي",
                      color: "warning",
                      mods: "MOD-08, MOD-09",
                    },
                    {
                      std: "OWASP Top 10",
                      desc: "أمان تطبيقات الويب",
                      level: "كامل",
                      color: "safe",
                      mods: "البنية التحتية للتطبيق",
                    },
                  ].map((row) => (
                    <tr key={row.std} className="border-b border-border/50 hover:bg-surface-2/30 transition">
                      <td className="px-3 py-3 font-mono text-cyan text-xs font-bold">{row.std}</td>
                      <td className="px-3 py-3 text-xs text-muted-foreground">{row.desc}</td>
                      <td className="px-3 py-3">
                        <Badge label={row.level} color={row.color} />
                      </td>
                      <td className="px-3 py-3 text-xs text-muted-foreground">{row.mods}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </section>

        {/* Footer */}
        <div className="text-center text-[11px] text-muted-foreground font-mono pt-4 border-t border-border">
          DFAS v3.0.0 · تقرير المشروع · ISO/IEC 27037 · NIST 800-86 · TLP:AMBER · © 2026
        </div>
      </div>
    </div>
  );
}
