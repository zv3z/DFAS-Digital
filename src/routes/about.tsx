import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/about")({
  head: () => ({
    meta: [
      { title: "DFAS · حول النظام" },
      {
        name: "description",
        content: "نظام DFAS مبني وفق معايير ISO/IEC 27037 و NIST 800-86 و RFC 3227.",
      },
      { property: "og:title", content: "DFAS · حول النظام" },
      {
        property: "og:description",
        content: "معلومات المشروع، المطوّر، والامتثال للمعايير الدولية.",
      },
    ],
  }),
  component: About,
});

const STANDARDS = [
  {
    code: "ISO/IEC 27037:2012",
    title: "إرشادات التعامل مع الأدلة الرقمية",
    desc: "تحديد، تجميع، اقتناء، والمحافظة على الأدلة الرقمية.",
  },
  {
    code: "NIST SP 800-86",
    title: "دليل دمج الطب الشرعي الرقمي",
    desc: "إطار عمل أمريكي شامل للتحقيق الجنائي الرقمي.",
  },
  {
    code: "RFC 3227",
    title: "Guidelines for Evidence Collection",
    desc: "المعيار العالمي لجمع الأدلة وأرشفتها بطريقة سليمة.",
  },
];

function About() {
  return (
    <div className="px-6 lg:px-12 py-10 max-w-5xl mx-auto space-y-6">
      <div>
        <div className="text-xs font-mono text-cyan tracking-widest">ABOUT · DFAS</div>
        <h1 className="text-3xl lg:text-4xl font-bold mt-1 glow-text-cyan">حول النظام</h1>
        <p className="text-sm text-muted-foreground mt-2 max-w-2xl">
          DFAS v3 منصة احترافية للتحليل الجنائي الرقمي مُصمّمة لخدمة المحققين السيبرانيين والباحثين
          والطلاب في العالم العربي.
        </p>
      </div>

      {/* TLP notice */}
      <div
        className="glass rounded-xl p-5 border-warning/40 flex items-start gap-4 animate-fade-up"
        style={{ boxShadow: "0 0 24px oklch(0.78 0.16 75 / 0.2)" }}
      >
        <div className="w-12 h-12 rounded-lg bg-warning/15 text-warning grid place-items-center text-2xl">
          ⚠
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded bg-warning/20 text-warning text-[10px] font-mono font-bold">
              TLP:AMBER
            </span>
            <span className="text-xs text-muted-foreground font-mono">Limited Disclosure</span>
          </div>
          <p className="text-sm">
            المخرجات والتقارير الناتجة عن النظام مصنّفة{" "}
            <strong className="text-warning">TLP:AMBER</strong>؛ يجوز مشاركتها فقط مع الأطراف
            المعنية بحدود الضرورة.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Project */}
        <div className="glass rounded-xl p-6 animate-fade-up">
          <h2 className="font-bold text-lg flex items-center gap-2">
            <span className="w-1 h-5 bg-primary rounded glow-cyan" /> المشروع
          </h2>
          <dl className="mt-4 space-y-3 text-sm">
            <Row k="الاسم" v="DFAS — Digital Forensics Analysis System" />
            <Row k="الإصدار" v="v3.0.0" />
            <Row k="اللغة" v="العربية (RTL) · الإنجليزية" />
            <Row k="الترخيص" v="MIT · Educational" />
            <Row k="المحرّك" v="DFAS Engine v3 · 14 محرك" />
          </dl>
        </div>

        {/* Developer */}
        <div className="glass rounded-xl p-6 animate-fade-up" style={{ animationDelay: ".05s" }}>
          <h2 className="font-bold text-lg flex items-center gap-2">
            <span className="w-1 h-5 bg-primary rounded glow-cyan" /> فريق التطوير
          </h2>
          <div className="mt-4 flex items-center gap-4">
            <div className="w-14 h-14 rounded-full bg-linear-to-br from-primary to-info grid place-items-center font-mono font-bold text-xl glow-cyan">
              DF
            </div>
            <div>
              <div className="font-semibold">فريق DFAS</div>
              <div className="text-xs text-muted-foreground font-mono">research@dfas.local</div>
            </div>
          </div>
          <p className="text-xs text-muted-foreground mt-4 leading-relaxed">
            باحثون ومطوّرون متخصصون في الأمن السيبراني، التحقيق الرقمي، وتطوير أدوات التحليل
            المتقدمة.
          </p>
        </div>
      </div>

      {/* Standards */}
      <div className="glass rounded-xl p-6 animate-fade-up" style={{ animationDelay: ".1s" }}>
        <h2 className="font-bold text-lg flex items-center gap-2">
          <span className="w-1 h-5 bg-primary rounded glow-cyan" /> الامتثال للمعايير الدولية
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
          {STANDARDS.map((s) => (
            <div
              key={s.code}
              className="rounded-lg border border-border bg-surface-2/50 p-4 hover:border-primary/40 transition"
            >
              <div className="text-[10px] font-mono text-cyan tracking-wider">{s.code}</div>
              <div className="font-semibold mt-1.5 text-sm">{s.title}</div>
              <div className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{s.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="text-center text-[11px] text-muted-foreground font-mono pt-4">
        DFAS · Made for Arab cybersecurity analysts · © 2026
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between border-b border-border/50 pb-2 last:border-0">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="font-mono text-cyan text-xs" dir="ltr">
        {v}
      </dd>
    </div>
  );
}
