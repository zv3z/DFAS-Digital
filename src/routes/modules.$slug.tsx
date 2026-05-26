import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { useState, useRef } from "react";
import { MODULES, type ModuleDef } from "@/lib/dfas-data";
import { RiskGauge, SeverityBadge, type Severity } from "@/components/dfas/ui";
import { runEngine, SAMPLES, type AnalysisResult, type FindingItem } from "@/engines/runner";

export const Route = createFileRoute("/modules/$slug")({
  loader: ({ params }) => {
    const mod = MODULES.find((m) => m.slug === params.slug);
    if (!mod) throw notFound();
    return { mod };
  },
  head: ({ loaderData }) => ({
    meta: loaderData?.mod
      ? [
          { title: `DFAS · ${loaderData.mod.nameAr}` },
          { name: "description", content: loaderData.mod.descAr },
        ]
      : [{ title: "DFAS · وحدة" }],
  }),
  notFoundComponent: () => (
    <div className="px-6 py-20 text-center">
      <div className="font-mono text-cyan text-xs">MOD · NOT_FOUND</div>
      <h1 className="text-3xl font-bold mt-2">الوحدة غير موجودة</h1>
      <Link
        to="/modules"
        className="inline-flex mt-6 px-4 py-2 rounded-lg bg-primary text-primary-foreground"
      >
        عودة للوحدات
      </Link>
    </div>
  ),
  component: ModulePage,
});

type Phase = "idle" | "running" | "done";

function ModulePage() {
  const { mod } = Route.useLoaderData();
  return <ModuleView mod={mod} />;
}

const STEPS = [
  "تحقّق من المدخل",
  "استخراج المؤشرات",
  "مقارنة قواعد البيانات",
  "تقييم المخاطر",
  "توليد التقرير",
];

function ModuleView({ mod }: { mod: ModuleDef }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [step, setStep] = useState(0);
  const [fileName, setFileName] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<File | null>(null);

  function loadSample() {
    const sample = SAMPLES[mod.slug];
    if (sample) setInput(sample);
  }

  async function analyze() {
    const isImageDemo = (mod.slug === "image" || mod.slug === "stego") && !fileRef.current;
    if (!input.trim() && !fileRef.current && !isImageDemo) return;
    setPhase("running");
    setStep(0);
    setError(null);
    setResult(null);

    // Animate steps
    let i = 0;
    const stepTimer = setInterval(() => {
      i++;
      setStep(i);
      if (i >= STEPS.length) clearInterval(stepTimer);
    }, 450);

    try {
      const res = await runEngine(mod.slug, input, fileRef.current);
      // Wait for animation to finish
      await new Promise((r) => setTimeout(r, STEPS.length * 450 + 200));
      setResult(res);
      setPhase("done");
    } catch (e) {
      clearInterval(stepTimer);
      setError(e instanceof Error ? e.message : "حدث خطأ أثناء التحليل");
      setPhase("idle");
    }
  }

  function reset() {
    setPhase("idle");
    setInput("");
    setFileName(null);
    setResult(null);
    setError(null);
    fileRef.current = null;
  }

  return (
    <div className="px-6 lg:px-12 py-8 max-w-7xl mx-auto space-y-6">
      {/* ── Header ── */}
      <div className="glass rounded-xl p-6 flex items-start gap-4 animate-fade-up relative overflow-hidden">
        <div className="absolute -top-10 -left-10 w-40 h-40 rounded-full bg-primary/20 blur-3xl" />
        <div className="w-14 h-14 rounded-lg bg-surface-2 grid place-items-center text-3xl glow-border shrink-0">
          {mod.icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/30">
              {mod.code}
            </span>
            <span className="text-[10px] font-mono text-muted-foreground">
              FORENSIC · MODULE · LIVE ENGINE
            </span>
          </div>
          <h1 className="text-2xl font-bold mt-2">{mod.nameAr}</h1>
          <p className="text-sm text-muted-foreground mt-1">{mod.descAr}</p>
        </div>
        <Link
          to="/modules"
          className="hidden sm:inline-flex text-xs text-muted-foreground hover:text-foreground"
        >
          → الوحدات
        </Link>
      </div>

      {/* ── Input ── */}
      <div className="glass rounded-xl p-6 animate-fade-up" style={{ animationDelay: ".05s" }}>
        <h2 className="font-semibold mb-4 flex items-center gap-2">
          <span className="w-1 h-4 bg-primary rounded glow-cyan" />
          المدخلات
        </h2>

        {(mod.inputType === "text" || mod.inputType === "headers" || mod.inputType === "url") && (
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={mod.placeholder}
            rows={mod.inputType === "url" ? 2 : 7}
            className="w-full bg-surface-2 border border-border rounded-lg p-4 text-sm font-mono focus:outline-none focus:border-primary transition resize-none"
            dir={mod.inputType === "url" ? "ltr" : "auto"}
          />
        )}

        {(mod.inputType === "image" || mod.inputType === "file" || mod.inputType === "log") && (
          <label className="block">
            <input
              type="file"
              className="hidden"
              accept={mod.inputType === "image" ? "image/*" : undefined}
              onChange={(e) => {
                const f = e.target.files?.[0] ?? null;
                fileRef.current = f;
                setFileName(f?.name ?? null);
                setInput(f?.name ?? "");
              }}
            />
            <div className="border-2 border-dashed border-border rounded-lg p-10 text-center cursor-pointer hover:border-primary hover:bg-primary/5 transition group">
              <div className="text-4xl mb-3 opacity-70 group-hover:scale-110 transition">⤓</div>
              <div className="font-medium">{fileName ?? "اسحب الملف هنا أو انقر للرفع"}</div>
              <div className="text-xs text-muted-foreground mt-1.5">
                {mod.inputType === "image"
                  ? "PNG, JPG, WEBP حتى 20MB"
                  : mod.inputType === "log"
                    ? "access.log, error.log, syslog"
                    : "أي ملف ثنائي أو نصي"}
              </div>
            </div>
          </label>
        )}

        <div className="mt-5 flex items-center gap-3 flex-wrap">
          <button
            onClick={analyze}
            disabled={
              phase === "running" ||
              (!input.trim() && !fileRef.current && mod.inputType !== "image")
            }
            className="px-6 py-2.5 rounded-lg bg-primary text-primary-foreground font-semibold glow-cyan hover:scale-[1.02] transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {phase === "running" ? "جاري التحليل…" : "▶ تشغيل التحليل"}
          </button>
          {SAMPLES[mod.slug] && (
            <button
              onClick={loadSample}
              className="px-4 py-2.5 rounded-lg border border-primary/30 text-primary text-sm hover:bg-primary/10 transition"
            >
              ← تحميل مثال
            </button>
          )}
          {(mod.slug === "image" || mod.slug === "stego") && !fileRef.current && (
            <button
              onClick={analyze}
              disabled={phase === "running"}
              className="px-4 py-2.5 rounded-lg border border-warning/40 text-warning text-sm hover:bg-warning/10 transition"
            >
              ⚗ تحليل نموذجي
            </button>
          )}
          <button
            onClick={reset}
            className="px-4 py-2.5 rounded-lg border border-border text-sm hover:bg-surface-2 transition"
          >
            إعادة تعيين
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
            {error}
          </div>
        )}

        {phase !== "idle" && (
          <div className="mt-5 space-y-2">
            <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden">
              <div
                className="h-full bg-linear-to-l from-primary to-info transition-all duration-500"
                style={{ width: `${(step / STEPS.length) * 100}%` }}
              />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-[11px]">
              {STEPS.map((s, i) => (
                <div
                  key={s}
                  className={`flex items-center gap-1.5 ${
                    i < step
                      ? "text-safe"
                      : i === step && phase === "running"
                        ? "text-cyan"
                        : "text-muted-foreground"
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-current" />
                  {s}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Results ── */}
      {phase === "done" && result && (
        <>
          {/* Verdict + Gauge */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-fade-up">
            <VerdictCard result={result} />
            <div className="glass rounded-xl p-6 flex flex-col items-center justify-center text-center">
              <div className="text-[10px] font-mono text-muted-foreground tracking-widest mb-2">
                RISK · SCORE
              </div>
              <RiskGauge value={result.pct} />
              <button
                onClick={() => exportReport(result, mod)}
                className="mt-5 w-full px-4 py-2 rounded-lg border border-border text-sm hover:bg-surface-2 transition"
              >
                ⤓ تصدير التقرير
              </button>
            </div>
          </div>

          {/* Findings */}
          {result.findings.length > 0 && (
            <div
              className="glass rounded-xl p-6 animate-fade-up"
              style={{ animationDelay: ".05s" }}
            >
              <h2 className="font-semibold mb-4 flex items-center gap-2">
                <span className="w-1 h-4 bg-primary rounded glow-cyan" />
                النتائج التفصيلية
                <span className="ml-2 text-xs font-mono text-muted-foreground">
                  {result.findings.length} مؤشر
                </span>
              </h2>
              <div className="space-y-3">
                {result.findings.map((f, i) => (
                  <FindingCard key={i} finding={f} />
                ))}
              </div>
            </div>
          )}

          {/* Metadata */}
          {result.meta.length > 0 && (
            <div className="glass rounded-xl p-6 animate-fade-up" style={{ animationDelay: ".1s" }}>
              <h2 className="font-semibold mb-4 flex items-center gap-2">
                <span className="w-1 h-4 bg-primary rounded glow-cyan" />
                البيانات التقنية
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
                {result.meta.map((m) => (
                  <div
                    key={m.k}
                    className="flex items-center justify-between py-2.5 border-b border-border/60 text-sm"
                  >
                    <span className="text-muted-foreground">{m.k}</span>
                    <span className="font-mono text-cyan text-xs" dir="ltr">
                      {m.v}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ── Sub-components ── */

function VerdictCard({ result }: { result: AnalysisResult }) {
  const level: Severity =
    result.threat === "crit" ? "CRITICAL" : result.threat === "warn" ? "HIGH" : "INFO";

  const glowClass =
    result.threat === "crit"
      ? "border-critical/40"
      : result.threat === "warn"
        ? "border-warning/40"
        : "border-safe/40";

  const gradClass =
    result.threat === "crit"
      ? "from-critical/10"
      : result.threat === "warn"
        ? "from-warning/10"
        : "from-safe/10";

  return (
    <div className={`lg:col-span-2 glass rounded-xl p-6 relative overflow-hidden ${glowClass}`}>
      <div className={`absolute inset-0 bg-linear-to-l ${gradClass} to-transparent`} />
      <div className="relative">
        <div className="flex items-center gap-2">
          <SeverityBadge level={level} pulse={result.threat === "crit"} />
          <span className="text-[10px] font-mono text-muted-foreground">VERDICT · LIVE ENGINE</span>
        </div>
        <h2 className="text-2xl font-bold mt-3">{result.verdictTitle}</h2>
        <p className="text-sm text-muted-foreground mt-2 max-w-xl">{result.verdictDesc}</p>
        <div className="mt-6 grid grid-cols-3 gap-4">
          {result.stats.map((s) => (
            <div key={s.label}>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                {s.label}
              </div>
              <div className="text-xl font-bold font-mono mt-1">{s.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: FindingItem }) {
  const [open, setOpen] = useState(false);
  const borderColor =
    finding.sev === "CRITICAL"
      ? "border-r-critical"
      : finding.sev === "HIGH"
        ? "border-r-high"
        : finding.sev === "MEDIUM"
          ? "border-r-warning"
          : finding.sev === "LOW"
            ? "border-r-info"
            : "border-r-muted-foreground";

  return (
    <div
      className={`bg-surface-2/50 rounded-lg border border-border ${borderColor} border-r-4 transition hover:bg-surface-2`}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full text-right p-4 flex items-start gap-3"
      >
        <SeverityBadge level={finding.sev as Severity} />
        <div className="flex-1">
          <div className="font-semibold text-sm">{finding.title}</div>
          <div className="text-xs text-muted-foreground mt-1">{finding.desc}</div>
        </div>
        <span
          className={`text-muted-foreground text-sm transition-transform ${open ? "rotate-90" : ""}`}
        >
          ‹
        </span>
      </button>
      {open && finding.evidence && (
        <div className="px-4 pb-4">
          <div
            className="bg-void/60 border border-border rounded p-3 font-mono text-xs text-cyan overflow-x-auto whitespace-pre-wrap"
            dir="ltr"
          >
            {finding.evidence}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Export Report ── */
function exportReport(result: AnalysisResult, mod: ModuleDef) {
  const lines = [
    `# DFAS v3 — تقرير التحليل الجنائي`,
    `## ${mod.code} · ${mod.nameAr}`,
    ``,
    `**النتيجة:** ${result.verdictTitle}`,
    `**نسبة الخطر:** ${result.pct}%`,
    ``,
    `### البيانات التقنية`,
    ...result.meta.map((m) => `- **${m.k}:** ${m.v}`),
    ``,
    `### النتائج (${result.findings.length})`,
    ...result.findings.map((f) => `#### [${f.sev}] ${f.title}\n${f.desc}\n\`${f.evidence}\``),
    ``,
    `---`,
    `TLP:AMBER · DFAS v3 · ISO/IEC 27037:2012`,
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `DFAS-Report-${mod.code}-${Date.now()}.md`;
  a.click();
}
