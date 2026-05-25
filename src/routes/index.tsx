import { createFileRoute, Link } from "@tanstack/react-router";
import { MODULES } from "@/lib/dfas-data";
import { ParticleField } from "@/components/dfas/ParticleField";
import { Counter } from "@/components/dfas/ui";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "DFAS — الرئيسية · نظام التحليل الجنائي الرقمي" },
      { name: "description", content: "DFAS v2 منصة احترافية للتحليل الجنائي الرقمي وتعليم الأمن السيبراني." },
      { property: "og:title", content: "DFAS — الرئيسية" },
      { property: "og:description", content: "10 وحدات تحليل متقدمة · معايير ISO/NIST/RFC" },
    ],
  }),
  component: Home,
});

const KPIS = [
  { label: "إجمالي التحاليل", value: 12847, hue: "cyan",     icon: "Σ" },
  { label: "تهديدات مكتشفة",  value: 1893,  hue: "critical", icon: "⚠" },
  { label: "قضايا نشطة",      value: 47,    hue: "warning",  icon: "⛬" },
  { label: "دقة النظام",      value: 99,    hue: "safe",     icon: "✓", suffix: "%" },
] as const;

function Home() {
  return (
    <div className="relative">
      {/* HERO */}
      <section className="relative overflow-hidden border-b border-border" style={{ background: "var(--grad-hero)" }}>
        <div className="absolute inset-0 opacity-60"><ParticleField /></div>

        <div className="relative px-6 lg:px-12 py-16 lg:py-24 max-w-6xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass text-[11px] font-mono mb-6 animate-fade-up">
            <span className="w-1.5 h-1.5 rounded-full bg-warning animate-pulse" />
            TLP:AMBER · CLASSIFICATION RESTRICTED
          </div>

          <h1 className="text-5xl lg:text-7xl font-bold tracking-tight glow-text-cyan animate-fade-up" style={{ animationDelay: ".05s" }}>
            DFAS <span className="font-mono text-cyan">v2</span>
          </h1>
          <p className="mt-4 text-lg lg:text-xl text-foreground/80 animate-fade-up" style={{ animationDelay: ".15s" }}>
            نظام التحليل الجنائي الرقمي
          </p>
          <p className="mt-3 max-w-2xl mx-auto text-sm lg:text-base text-muted-foreground animate-fade-up" style={{ animationDelay: ".25s" }}>
            منصة احترافية للتحقيق الرقمي وتحليل الأدلة السيبرانية، مبنية على أحدث المعايير الدولية ومخصّصة للمحللين العرب.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3 animate-fade-up" style={{ animationDelay: ".35s" }}>
            <Link to="/dashboard" className="px-6 py-3 rounded-lg bg-primary text-primary-foreground font-semibold glow-cyan hover:scale-[1.02] transition-transform">
              فتح لوحة التحكم
            </Link>
            <Link to="/modules" className="px-6 py-3 rounded-lg glass glass-hover font-semibold">
              استعراض الوحدات
            </Link>
          </div>
        </div>
      </section>

      {/* KPIs */}
      <section className="px-6 lg:px-12 py-10 max-w-7xl mx-auto">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {KPIS.map((k, i) => (
            <div key={k.label} className="glass glass-hover rounded-xl p-5 relative overflow-hidden animate-fade-up" style={{ animationDelay: `${i * 0.08}s` }}>
              <div className={`absolute -top-6 -left-6 w-24 h-24 rounded-full blur-2xl opacity-30 bg-${k.hue}`} />
              <div className="flex items-start justify-between relative">
                <div>
                  <div className="text-[11px] text-muted-foreground uppercase tracking-wider">{k.label}</div>
                  <div className={`mt-2 text-3xl font-bold text-${k.hue}`}>
                    <Counter value={k.value} suffix={(k as { suffix?: string }).suffix} />
                  </div>
                </div>
                <div className={`w-10 h-10 rounded-lg bg-${k.hue}/15 text-${k.hue} grid place-items-center text-lg`}>{k.icon}</div>
              </div>
              <div className="mt-4 h-1 bg-surface-2 rounded-full overflow-hidden">
                <div className={`h-full bg-${k.hue} animate-shimmer`} style={{ width: `${60 + i * 10}%` }} />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* MODULES GRID */}
      <section className="px-6 lg:px-12 pb-16 max-w-7xl mx-auto">
        <div className="flex items-end justify-between mb-6">
          <div>
            <div className="text-xs font-mono text-cyan tracking-widest">ANALYSIS · MODULES</div>
            <h2 className="text-2xl lg:text-3xl font-bold mt-1">وحدات التحليل</h2>
          </div>
          <Link to="/modules" className="text-sm text-cyan hover:underline">عرض الكل ←</Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {MODULES.map((m, i) => (
            <Link
              key={m.id}
              to="/modules/$slug"
              params={{ slug: m.slug }}
              className="group glass glass-hover rounded-xl p-5 relative overflow-hidden animate-fade-up"
              style={{ animationDelay: `${i * 0.05}s` }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="text-3xl">{m.icon}</div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-2 text-cyan border border-cyan/20">{m.code}</span>
              </div>
              <h3 className="font-bold leading-snug">{m.nameAr}</h3>
              <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed line-clamp-2">{m.descAr}</p>
              <div className="mt-4 flex items-center justify-between text-xs text-cyan font-medium">
                <span>بدء التحليل</span>
                <span className="transition-transform group-hover:-translate-x-1">←</span>
              </div>
              <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-l from-transparent via-primary to-transparent opacity-0 group-hover:opacity-100 transition" />
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
