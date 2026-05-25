import { createFileRoute, Link } from "@tanstack/react-router";
import { MODULES } from "@/lib/dfas-data";

export const Route = createFileRoute("/modules/")({
  head: () => ({
    meta: [
      { title: "DFAS · وحدات التحليل" },
      { name: "description", content: "10 وحدات تحليل جنائي متخصصة لكشف التهديدات السيبرانية." },
      { property: "og:title", content: "DFAS · وحدات التحليل" },
      { property: "og:description", content: "تصيد، روابط، صور، ترويسات، بصمة، IOC، إخفاء، خط زمني، شبكة، MITRE." },
    ],
  }),
  component: ModulesIndex,
});

function ModulesIndex() {
  return (
    <div className="px-6 lg:px-12 py-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <div className="text-xs font-mono text-cyan tracking-widest">FORENSICS · TOOLKIT</div>
        <h1 className="text-2xl lg:text-3xl font-bold mt-1">وحدات التحليل</h1>
        <p className="text-sm text-muted-foreground mt-1">عشر وحدات متخصصة تغطي طيف التحقيق الجنائي الرقمي.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {MODULES.map((m, i) => (
          <Link
            key={m.id}
            to="/modules/$slug"
            params={{ slug: m.slug }}
            className="group glass glass-hover rounded-xl p-6 relative overflow-hidden animate-fade-up"
            style={{ animationDelay: `${i*0.04}s` }}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="w-12 h-12 rounded-lg bg-surface-2 grid place-items-center text-2xl glow-border">{m.icon}</div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/30">{m.code}</span>
            </div>
            <h3 className="font-bold text-lg">{m.nameAr}</h3>
            <p className="mt-2 text-sm text-muted-foreground leading-relaxed">{m.descAr}</p>
            <div className="mt-5 flex items-center justify-between text-sm">
              <span className="text-cyan font-medium">بدء التحليل</span>
              <span className="text-cyan transition-transform group-hover:-translate-x-1">←</span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
