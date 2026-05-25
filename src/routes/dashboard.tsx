import { createFileRoute } from "@tanstack/react-router";
import { Counter, SeverityBadge, Sparkline, type Severity } from "@/components/dfas/ui";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "DFAS · لوحة التحكم" },
      { name: "description", content: "نظرة شاملة على حالة التحاليل، التهديدات، والقضايا النشطة." },
      { property: "og:title", content: "DFAS · لوحة التحكم" },
      { property: "og:description", content: "مؤشرات أداء حية لمركز عمليات الأمن السيبراني." },
    ],
  }),
  component: Dashboard,
});

const METRICS = [
  { label: "إجمالي التحاليل", value: 12847, hue: "cyan",     trend: [12,18,14,22,28,24,32], delta: "+12.4%" },
  { label: "تهديدات حرجة",   value: 287,   hue: "critical", trend: [4,6,3,8,12,9,14],     delta: "+5.1%" },
  { label: "قضايا نشطة",     value: 47,    hue: "warning",  trend: [3,3,5,4,6,5,7],       delta: "+2"     },
  { label: "ملفات نظيفة",    value: 9241,  hue: "safe",     trend: [40,42,48,55,52,60,68], delta: "+18%"  },
];

const RECENT: { id: string; name: string; mod: string; sev: Severity; time: string }[] = [
  { id: "CASE-2419", name: "phish_invoice_q3.eml",  mod: "MOD-04", sev: "CRITICAL", time: "منذ دقيقتين" },
  { id: "CASE-2418", name: "screenshot_alpha.png",  mod: "MOD-07", sev: "HIGH",     time: "منذ 14 دقيقة" },
  { id: "CASE-2417", name: "access_log_0925",       mod: "MOD-09", sev: "MEDIUM",   time: "منذ 38 دقيقة" },
  { id: "CASE-2416", name: "vendor-portal.url",     mod: "MOD-02", sev: "LOW",      time: "منذ ساعة" },
  { id: "CASE-2415", name: "incident_notes.txt",    mod: "MOD-06", sev: "INFO",     time: "منذ 3 ساعات" },
  { id: "CASE-2414", name: "binary_dropped.bin",    mod: "MOD-05", sev: "CRITICAL", time: "منذ 5 ساعات" },
];

// Donut chart
function Donut() {
  const segs = [
    { label: "حرج",   value: 18, color: "var(--critical)" },
    { label: "تحذير", value: 32, color: "var(--warning)" },
    { label: "آمن",   value: 50, color: "var(--safe)" },
  ];
  const total = segs.reduce((a, b) => a + b.value, 0);
  const r = 64, c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <div className="flex items-center gap-6">
      <svg width={160} height={160} className="-rotate-90">
        <circle cx={80} cy={80} r={r} fill="none" stroke="oklch(0.22 0.025 248)" strokeWidth={18} />
        {segs.map((s) => {
          const len = (s.value / total) * c;
          const el = (
            <circle key={s.label} cx={80} cy={80} r={r} fill="none" stroke={s.color}
              strokeWidth={18} strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-acc}
              style={{ filter: `drop-shadow(0 0 6px ${s.color})`, transition: "stroke-dasharray 1s" }} />
          );
          acc += len;
          return el;
        })}
      </svg>
      <div className="space-y-2.5">
        {segs.map((s) => (
          <div key={s.label} className="flex items-center gap-3 text-sm">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: s.color, boxShadow: `0 0 8px ${s.color}` }} />
            <span className="text-muted-foreground">{s.label}</span>
            <span className="font-mono mr-auto pl-3">{s.value}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Stacked bars
function StackedBars() {
  const days = ["السبت","الأحد","الإثنين","الثلاثاء","الأربعاء","الخميس","الجمعة"];
  const data = [
    { c: 4, w: 12, s: 28 },
    { c: 7, w: 18, s: 22 },
    { c: 3, w: 14, s: 36 },
    { c: 9, w: 24, s: 18 },
    { c: 12, w: 20, s: 26 },
    { c: 6, w: 16, s: 32 },
    { c: 14, w: 22, s: 30 },
  ];
  const max = Math.max(...data.map(d => d.c + d.w + d.s));
  return (
    <div>
      <div className="flex items-end gap-3 h-48">
        {data.map((d, i) => {
          const total = d.c + d.w + d.s;
          const h = (total / max) * 100;
          return (
            <div key={i} className="flex-1 flex flex-col items-center gap-1.5">
              <div className="text-[10px] font-mono text-muted-foreground">{total}</div>
              <div className="w-full rounded-md overflow-hidden bg-surface-2 flex flex-col justify-end" style={{ height: `${h}%` }}>
                <div style={{ height: `${(d.s/total)*100}%`, background: "var(--safe)" }} />
                <div style={{ height: `${(d.w/total)*100}%`, background: "var(--warning)" }} />
                <div style={{ height: `${(d.c/total)*100}%`, background: "var(--critical)", boxShadow: "0 0 8px var(--critical)" }} />
              </div>
              <div className="text-[10px] text-muted-foreground">{days[i].slice(0,3)}</div>
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-4 mt-4 text-xs">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-critical" />حرج</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-warning" />تحذير</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-safe" />آمن</span>
      </div>
    </div>
  );
}

function Dashboard() {
  return (
    <div className="px-6 lg:px-12 py-8 max-w-7xl mx-auto space-y-6">
      <div>
        <div className="text-xs font-mono text-cyan tracking-widest">OPERATIONS · CENTER</div>
        <h1 className="text-2xl lg:text-3xl font-bold mt-1">لوحة التحكم</h1>
        <p className="text-sm text-muted-foreground mt-1">نظرة حيّة على نشاط التحليل وحالة التهديدات.</p>
      </div>

      {/* METRICS */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {METRICS.map((m, i) => (
          <div key={m.label} className="glass glass-hover rounded-xl p-5 animate-fade-up" style={{ animationDelay: `${i*0.06}s` }}>
            <div className="flex items-start justify-between">
              <div className="text-[11px] text-muted-foreground uppercase tracking-wider">{m.label}</div>
              <Sparkline data={m.trend} color={`var(--${m.hue})`} />
            </div>
            <div className={`mt-3 text-3xl font-bold text-${m.hue}`}><Counter value={m.value} /></div>
            <div className="mt-1 text-xs text-muted-foreground font-mono">{m.delta} عن الأسبوع الماضي</div>
          </div>
        ))}
      </div>

      {/* CHARTS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass rounded-xl p-6 animate-fade-up">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">توزيع التهديدات</h3>
            <span className="text-[10px] font-mono text-muted-foreground">آخر 30 يوماً</span>
          </div>
          <Donut />
        </div>
        <div className="glass rounded-xl p-6 lg:col-span-2 animate-fade-up" style={{ animationDelay: ".1s" }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">النشاط اليومي</h3>
            <span className="text-[10px] font-mono text-muted-foreground">آخر 7 أيام</span>
          </div>
          <StackedBars />
        </div>
      </div>

      {/* RECENT TABLE */}
      <div className="glass rounded-xl p-6 animate-fade-up" style={{ animationDelay: ".15s" }}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">آخر التحاليل</h3>
          <button className="text-xs text-cyan hover:underline">عرض الكل</button>
        </div>
        <div className="overflow-x-auto -mx-2">
          <table className="w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr className="border-b border-border">
                <th className="text-right font-medium px-2 py-3">معرّف</th>
                <th className="text-right font-medium px-2 py-3">الملف / المدخل</th>
                <th className="text-right font-medium px-2 py-3">الوحدة</th>
                <th className="text-right font-medium px-2 py-3">الخطورة</th>
                <th className="text-right font-medium px-2 py-3">الوقت</th>
              </tr>
            </thead>
            <tbody>
              {RECENT.map((r) => (
                <tr key={r.id} className="border-b border-border/50 hover:bg-surface-2/40 transition">
                  <td className="px-2 py-3 font-mono text-cyan text-xs">{r.id}</td>
                  <td className="px-2 py-3 font-mono text-xs">{r.name}</td>
                  <td className="px-2 py-3 text-xs"><span className="px-2 py-0.5 rounded bg-surface-2 font-mono">{r.mod}</span></td>
                  <td className="px-2 py-3"><SeverityBadge level={r.sev} pulse /></td>
                  <td className="px-2 py-3 text-xs text-muted-foreground">{r.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
