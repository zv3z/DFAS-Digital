import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { SeverityBadge, type Severity } from "@/components/dfas/ui";

export const Route = createFileRoute("/cases")({
  head: () => ({
    meta: [
      { title: "DFAS · إدارة القضايا" },
      { name: "description", content: "إدارة قضايا التحقيق الجنائي الرقمي وتتبع الحالة." },
      { property: "og:title", content: "DFAS · إدارة القضايا" },
      { property: "og:description", content: "تتبع، تصفية، وتصدير القضايا الجنائية الرقمية." },
    ],
  }),
  component: CasesPage,
});

type Status = "active" | "pending" | "closed";

interface CaseRow {
  id: string;
  title: string;
  status: Status;
  date: string;
  threat: Severity;
}

const SEED: CaseRow[] = [
  {
    id: "DFAS-2026-0047",
    title: "حملة تصيد تستهدف موظفي المالية",
    status: "active",
    date: "2026-05-24",
    threat: "CRITICAL",
  },
  {
    id: "DFAS-2026-0046",
    title: "تحليل سجلات اختراق بوابة العملاء",
    status: "active",
    date: "2026-05-23",
    threat: "HIGH",
  },
  {
    id: "DFAS-2026-0045",
    title: "صور مزوّرة في تحقيق احتيال إداري",
    status: "pending",
    date: "2026-05-22",
    threat: "MEDIUM",
  },
  {
    id: "DFAS-2026-0044",
    title: "تحقيق بصمة ملف تنفيذي مشبوه",
    status: "closed",
    date: "2026-05-20",
    threat: "HIGH",
  },
  {
    id: "DFAS-2026-0043",
    title: "خط زمني لتسرّب بيانات قاعدة المستخدمين",
    status: "active",
    date: "2026-05-19",
    threat: "CRITICAL",
  },
  {
    id: "DFAS-2026-0042",
    title: "تتبع IOC مرتبط بمجموعة APT-29",
    status: "pending",
    date: "2026-05-18",
    threat: "HIGH",
  },
  {
    id: "DFAS-2026-0041",
    title: "مراجعة سجلات Apache لخادم الإنتاج",
    status: "closed",
    date: "2026-05-15",
    threat: "LOW",
  },
  {
    id: "DFAS-2026-0040",
    title: "تحقيق MITRE ATT&CK في حادثة برمجية خبيثة",
    status: "closed",
    date: "2026-05-12",
    threat: "MEDIUM",
  },
];

const STATUS_MAP: Record<Status, { ar: string; cls: string }> = {
  active: { ar: "نشطة", cls: "bg-safe/15 text-safe border-safe/30" },
  pending: { ar: "معلّقة", cls: "bg-warning/15 text-warning border-warning/30" },
  closed: { ar: "مغلقة", cls: "bg-muted text-muted-foreground border-border" },
};

let nextId = SEED.length + 1;

function genId() {
  const n = (48 - SEED.length + nextId++).toString().padStart(4, "0");
  return `DFAS-2026-${n}`;
}

function CasesPage() {
  const [cases, setCases] = useState<CaseRow[]>(SEED);
  const [filter, setFilter] = useState<"all" | Status>("all");
  const [search, setSearch] = useState("");
  const [openNew, setOpenNew] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newThreat, setNewThreat] = useState<Severity>("MEDIUM");
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const rows = cases.filter((r) => {
    const matchFilter = filter === "all" || r.status === filter;
    const matchSearch =
      !search.trim() ||
      r.title.includes(search) ||
      r.id.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  });

  function addCase() {
    if (!newTitle.trim()) return;
    const today = new Date().toISOString().slice(0, 10);
    const newCase: CaseRow = {
      id: genId(),
      title: newTitle.trim(),
      status: "active",
      date: today,
      threat: newThreat,
    };
    setCases((prev) => [newCase, ...prev]);
    setNewTitle("");
    setNewThreat("MEDIUM");
    setOpenNew(false);
  }

  function deleteCase(id: string) {
    setCases((prev) => prev.filter((r) => r.id !== id));
    setDeleteConfirm(null);
  }

  const countFor = (s: Status) => cases.filter((r) => r.status === s).length;

  return (
    <div className="px-6 lg:px-12 py-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <div className="text-xs font-mono text-cyan tracking-widest">CASE · MANAGEMENT</div>
          <h1 className="text-2xl lg:text-3xl font-bold mt-1">إدارة القضايا</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {rows.length} من أصل {cases.length} قضية
          </p>
        </div>
        <button
          onClick={() => setOpenNew(true)}
          className="px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-semibold glow-cyan hover:scale-[1.02] transition-transform"
        >
          + قضية جديدة
        </button>
      </div>

      {/* Filter bar */}
      <div className="glass rounded-xl p-4 flex flex-wrap items-center gap-2">
        {(
          [
            ["all", "الكل", cases.length],
            ["active", "نشطة", countFor("active")],
            ["pending", "معلّقة", countFor("pending")],
            ["closed", "مغلقة", countFor("closed")],
          ] as const
        ).map(([key, label, count]) => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            className={[
              "px-4 py-1.5 rounded-md text-sm border transition",
              filter === key
                ? "bg-primary/15 border-primary/50 text-primary glow-cyan"
                : "border-border text-muted-foreground hover:text-foreground",
            ].join(" ")}
          >
            {label} <span className="font-mono text-[10px] opacity-70">({count})</span>
          </button>
        ))}
        <div className="mr-auto" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="بحث في القضايا..."
          className="bg-surface-2 border border-border rounded-md px-3 py-1.5 text-sm focus:outline-none focus:border-primary w-full sm:w-56 transition"
        />
      </div>

      {/* Table */}
      <div className="glass rounded-xl p-2 sm:p-4 overflow-x-auto">
        <table className="w-full text-sm min-w-[700px]">
          <thead className="text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr className="border-b border-border">
              <th className="text-right font-medium px-3 py-3">معرّف القضية</th>
              <th className="text-right font-medium px-3 py-3">العنوان</th>
              <th className="text-right font-medium px-3 py-3">الحالة</th>
              <th className="text-right font-medium px-3 py-3">التاريخ</th>
              <th className="text-right font-medium px-3 py-3">الخطورة</th>
              <th className="text-right font-medium px-3 py-3">إجراءات</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-10 text-center text-muted-foreground text-sm">
                  لا توجد قضايا تطابق معايير البحث
                </td>
              </tr>
            )}
            {rows.map((r, i) => {
              const s = STATUS_MAP[r.status];
              return (
                <tr
                  key={r.id}
                  className="border-b border-border/40 hover:bg-surface-2/50 transition animate-fade-up"
                  style={{ animationDelay: `${i * 0.03}s` }}
                >
                  <td className="px-3 py-3 font-mono text-cyan text-xs">{r.id}</td>
                  <td className="px-3 py-3">{r.title}</td>
                  <td className="px-3 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${s.cls}`}>
                      {s.ar}
                    </span>
                  </td>
                  <td className="px-3 py-3 font-mono text-xs text-muted-foreground" dir="ltr">
                    {r.date}
                  </td>
                  <td className="px-3 py-3">
                    <SeverityBadge level={r.threat} pulse={r.threat === "CRITICAL"} />
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex items-center gap-1.5">
                      <IconBtn title="عرض">⊙</IconBtn>
                      <IconBtn title="تصدير" onClick={() => exportCase(r)}>
                        ⤓
                      </IconBtn>
                      <IconBtn title="حذف" danger onClick={() => setDeleteConfirm(r.id)}>
                        ×
                      </IconBtn>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* New Case Modal */}
      {openNew && (
        <div
          className="fixed inset-0 z-50 grid place-items-center p-4 bg-black/70 backdrop-blur-sm animate-fade-up"
          onClick={() => setOpenNew(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="glass rounded-2xl p-6 w-full max-w-md glow-border"
          >
            <h3 className="text-lg font-bold">قضية جديدة</h3>
            <p className="text-xs text-muted-foreground mt-1">
              أدخل تفاصيل القضية الأولية. يمكن تعديلها لاحقاً.
            </p>
            <div className="space-y-3 mt-5">
              <Field label="عنوان القضية">
                <input
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addCase()}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:border-primary transition"
                  placeholder="مثال: تحقيق في تصيد استهدف إدارة الموارد البشرية..."
                  autoFocus
                />
              </Field>
              <Field label="مستوى الخطورة">
                <select
                  value={newThreat}
                  onChange={(e) => setNewThreat(e.target.value as Severity)}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:border-primary transition"
                >
                  <option value="CRITICAL">CRITICAL · حرج</option>
                  <option value="HIGH">HIGH · مرتفع</option>
                  <option value="MEDIUM">MEDIUM · متوسط</option>
                  <option value="LOW">LOW · منخفض</option>
                  <option value="INFO">INFO · معلوماتي</option>
                </select>
              </Field>
            </div>
            <div className="flex justify-start gap-2 mt-5">
              <button
                onClick={addCase}
                disabled={!newTitle.trim()}
                className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold glow-cyan disabled:opacity-50 disabled:cursor-not-allowed hover:scale-[1.02] transition-transform"
              >
                إنشاء القضية
              </button>
              <button
                onClick={() => {
                  setOpenNew(false);
                  setNewTitle("");
                }}
                className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-surface-2 transition"
              >
                إلغاء
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div
          className="fixed inset-0 z-50 grid place-items-center p-4 bg-black/70 backdrop-blur-sm"
          onClick={() => setDeleteConfirm(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="glass rounded-2xl p-6 w-full max-w-sm border border-critical/30"
          >
            <div className="text-critical font-mono text-xs mb-2">CONFIRM · DELETE</div>
            <h3 className="text-lg font-bold">حذف القضية</h3>
            <p className="text-sm text-muted-foreground mt-1">
              هل أنت متأكد من حذف <span className="text-critical font-mono">{deleteConfirm}</span>؟
              لا يمكن التراجع.
            </p>
            <div className="flex justify-start gap-2 mt-5">
              <button
                onClick={() => deleteCase(deleteConfirm)}
                className="px-4 py-2 rounded-lg bg-critical/80 text-white text-sm font-semibold hover:bg-critical transition"
              >
                حذف
              </button>
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 rounded-lg border border-border text-sm hover:bg-surface-2 transition"
              >
                إلغاء
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function exportCase(r: CaseRow) {
  const lines = [
    `# DFAS v3 — بطاقة القضية`,
    `## ${r.id}`,
    ``,
    `**العنوان:** ${r.title}`,
    `**الحالة:** ${r.status}`,
    `**الخطورة:** ${r.threat}`,
    `**التاريخ:** ${r.date}`,
    ``,
    `---`,
    `TLP:AMBER · DFAS v3 · ISO/IEC 27037:2012`,
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `DFAS-Case-${r.id}-${Date.now()}.md`;
  a.click();
}

function IconBtn({
  children,
  danger,
  title,
  onClick,
}: {
  children: React.ReactNode;
  danger?: boolean;
  title: string;
  onClick?: () => void;
}) {
  return (
    <button
      title={title}
      onClick={onClick}
      className={`w-8 h-8 rounded-md grid place-items-center text-sm border border-border transition ${
        danger
          ? "hover:bg-critical/15 hover:text-critical hover:border-critical/40"
          : "hover:bg-primary/10 hover:text-primary hover:border-primary/40"
      }`}
    >
      {children}
    </button>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="text-xs text-muted-foreground mb-1.5">{label}</div>
      {children}
    </label>
  );
}
