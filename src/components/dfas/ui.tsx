import { useEffect, useRef, useState } from "react";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const SEV_MAP: Record<Severity, { bg: string; text: string; border: string; label: string }> = {
  CRITICAL: {
    bg: "bg-critical/15",
    text: "text-critical",
    border: "border-critical/40",
    label: "حرج",
  },
  HIGH: { bg: "bg-high/15", text: "text-high", border: "border-high/40", label: "مرتفع" },
  MEDIUM: {
    bg: "bg-warning/15",
    text: "text-warning",
    border: "border-warning/40",
    label: "متوسط",
  },
  LOW: { bg: "bg-info/15", text: "text-info", border: "border-info/40", label: "منخفض" },
  INFO: {
    bg: "bg-muted",
    text: "text-muted-foreground",
    border: "border-border",
    label: "معلوماتي",
  },
};

export function SeverityBadge({ level, pulse }: { level: Severity; pulse?: boolean }) {
  const s = SEV_MAP[level];
  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono font-semibold tracking-wider uppercase",
        s.bg,
        s.text,
        s.border,
        pulse && level === "CRITICAL" ? "animate-pulse-critical" : "",
      ].join(" ")}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {level} · {s.label}
    </span>
  );
}

export function useCounter(target: number, duration = 1200) {
  const [v, setV] = useState(0);
  const startRef = useRef<number | null>(null);
  useEffect(() => {
    let raf = 0;
    const step = (t: number) => {
      if (startRef.current === null) startRef.current = t;
      const p = Math.min(1, (t - startRef.current) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setV(Math.round(target * eased));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return v;
}

export function Counter({ value, suffix }: { value: number; suffix?: string }) {
  const v = useCounter(value);
  return (
    <span className="font-mono tabular-nums">
      {v.toLocaleString("en")}
      {suffix}
    </span>
  );
}

export function RiskGauge({ value, size = 180 }: { value: number; size?: number }) {
  const [v, setV] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setV(value));
    return () => cancelAnimationFrame(id);
  }, [value]);
  const r = (size - 24) / 2;
  const c = 2 * Math.PI * r;
  const dash = c * 0.75; // 270deg arc
  const offset = dash * (1 - v / 100);

  const color =
    v >= 86
      ? "var(--critical)"
      : v >= 71
        ? "var(--high)"
        : v >= 51
          ? "var(--warning)"
          : v >= 26
            ? "var(--info)"
            : "var(--safe)";
  const label = v >= 86 ? "حرج" : v >= 71 ? "مرتفع" : v >= 51 ? "متوسط" : v >= 26 ? "منخفض" : "آمن";

  return (
    <div className="relative inline-grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-[135deg]">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="oklch(0.28 0.025 248)"
          strokeWidth="10"
          strokeDasharray={`${dash} ${c}`}
          strokeLinecap="round"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${dash} ${c}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{
            transition: "stroke-dashoffset 1.2s cubic-bezier(.2,.8,.2,1), stroke .3s",
            filter: `drop-shadow(0 0 8px ${color})`,
          }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="font-mono text-3xl font-bold" style={{ color }}>
            {Math.round(v)}
            <span className="text-base">%</span>
          </div>
          <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground mt-1">
            {label}
          </div>
        </div>
      </div>
    </div>
  );
}

export function Sparkline({ data, color = "var(--cyan)" }: { data: number[]; color?: string }) {
  const w = 80,
    h = 24;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const pts = data
    .map((d, i) => `${(i / (data.length - 1)) * w},${h - ((d - min) / range) * h}`)
    .join(" ");
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline fill="none" stroke={color} strokeWidth="1.5" points={pts} />
    </svg>
  );
}
