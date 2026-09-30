import { AlertOctagon, AlertTriangle, CheckCircle2, Info, Loader2, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { SEV_COLOR } from "../lib/format";

export function Panel({ title, right, children, className = "", bodyClass = "p-4" }: {
  title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string;
}) {
  return (
    <section className={`panel flex flex-col min-w-0 ${className}`}>
      {(title || right) && (
        <header className="flex items-center justify-between gap-3 px-4 pt-3 pb-2 border-b border-ink-700/70">
          <h2 className="panel-title">{title}</h2>
          {right}
        </header>
      )}
      <div className={`flex-1 min-h-0 ${bodyClass}`}>{children}</div>
    </section>
  );
}

const SEV_ICON: Record<string, typeof Info> = {
  LOW: CheckCircle2, MEDIUM: Info, HIGH: AlertTriangle, CRITICAL: AlertOctagon,
};

export function SeverityBadge({ severity, large = false }: { severity: string; large?: boolean }) {
  const color = SEV_COLOR[severity] ?? "#8a9bab";
  const Icon = SEV_ICON[severity] ?? Info;
  return (
    <span className={`chip ${large ? "text-sm px-2.5 py-1" : ""}`}
          style={{ color, borderColor: `${color}66`, backgroundColor: `${color}1a` }}>
      <Icon size={large ? 15 : 12} /> {severity}
    </span>
  );
}

const STATUS_STYLE: Record<string, string> = {
  NEW: "text-sky-300 border-sky-400/40 bg-sky-400/10",
  INVESTIGATING: "text-violet-300 border-violet-400/40 bg-violet-400/10",
  HOLD: "text-amber-300 border-amber-400/40 bg-amber-400/10",
  RESOLVED: "text-fg-muted border-ink-600 bg-ink-800",
  FALSE_POSITIVE: "text-emerald-300 border-emerald-400/40 bg-emerald-400/10",
  CONFIRMED_FRAUD: "text-rose-300 border-rose-400/40 bg-rose-400/10",
};

export function StatusBadge({ status }: { status: string }) {
  return <span className={`chip ${STATUS_STYLE[status] ?? "text-fg-muted border-ink-600"}`}>{status.replace(/_/g, " ")}</span>;
}

export function PolicyBadge({ label }: { label: string }) {
  return (
    <span className="chip text-accent border-accent/40 bg-accent/10">
      <ShieldAlert size={12} /> {label}
    </span>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-fg-muted text-sm">
      <Loader2 className="animate-spin" size={16} /> {label}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 py-8 text-sm text-rose-300">
      <AlertTriangle size={18} />
      <span className="text-center max-w-md">{error}</span>
      {onRetry && <button className="btn-ghost" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-fg-dim">{children}</div>;
}

export function ScoreBar({ value, color, height = 6 }: { value: number; color?: string; height?: number }) {
  const v = Math.max(0, Math.min(1, value));
  return (
    <div className="w-full rounded-full bg-ink-700/70 overflow-hidden" style={{ height }}>
      <div className="h-full rounded-full transition-all duration-700 ease-out"
           style={{ width: `${v * 100}%`, backgroundColor: color ?? "#2dd4bf" }} />
    </div>
  );
}

export function SimBanner({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`flex items-center justify-center gap-2 bg-amber-400/10 border-y border-amber-400/30 text-amber-200 font-semibold tracking-wide ${compact ? "text-[11px] py-1" : "text-xs py-1.5"}`}>
      <AlertTriangle size={13} /> SIMULATED DATA — NO REAL BANK INCIDENT
      <span className="hidden md:inline font-normal text-amber-200/70">· SBI, HDFC Bank and ICICI Bank appear only as fictional demo entities</span>
    </div>
  );
}
