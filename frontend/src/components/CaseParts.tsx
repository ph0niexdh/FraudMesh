import { useState } from "react";
import { Ban, Check, CheckCircle2, Gavel, KeyRound, PauseCircle, ShieldCheck } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { post } from "../api/client";
import type { CaseDetail, Explanation } from "../api/types";
import { time } from "../lib/format";

/** Pick evidence round-robin across channels so every correlated channel is represented. */
function diverse(items: Explanation[], limit: number): Explanation[] {
  const byChannel = new Map<string, Explanation[]>();
  for (const it of items) byChannel.set(it.channel, [...(byChannel.get(it.channel) ?? []), it]);
  const out: Explanation[] = [];
  while (out.length < limit && [...byChannel.values()].some((l) => l.length)) {
    for (const list of byChannel.values()) {
      const next = list.shift();
      if (next && out.length < limit) out.push(next);
    }
  }
  return out.sort((a, b) => b.contribution - a.contribution);
}

export function WhyFlagged({ items, limit = 8, detailed = false }: { items: Explanation[]; limit?: number; detailed?: boolean }) {
  if (!items.length) return <div className="text-sm text-fg-dim">No explanation available yet.</div>;
  const max = Math.max(...items.map((i) => i.contribution), 1);
  const shown = detailed ? items.slice(0, limit) : diverse(items.filter((i) => i.contribution > 0), limit);
  return (
    <ol className="space-y-1.5">
      {shown.map((e) => (
        <li key={`${e.channel}:${e.signal}`} className="grid grid-cols-[18px_1fr_auto] items-start gap-2 text-sm">
          <Check size={15} className="mt-0.5 text-accent" />
          <div className="min-w-0">
            <div className="leading-snug">{e.text}</div>
            {detailed && (
              <div className="mt-1 flex items-center gap-2 text-[11px] text-fg-dim">
                <span>{e.channel_name}</span>
                <span className="font-mono">{e.detector}</span>
                {e.timestamp && <span className="font-mono">{time(e.timestamp, false)}</span>}
                <div className="h-1 flex-1 max-w-[140px] rounded-full bg-ink-700">
                  <div className="h-1 rounded-full bg-accent" style={{ width: `${(e.contribution / max) * 100}%` }} />
                </div>
              </div>
            )}
          </div>
          <span className="font-mono text-xs text-fg-muted tabular-nums" title="approximate share of the fused risk score">
            +{e.contribution.toFixed(1)}
          </span>
        </li>
      ))}
    </ol>
  );
}

const ACTIONS = [
  { action: "HOLD", label: "HOLD", icon: PauseCircle, cls: "text-amber-200 border-amber-400/40 hover:bg-amber-400/15" },
  { action: "STEP_UP", label: "STEP-UP", icon: KeyRound, cls: "text-sky-200 border-sky-400/40 hover:bg-sky-400/15" },
  { action: "BLOCK", label: "BLOCK", icon: Ban, cls: "text-rose-200 border-rose-400/40 hover:bg-rose-400/15" },
  { action: "MARK_LEGITIMATE", label: "MARK LEGIT", icon: ShieldCheck, cls: "text-emerald-200 border-emerald-400/40 hover:bg-emerald-400/15" },
  { action: "CONFIRM_FRAUD", label: "CONFIRM FRAUD", icon: Gavel, cls: "text-rose-100 border-rose-500/60 bg-rose-500/15 hover:bg-rose-500/25" },
];

/** Every button calls POST /api/cases/{id}/feedback. */
export function CaseActions({ caseId, onDone, withNotes = false }: { caseId: string; onDone?: () => void; withNotes?: boolean }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [notes, setNotes] = useState("");
  const [analyst, setAnalyst] = useState("demo-analyst");

  const act = async (action: string) => {
    setBusy(action);
    setMsg(null);
    try {
      const res = await post<any>(`/api/cases/${caseId}/feedback`, { action, notes, analyst: analyst || "demo-analyst" });
      const learn = res.learning?.note ? ` — ${res.learning.note}` : "";
      setMsg({ ok: true, text: `${action.replace(/_/g, " ")} recorded → status ${res.case.status}${learn}` });
      setNotes("");
      onDone?.();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-2">
      {withNotes && (
        <div className="grid sm:grid-cols-[160px_1fr] gap-2">
          <input className="input" value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="analyst" maxLength={64} />
          <input className="input" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="notes (optional)" maxLength={2000} />
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {ACTIONS.map(({ action, label, icon: Icon, cls }) => (
          <button key={action} className={`btn bg-ink-900 ${cls}`} disabled={!!busy} onClick={() => act(action)}>
            <Icon size={14} /> {busy === action ? "…" : label}
          </button>
        ))}
      </div>
      {msg && (
        <div className={`text-xs flex items-center gap-1.5 ${msg.ok ? "text-emerald-300" : "text-rose-300"}`}>
          {msg.ok && <CheckCircle2 size={13} />} {msg.text}
        </div>
      )}
    </div>
  );
}

/** Single-series area chart of the unified case risk as evidence arrived. */
export function RiskTrajectory({ detail, height = 150 }: { detail: CaseDetail; height?: number }) {
  const ev = new Map(detail.events.map((e) => [e.event_id, e]));
  const data = detail.risk_history.map((h, i) => {
    const e = ev.get(h.event_id);
    return { i, t: time(h.timestamp, false), risk: h.risk_score, what: e ? (e.metadata?.subtype ?? e.event_type).replace(/_/g, " ") : "re-score" };
  });
  if (data.length < 2) return <div className="text-xs text-fg-dim py-4">Risk history appears as evidence accumulates.</div>;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
        <defs>
          <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#2dd4bf" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#2dd4bf" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1b2733" vertical={false} />
        <XAxis dataKey="t" tick={{ fill: "#5d6f80", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis domain={[0, 100]} ticks={[0, 30, 60, 80, 100]} tick={{ fill: "#5d6f80", fontSize: 10 }} axisLine={false} tickLine={false} />
        <ReferenceLine y={60} stroke="#f97316" strokeDasharray="3 4" strokeOpacity={0.5} />
        <ReferenceLine y={80} stroke="#e11d48" strokeDasharray="3 4" strokeOpacity={0.5} />
        <Tooltip cursor={{ stroke: "#5d6f80" }} contentStyle={{ background: "#0a1016", border: "1px solid #263545", borderRadius: 8, fontSize: 12 }}
                 labelStyle={{ color: "#8a9bab" }}
                 formatter={(v: number, _n, p: any) => [`${v.toFixed(1)} / 100`, p.payload.what]} />
        <Area type="monotone" dataKey="risk" stroke="#2dd4bf" strokeWidth={2} fill="url(#riskFill)" isAnimationActive
              dot={{ r: 4, fill: "#2dd4bf", stroke: "#0d141b", strokeWidth: 2 }} activeDot={{ r: 6 }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
