import { Link } from "react-router-dom";
import { Radio } from "lucide-react";
import type { LiveMessage } from "../api/types";
import { useLive } from "../hooks/live";
import { EVENT_LABEL, inr, time } from "../lib/format";

function Row({ m }: { m: LiveMessage }) {
  const d = m.data;
  if (m.type === "event.received") {
    const sub = d.subtype && d.subtype !== "PAYMENT" && d.subtype !== "API_CALL" ? d.subtype.replace(/_/g, " ") : null;
    return (
      <div className="animate-flash rounded-md px-2 py-1.5">
        <div className="flex items-center gap-2 text-xs">
          <span className="font-mono text-fg-muted">{time(d.timestamp)}</span>
          <span className="font-semibold tracking-wide">{EVENT_LABEL[d.event_type] ?? d.event_type}</span>
          {d.bank_name && <span className="chip border-ink-600 text-fg-muted !py-0">{d.bank_name}</span>}
        </div>
        <div className="text-xs text-fg-dim mt-0.5 flex gap-2 flex-wrap">
          {sub && <span className="text-accent">{sub}</span>}
          {d.event_type === "transaction" && <span className="text-amber-200 font-mono">{inr(d.amount)}</span>}
          {d.account_label && <span>{d.account_label}</span>}
          {d.device_label && <span>{d.device_label}</span>}
        </div>
      </div>
    );
  }
  const map: Record<string, { text: string; cls: string }> = {
    "case.created": { text: `CASE ${d.case_id} CREATED · risk ${Math.round(d.risk_score)}`, cls: "text-rose-300" },
    "case.updated": { text: `${d.case_id} → risk ${Math.round(d.risk_score)} · ${d.status}`, cls: "text-fg-muted" },
    "policy.triggered": { text: `POLICY ${d.policy?.policy_id}: ${d.policy?.action_label}`, cls: "text-amber-200" },
    "analyst.action": { text: `ANALYST ${d.feedback?.action?.replace(/_/g, " ")} on ${d.case_id}`, cls: "text-sky-300" },
    "demo.reset": { text: "Live demo data reset", cls: "text-fg-dim" },
    "simulation.started": { text: `Simulation started: ${d.scenario?.replace(/_/g, " ")}`, cls: "text-accent" },
    "simulation.completed": { text: "Simulation completed", cls: "text-accent" },
    "model.retrained": { text: `Model retrained → ${d.model_version}`, cls: "text-accent" },
  };
  const item = map[m.type];
  if (!item) return null;
  const inner = <div className={`px-2 py-1 text-[11px] font-medium ${item.cls}`}>{item.text}</div>;
  return d?.case_id && m.type !== "analyst.action" ? <Link to={`/cases/${d.case_id}`} className="block hover:bg-ink-800 rounded">{inner}</Link> : inner;
}

export function LiveStream({ max = 60, showCaseEvents = true }: { max?: number; showCaseEvents?: boolean }) {
  const { feed, connected } = useLive();
  const items = feed.filter((m) => showCaseEvents || m.type === "event.received").filter((m) => m.type !== "risk.updated" && m.type !== "config.updated" && m.type !== "policy.updated");
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 text-[11px] text-fg-muted mb-2">
        <Radio size={13} className={connected ? "text-accent" : "text-fg-dim"} />
        {connected ? "Streaming over WebSocket /ws/events" : "Reconnecting…"}
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto divide-y divide-ink-700/60 pr-1">
        {items.length === 0 ? (
          <div className="text-xs text-fg-dim py-6 text-center">Waiting for live events.<br />Start the attack simulation or POST to /api/events.</div>
        ) : (
          items.slice(0, max).map((m, i) => <Row key={`${m.type}-${m.server_ts}-${i}`} m={m} />)
        )}
      </div>
    </div>
  );
}
