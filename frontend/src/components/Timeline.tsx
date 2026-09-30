import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { EventRecord } from "../api/types";
import { eventHeadline, inr, scoreColor, time } from "../lib/format";
import { DetectorOutputs } from "./DetectorOutputs";

export function Timeline({ events, expandable = false, highlight }: {
  events: EventRecord[]; expandable?: boolean; highlight?: string | null;
}) {
  const [open, setOpen] = useState<string | null>(null);
  if (!events.length) return <div className="text-sm text-fg-dim">No events.</div>;
  return (
    <ol className="relative border-l border-ink-600 ml-2 space-y-3">
      {events.map((e) => {
        const color = e.suspicious ? scoreColor(e.signal_score) : "#5d6f80";
        const isOpen = open === e.event_id;
        return (
          <li key={e.event_id} className={`ml-4 rounded-md ${highlight === e.event_id ? "animate-flash" : ""}`}>
            <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full ring-2 ring-ink-850" style={{ backgroundColor: color }} />
            <button className={`w-full text-left ${expandable ? "cursor-pointer" : "cursor-default"}`}
                    onClick={() => expandable && setOpen(isOpen ? null : e.event_id)}>
              <div className="flex items-center gap-2 text-sm">
                <span className="font-mono text-fg-muted text-xs">{time(e.timestamp, false)}</span>
                <span className="font-semibold">{eventHeadline(e)}</span>
                {e.event_type === "transaction" && <span className="font-mono text-amber-200">{inr(e.amount)}</span>}
                {e.bank_name && <span className="chip border-ink-600 text-fg-muted">{e.bank_name}</span>}
                <span className="ml-auto font-mono text-xs tabular-nums" style={{ color }}>
                  {Math.round(e.signal_score * 100)}
                </span>
                {expandable && (isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />)}
              </div>
              <div className="text-xs text-fg-dim mt-0.5 flex flex-wrap gap-x-3">
                {e.account_label && <span>{e.account_label}</span>}
                {e.device_label && <span>{e.device_label}</span>}
                {e.metadata?.city && <span>{e.metadata.city}</span>}
                {e.detector_results.flatMap((r) => r.score >= 0.35 ? r.signals.slice(0, 3) : []).slice(0, 4).map((s) => (
                  <span key={s} className="text-fg-muted">#{s}</span>
                ))}
              </div>
            </button>
            {isOpen && <div className="mt-2"><DetectorOutputs results={e.detector_results} /></div>}
          </li>
        );
      })}
    </ol>
  );
}
