import { useEffect, useState } from "react";
import { ChevronRight } from "lucide-react";
import { useLive } from "../hooks/live";

const STAGES: { key: string; label: string; stage?: string }[] = [
  { key: "event", label: "EVENT" },
  { key: "normalize", label: "NORMALIZE", stage: "normalize_ms" },
  { key: "detect", label: "DETECT", stage: "detect_ms" },
  { key: "correlate", label: "CORRELATE", stage: "correlate_ms" },
  { key: "graph", label: "GRAPH", stage: "graph_ms" },
  { key: "fuse", label: "RISK FUSION", stage: "score_explain_policy_ms" },
  { key: "explain", label: "EXPLAIN" },
  { key: "policy", label: "POLICY" },
  { key: "analyst", label: "ANALYST" },
  { key: "learn", label: "LEARN" },
];

/** Lights up EVENT → … → POLICY for each processed event, ANALYST/LEARN on feedback. */
export function PipelineStrip() {
  const { lastPipeline, subscribe } = useLive();
  const [lit, setLit] = useState(-1);
  const [feedback, setFeedback] = useState(0);

  useEffect(() => {
    if (!lastPipeline) return;
    const hasCase = lastPipeline.stages.score_explain_policy_ms !== undefined;
    const last = hasCase ? 7 : 4;
    let i = 0;
    setLit(0);
    const t = window.setInterval(() => {
      i += 1;
      setLit(i);
      if (i >= last) window.clearInterval(t);
    }, 110);
    return () => window.clearInterval(t);
  }, [lastPipeline]);

  useEffect(() => subscribe((m) => {
    if (m.type === "analyst.action") setFeedback(Date.now());
  }), [subscribe]);

  const analystLit = Date.now() - feedback < 3000;
  return (
    <div className="flex items-center gap-1 overflow-x-auto py-1 text-[10px] font-semibold tracking-wider">
      {STAGES.map((s, idx) => {
        const on = idx <= lit || (analystLit && idx >= 8);
        const ms = s.stage && lastPipeline ? lastPipeline.stages[s.stage] : undefined;
        return (
          <div key={s.key} className="flex items-center gap-1 shrink-0">
            <div className={`rounded-md border px-2 py-1 transition-all duration-300 ${on ? "border-accent/70 bg-accent/15 text-accent shadow-[0_0_12px_rgba(45,212,191,0.25)]" : "border-ink-700 text-fg-dim"}`}>
              {s.label}
              {ms !== undefined && on && <span className="ml-1 font-mono font-normal text-fg-muted">{ms.toFixed(1)}ms</span>}
            </div>
            {idx < STAGES.length - 1 && <ChevronRight size={12} className={on ? "text-accent" : "text-ink-600"} />}
          </div>
        );
      })}
    </div>
  );
}
