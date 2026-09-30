import { useState } from "react";
import { Play, RotateCcw, Zap } from "lucide-react";
import { post } from "../api/client";
import { useApi } from "../hooks/useApi";
import { useLive } from "../hooks/live";

interface ScenarioList {
  scenarios: { name: string; description: string }[];
  flagship: { offset: number; title: string; narrative: string }[];
}

export function SimulationPanel() {
  const { simulation } = useLive();
  const { data } = useApi<ScenarioList>("/api/demo/scenarios");
  const [scenario, setScenario] = useState("coordinated_cross_channel_fraud");
  const [speed, setSpeed] = useState(2.5);
  const [reset, setReset] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const start = async () => {
    setError(null);
    setBusy(true);
    try {
      await post("/api/demo/simulate", { scenario, step_seconds: speed, reset });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const doReset = async () => {
    setError(null);
    try {
      await post("/api/demo/reset", {}, true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const steps = simulation.steps ?? (scenario === "coordinated_cross_channel_fraud" ? data?.flagship : undefined) ?? [];
  const current = simulation.index ?? -1;
  const desc = data?.scenarios.find((s) => s.name === scenario)?.description;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[240px]">
          <label className="label" htmlFor="scenario">Scenario</label>
          <select id="scenario" className="input w-full" value={scenario} onChange={(e) => setScenario(e.target.value)} disabled={simulation.running}>
            {(data?.scenarios ?? []).map((s) => (
              <option key={s.name} value={s.name}>{s.name.replace(/_/g, " ")}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="speed">Seconds between events: {speed.toFixed(1)}</label>
          <input id="speed" type="range" min={0.5} max={6} step={0.5} value={speed} onChange={(e) => setSpeed(+e.target.value)} className="accent-teal-400 w-40" />
        </div>
        <label className="flex items-center gap-2 text-xs text-fg-muted pb-2">
          <input type="checkbox" checked={reset} onChange={(e) => setReset(e.target.checked)} className="accent-teal-400" />
          clear previous live data
        </label>
        <button className="btn-primary" onClick={start} disabled={busy || simulation.running}>
          {simulation.running ? <><Zap size={14} className="animate-pulse" /> Streaming…</> : <><Play size={14} /> Start simulated attack</>}
        </button>
        <button className="btn-ghost" onClick={doReset} disabled={simulation.running} title="POST /api/demo/reset">
          <RotateCcw size={14} /> Reset live data
        </button>
      </div>
      {desc && <p className="text-xs text-fg-muted">{desc}</p>}
      {error && <p className="text-xs text-rose-300">{error}</p>}
      {steps.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-5 xl:grid-cols-9 gap-1.5">
          {steps.map((s, i) => {
            const done = i < current || (i === current && !simulation.running);
            const now = i === current && simulation.running;
            return (
              <div key={i} className={`rounded-md border px-2 py-1.5 text-[10px] leading-tight transition-colors ${now ? "border-accent bg-accent/15 text-accent" : done ? "border-accent/30 text-fg" : "border-ink-700 text-fg-dim"}`}>
                <div className="font-mono">T+{String(Math.floor(s.offset / 60)).padStart(2, "0")}:{String(s.offset % 60).padStart(2, "0")}</div>
                <div className="font-semibold">{s.title}</div>
              </div>
            );
          })}
        </div>
      )}
      {simulation.running && simulation.narrative && (
        <p className="text-sm text-accent">▶ {simulation.title}: <span className="text-fg">{simulation.narrative}</span></p>
      )}
      {!simulation.running && simulation.final && (
        <p className="text-sm">
          <span className="text-rose-300 font-semibold">🚨 {simulation.final.case_id}</span> · risk {Math.round(simulation.final.risk_score)}/100 ·{" "}
          {simulation.final.severity} · <span className="text-accent">{simulation.final.policy?.action_label}</span>
        </p>
      )}
    </div>
  );
}
