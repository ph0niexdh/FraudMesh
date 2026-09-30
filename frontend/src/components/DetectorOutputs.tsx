import type { DetectorResult } from "../api/types";
import { humanize, pct, scoreColor } from "../lib/format";

const FEATURE_LABEL: Record<string, string> = {
  amount_ratio: "Amount vs baseline", velocity_1h: "Velocity (1h)", beneficiary_new: "New beneficiary",
  merchant_new: "New merchant", hour_deviation: "Hour deviation", geo_km: "Distance from home (km)",
  device_new: "New device", frequency_ratio: "Frequency ratio", amount_rarity: "Amount rarity",
};

/** Per-detector output; transaction results include real TreeSHAP contributions. */
export function DetectorOutputs({ results }: { results: DetectorResult[] }) {
  return (
    <div className="grid gap-2">
      {results.map((r) => (
        <div key={r.detector} className="rounded-lg border border-ink-700 bg-ink-900 p-3 text-xs">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-semibold text-fg">{r.details?.display_name ?? humanize(r.detector)}</span>
            <span className="text-fg-dim font-mono">{r.model_version}</span>
            <span className="ml-auto font-mono" style={{ color: scoreColor(r.score) }}>score {r.score.toFixed(2)}</span>
            <span className="font-mono text-fg-muted">conf {pct(r.confidence)}</span>
          </div>
          {r.details?.disclaimer && <p className="text-amber-200/80 mb-2">{r.details.disclaimer}</p>}
          {r.details?.mode === "controlled_scenario_value" && (
            <p className="text-amber-200/80 mb-2">Score is a controlled scenario value for the scripted demo.</p>
          )}
          {r.signal_details.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-2">
              {r.signal_details.map((s) => (
                <span key={s.name} className="chip border-ink-600 text-fg-muted">
                  {s.label ?? s.name}{s.points ? ` +${s.points}` : ""}
                </span>
              ))}
            </div>
          )}
          {r.details?.shap_values && <ShapBars values={r.details.shap_values} features={r.details.features} />}
          {r.details?.behavior_score !== undefined && (
            <div className="text-fg-muted font-mono">
              behavior_score (Isolation Forest) {r.details.behavior_score.toFixed(2)} · takeover_score {r.details.takeover_score.toFixed(2)}
            </div>
          )}
          {r.details?.anomaly_score !== undefined && (
            <div className="text-fg-muted font-mono">isolation-forest anomaly {r.details.anomaly_score.toFixed(2)}</div>
          )}
          <div className="text-fg-dim mt-1 font-mono">latency {r.latency_ms.toFixed(2)} ms</div>
        </div>
      ))}
    </div>
  );
}

function ShapBars({ values, features }: { values: Record<string, number>; features: Record<string, number> }) {
  const rows = Object.entries(values).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  const max = Math.max(...rows.map(([, v]) => Math.abs(v)), 0.01);
  return (
    <div className="mb-1">
      <div className="text-fg-muted mb-1">SHAP contributions (log-odds, TreeSHAP)</div>
      <div className="space-y-1">
        {rows.map(([f, v]) => (
          <div key={f} className="grid grid-cols-[150px_1fr_52px] items-center gap-2" title={`${f} = ${features?.[f]}`}>
            <span className="text-fg-muted truncate">{FEATURE_LABEL[f] ?? f} <span className="text-fg-dim">({features?.[f]})</span></span>
            <div className="relative h-2">
              <div className="absolute top-0 h-2 left-1/2 w-px bg-ink-600" />
              <div className="absolute top-0 h-2 rounded-sm"
                   style={{
                     left: v >= 0 ? "50%" : `${50 - (Math.abs(v) / max) * 50}%`,
                     width: `${(Math.abs(v) / max) * 50}%`,
                     backgroundColor: v >= 0 ? "#f97316" : "#2dd4bf",
                   }} />
            </div>
            <span className="font-mono text-right text-fg-muted">{v >= 0 ? "+" : ""}{v.toFixed(2)}</span>
          </div>
        ))}
      </div>
      <div className="text-fg-dim mt-1">orange raises fraud probability · teal lowers it</div>
    </div>
  );
}
