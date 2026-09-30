import { useEffect, useState } from "react";
import { KeyRound, Save, Undo2 } from "lucide-react";
import { getAdminToken, put, setAdminToken } from "../api/client";
import type { FusionConfig, PolicyConfig, PolicyTier } from "../api/types";
import { ErrorState, Loading, Panel, SeverityBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { CHANNELS, CHANNEL_LABEL } from "../lib/format";

const DEFAULT_WEIGHTS: Record<string, number> = { transaction: 0.3, takeover: 0.2, kyc: 0.2, cloud: 0.1, graph: 0.15, temporal: 0.05 };

function Status({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return <span className={`text-xs ${msg.ok ? "text-emerald-300" : "text-rose-300"}`}>{msg.text}</span>;
}

export function PolicyCenter() {
  const cfgApi = useApi<FusionConfig>("/api/config", { refreshOn: ["config.updated"] });
  const polApi = useApi<PolicyConfig>("/api/policies", { refreshOn: ["policy.updated"] });
  const health = useApi<{ admin_auth_enabled: boolean }>("/api/health");
  const [cfg, setCfg] = useState<FusionConfig | null>(null);
  const [tiers, setTiers] = useState<PolicyTier[] | null>(null);
  const [token, setToken] = useState(getAdminToken());
  const [cfgMsg, setCfgMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [polMsg, setPolMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [rescore, setRescore] = useState(true);

  useEffect(() => { if (cfgApi.data) setCfg(structuredClone(cfgApi.data)); }, [cfgApi.data]);
  useEffect(() => { if (polApi.data) setTiers(structuredClone(polApi.data.tiers)); }, [polApi.data]);

  const saveCfg = async () => {
    if (!cfg) return;
    setCfgMsg(null);
    try {
      const { weights, temporal_window_minutes, suspicious_event_threshold, min_correlated_signals, case_creation_min_risk } = cfg;
      await put(`/api/config?rescore=${rescore}`, { weights, temporal_window_minutes, suspicious_event_threshold, min_correlated_signals, case_creation_min_risk });
      setCfgMsg({ ok: true, text: `Saved${rescore ? " — open cases re-scored" : ""}.` });
      cfgApi.reload(true);
    } catch (e) {
      setCfgMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    }
  };
  const savePol = async () => {
    if (!tiers) return;
    setPolMsg(null);
    try {
      await put(`/api/policies?rescore=${rescore}`, { tiers });
      setPolMsg({ ok: true, text: `Saved${rescore ? " — open cases re-evaluated" : ""}.` });
      polApi.reload(true);
    } catch (e) {
      setPolMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    }
  };

  if (cfgApi.loading || polApi.loading) return <Loading />;
  if (cfgApi.error) return <ErrorState error={cfgApi.error} onRetry={() => cfgApi.reload()} />;
  if (polApi.error) return <ErrorState error={polApi.error} onRetry={() => polApi.reload()} />;
  if (!cfg || !tiers || !polApi.data) return <Loading />;
  const sum = CHANNELS.reduce((a, c) => a + (cfg.weights[c] ?? 0), 0);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Policy Center</h1>
        <p className="text-sm text-fg-muted">Risk-fusion weights, correlation settings and policy tiers. These are demonstration configuration values — not scientifically optimised.</p>
      </div>

      <Panel title="Authorisation">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="label" htmlFor="tok">Admin token (X-Admin-Token)</label>
            <input id="tok" type="password" className="input w-72" value={token} onChange={(e) => setToken(e.target.value)} placeholder="FRAUDMESH_ADMIN_TOKEN" />
          </div>
          <button className="btn-ghost" onClick={() => setAdminToken(token)}><KeyRound size={14} /> Use token</button>
          <span className="text-xs text-fg-muted pb-2">
            {health.data?.admin_auth_enabled ? "Admin auth is enabled on the backend — changes require the token." :
              "Backend is in open demo mode (FRAUDMESH_ADMIN_TOKEN not set)."}
          </span>
          <label className="flex items-center gap-2 text-xs text-fg-muted pb-2 ml-auto">
            <input type="checkbox" className="accent-teal-400" checked={rescore} onChange={(e) => setRescore(e.target.checked)} /> re-score open cases on save
          </label>
        </div>
      </Panel>

      <div className="grid xl:grid-cols-2 gap-4">
        <Panel title="Risk-fusion weights" right={<span className={`text-xs font-mono ${Math.abs(sum - 1) < 0.001 ? "text-emerald-300" : "text-amber-300"}`}>Σ = {sum.toFixed(2)}</span>}>
          <p className="text-xs text-fg-muted mb-3 font-mono">risk = 100 × (Σ weight × channel score), clamped 0–100</p>
          <div className="space-y-3">
            {CHANNELS.map((c) => (
              <div key={c} className="grid grid-cols-[110px_1fr_60px] items-center gap-3">
                <label htmlFor={`w-${c}`} className="text-sm text-fg-muted">{CHANNEL_LABEL[c]}</label>
                <input id={`w-${c}`} type="range" min={0} max={0.6} step={0.01} value={cfg.weights[c]} className="accent-teal-400"
                       onChange={(e) => setCfg({ ...cfg, weights: { ...cfg.weights, [c]: +e.target.value } })} />
                <input type="number" min={0} max={1} step={0.01} className="input !px-1.5 text-right font-mono" value={cfg.weights[c]}
                       onChange={(e) => setCfg({ ...cfg, weights: { ...cfg.weights, [c]: Math.max(0, Math.min(1, +e.target.value)) } })} />
              </div>
            ))}
          </div>
          {Math.abs(sum - 1) >= 0.001 && <p className="text-xs text-amber-300 mt-2">Weights do not sum to 1 — scores will be clamped to 0–100.</p>}
          <div className="grid grid-cols-2 gap-3 mt-5">
            <div><label className="label">Temporal window (min)</label>
              <input type="number" min={1} max={1440} className="input w-full" value={cfg.temporal_window_minutes}
                     onChange={(e) => setCfg({ ...cfg, temporal_window_minutes: +e.target.value })} /></div>
            <div><label className="label">Suspicious-event threshold</label>
              <input type="number" min={0.05} max={0.95} step={0.05} className="input w-full" value={cfg.suspicious_event_threshold}
                     onChange={(e) => setCfg({ ...cfg, suspicious_event_threshold: +e.target.value })} /></div>
            <div><label className="label">Min correlated signals for a case</label>
              <input type="number" min={1} max={10} className="input w-full" value={cfg.min_correlated_signals}
                     onChange={(e) => setCfg({ ...cfg, min_correlated_signals: +e.target.value })} /></div>
            <div><label className="label">Case creation min risk</label>
              <input type="number" min={0} max={100} className="input w-full" value={cfg.case_creation_min_risk}
                     onChange={(e) => setCfg({ ...cfg, case_creation_min_risk: +e.target.value })} /></div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            <button className="btn-primary" onClick={saveCfg}><Save size={14} /> Save (PUT /api/config)</button>
            <button className="btn-ghost" onClick={() => setCfg({ ...cfg, weights: { ...DEFAULT_WEIGHTS }, temporal_window_minutes: 15 })}><Undo2 size={14} /> Defaults</button>
            <Status msg={cfgMsg} />
          </div>
        </Panel>

        <Panel title="Policy tiers">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-fg-muted">
                <tr><th className="text-left py-1.5">Severity</th><th className="text-left">Policy ID</th><th className="text-left">Min</th><th className="text-left">Max</th><th className="text-left">Action</th></tr>
              </thead>
              <tbody>
                {tiers.map((t, i) => (
                  <tr key={t.policy_id} className="border-t border-ink-700/60">
                    <td className="py-2"><SeverityBadge severity={t.severity} /></td>
                    <td className="font-mono text-xs text-fg-muted">{t.policy_id}</td>
                    {(["min_score", "max_score"] as const).map((k) => (
                      <td key={k}><input type="number" min={0} max={100} className="input w-16 !px-1.5 font-mono" value={t[k]}
                                         onChange={(e) => setTiers(tiers.map((x, j) => (j === i ? { ...x, [k]: +e.target.value } : x)))} /></td>
                    ))}
                    <td>
                      <select className="input" value={t.action} onChange={(e) => setTiers(tiers.map((x, j) => (j === i ? { ...x, action: e.target.value } : x)))}>
                        {Object.entries(polApi.data!.action_labels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-fg-muted mt-3">Tiers must be contiguous and cover 0–100. The backend policy engine returns action, reason, policy_id and threshold for every case — actions are never hidden UI behaviour.</p>
          <div className="flex items-center gap-2 mt-4">
            <button className="btn-primary" onClick={savePol}><Save size={14} /> Save (PUT /api/policies)</button>
            <Status msg={polMsg} />
          </div>
        </Panel>
      </div>
    </div>
  );
}
