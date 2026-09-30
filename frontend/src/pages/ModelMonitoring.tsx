import { useState } from "react";
import { RefreshCw, Upload } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, post } from "../api/client";
import type { DetectorResult } from "../api/types";
import { DetectorOutputs } from "../components/DetectorOutputs";
import { ErrorState, Loading, Panel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { dateTime, pct } from "../lib/format";

interface ModelsInfo {
  detectors: any[];
  transaction_evaluation: Record<string, any>;
  distributions: Record<string, { bin: string; count: number }[]>;
  score_counts: Record<string, number>;
  feedback: { by_action: Record<string, number>; confirmed_fraud: number; false_positives: number; analyst_precision: number | null;
              recent: { case_id: string; action: string; analyst: string; created_at: string }[] };
  privacy: Record<string, any>;
  explainability: Record<string, any>;
  audit: Record<string, any>;
  system: Record<string, any>;
}

const DIST_TITLES: Record<string, string> = {
  transaction: "Transaction score (XGBoost)",
  takeover: "Takeover score",
  behavior_anomaly: "Behaviour anomaly (Isolation Forest)",
  kyc: "KYC manipulation score (prototype)",
  cloud: "Cloud risk score",
  graph: "Graph risk score",
};

function Histogram({ data, n }: { data: { bin: string; count: number }[]; n: number }) {
  return (
    <div>
      <ResponsiveContainer width="100%" height={130}>
        <BarChart data={data} margin={{ top: 4, right: 4, left: -24, bottom: 0 }} barCategoryGap={2}>
          <CartesianGrid stroke="#1b2733" vertical={false} />
          <XAxis dataKey="bin" tick={{ fill: "#5d6f80", fontSize: 9 }} axisLine={false} tickLine={false} interval={1} />
          <YAxis tick={{ fill: "#5d6f80", fontSize: 9 }} axisLine={false} tickLine={false} allowDecimals={false} />
          <Tooltip cursor={{ fill: "rgba(45,212,191,0.08)" }} contentStyle={{ background: "#0a1016", border: "1px solid #263545", borderRadius: 8, fontSize: 12 }}
                   formatter={(v: number) => [v, "events"]} labelFormatter={(l) => `score ${l}`} />
          <Bar dataKey="count" fill="#2dd4bf" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
      <div className="text-[11px] text-fg-dim text-right">n = {n.toLocaleString()}</div>
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900 px-3 py-2">
      <div className="text-[11px] uppercase tracking-wider text-fg-muted">{label}</div>
      <div className="font-mono text-lg font-semibold">{value}</div>
      {hint && <div className="text-[11px] text-fg-dim">{hint}</div>}
    </div>
  );
}

function KycLab() {
  const [file, setFile] = useState<File | null>(null);
  const [customer, setCustomer] = useState("");
  const [bank, setBank] = useState("SBI");
  const [submitEvent, setSubmitEvent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ detector_result: DetectorResult; media_sha256: string; media_retained: boolean; case?: any; event_id?: string } | null>(null);

  const run = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    const fd = new FormData();
    fd.append("file", file);
    if (submitEvent && customer) {
      fd.append("customer_id", customer);
      fd.append("bank_name", bank);
      fd.append("submit_event", "true");
    }
    try {
      setResult(await api("/api/kyc/analyze", { method: "POST", body: fd }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs text-amber-200/90">
        Prototype KYC / Media Authenticity Detector — OpenCV quality, face-detection and manipulation heuristics.
        Not a validated deepfake detector. Use synthetic or consented test images only. JPEG/PNG ≤ 5 MB; media is analysed in memory and not stored.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <label className="btn-ghost cursor-pointer">
          <Upload size={14} /> {file ? file.name : "Choose image"}
          <input type="file" accept="image/jpeg,image/png" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <label className="flex items-center gap-2 text-xs text-fg-muted">
          <input type="checkbox" className="accent-teal-400" checked={submitEvent} onChange={(e) => setSubmitEvent(e.target.checked)} />
          also submit as a kyc_verification event for
        </label>
        <input className="input w-44" placeholder="CUSTOMER_… (synthetic)" value={customer} onChange={(e) => setCustomer(e.target.value)} disabled={!submitEvent} />
        <select className="input" value={bank} onChange={(e) => setBank(e.target.value)} disabled={!submitEvent}>
          <option>SBI</option><option>HDFC Bank</option><option>ICICI Bank</option>
        </select>
        <button className="btn-primary" disabled={!file || busy || (submitEvent && !customer)} onClick={run}>{busy ? "Analysing…" : "Analyse"}</button>
      </div>
      {error && <p className="text-xs text-rose-300">{error}</p>}
      {result && (
        <div className="space-y-2">
          <div className="text-xs text-fg-muted font-mono break-all">sha256 {result.media_sha256} · retained: {String(result.media_retained)}
            {result.event_id && <> · event {result.event_id}</>}{result.case && <> · case {result.case.case_id}</>}</div>
          <DetectorOutputs results={[result.detector_result]} />
        </div>
      )}
    </div>
  );
}

export function ModelMonitoring() {
  const { data: m, error, loading, reload } = useApi<ModelsInfo>("/api/models", { refreshOn: ["model.retrained", "analyst.action", "demo.reset"], throttleMs: 1500 });
  const [retrainMsg, setRetrainMsg] = useState<string | null>(null);
  const retrain = async () => {
    setRetrainMsg("Retraining…");
    try {
      const r = await post<any>("/api/models/retrain", {}, true);
      setRetrainMsg(`Retrained → ${r.model_version} with ${r.feedback_samples} analyst-labelled transactions.`);
      reload(true);
    } catch (e) {
      setRetrainMsg(e instanceof Error ? e.message : String(e));
    }
  };

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} onRetry={() => reload()} />;
  if (!m) return null;
  const ev = m.transaction_evaluation;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Model Monitoring</h1>
          <p className="text-sm text-fg-muted">Detector health, versions, latency and score distributions — all measured from this running instance on synthetic data.</p>
        </div>
        <div className="flex items-center gap-2">
          {retrainMsg && <span className="text-xs text-fg-muted">{retrainMsg}</span>}
          <button className="btn-ghost" onClick={retrain}><RefreshCw size={14} /> Retrain transaction model with analyst feedback</button>
        </div>
      </div>

      <Panel title="Detector health" bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-fg-muted">
              <tr className="border-b border-ink-700">
                {["Detector", "Status", "Type", "Version", "Inferences", "Avg latency", "p95", "Errors", "Trained"].map((h) => <th key={h} className="text-left font-medium px-4 py-2">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {m.detectors.map((d) => (
                <tr key={d.name} className="border-b border-ink-700/50">
                  <td className="px-4 py-2 font-mono text-xs">{d.display_name ?? d.name}</td>
                  <td className="px-4 py-2"><span className={`chip ${d.status === "healthy" ? "text-emerald-300 border-emerald-400/40" : "text-rose-300 border-rose-400/40"}`}>● {d.status}</span></td>
                  <td className="px-4 py-2 text-xs text-fg-muted">{d.type}</td>
                  <td className="px-4 py-2 font-mono text-xs">{d.version}</td>
                  <td className="px-4 py-2 font-mono text-xs">{d.inferences ?? "—"}</td>
                  <td className="px-4 py-2 font-mono text-xs">{d.avg_latency_ms != null ? `${d.avg_latency_ms} ms` : "—"}</td>
                  <td className="px-4 py-2 font-mono text-xs">{d.p95_latency_ms != null ? `${d.p95_latency_ms} ms` : "—"}</td>
                  <td className="px-4 py-2 font-mono text-xs">{d.errors ?? 0}</td>
                  <td className="px-4 py-2 text-xs text-fg-dim">{d.trained_at ? dateTime(d.trained_at) : d.nodes ? `${d.nodes} nodes` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Transaction model evaluation" right={<span className="text-[11px] text-amber-200/80">{ev.dataset}</span>}>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <Stat label="Precision" value={pct(ev.precision, 1)} />
          <Stat label="Recall" value={pct(ev.recall, 1)} />
          <Stat label="F1" value={ev.f1?.toFixed(3)} />
          <Stat label="PR-AUC" value={ev.pr_auc?.toFixed(3)} />
          <Stat label="False-positive rate" value={pct(ev.false_positive_rate, 2)} />
          <Stat label="Hold-out samples" value={ev.samples} hint={`threshold ${ev.threshold}`} />
        </div>
        <p className="text-xs text-fg-dim mt-2">Measured on deterministic synthetic data. These numbers say nothing about performance on real bank customers.</p>
      </Panel>

      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
        {Object.entries(DIST_TITLES).map(([k, title]) => (
          <Panel key={k} title={title}><Histogram data={m.distributions[k] ?? []} n={m.score_counts[k] ?? 0} /></Panel>
        ))}
      </div>

      <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-4">
        <Panel title="Analyst feedback">
          <div className="grid grid-cols-2 gap-2 mb-3">
            <Stat label="Confirmed fraud" value={m.feedback.confirmed_fraud} />
            <Stat label="False positives" value={m.feedback.false_positives} />
          </div>
          <div className="text-xs text-fg-muted mb-2">Analyst precision (confirmed / decided): {m.feedback.analyst_precision != null ? pct(m.feedback.analyst_precision) : "—"}</div>
          <ul className="text-xs space-y-1">
            {m.feedback.recent.map((f, i) => <li key={i} className="text-fg-muted"><span className="font-mono text-fg">{f.case_id}</span> {f.action.replace(/_/g, " ")} · {f.analyst}</li>)}
          </ul>
        </Panel>
        <Panel title="Privacy">
          <div className="space-y-2">
            <Stat label="PII tokenization coverage" value={pct(m.privacy.pii_tokenization_coverage, 1)} hint={`${m.privacy.identifier_values_checked.toLocaleString()} identifier values checked`} />
            <Stat label="Raw KYC media retained" value={m.privacy.raw_kyc_media_retained} hint={`${m.privacy.kyc_events} KYC events · retention ${m.privacy.kyc_retention_enabled ? "ON" : "OFF"}`} />
          </div>
        </Panel>
        <Panel title="Explainability & audit">
          <div className="space-y-2">
            <Stat label="Explanation coverage" value={pct(m.explainability.explanation_coverage, 0)} hint={`${m.explainability.cases} cases`} />
            <Stat label="Top-signal availability" value={pct(m.explainability.top_signal_availability, 0)} hint="cases with ≥3 ranked signals" />
            <Stat label="Audit-log coverage" value={pct(m.audit.audit_coverage, 1)} hint={`${m.audit.events_with_audit_record} / ${m.audit.events} events`} />
          </div>
        </Panel>
        <Panel title="System">
          <div className="space-y-2">
            <Stat label="Peak RSS" value={`${m.system.max_rss_mb} MB`} />
            <Stat label="CPU (user)" value={`${m.system.cpu_user_seconds} s`} />
            <Stat label="Uptime" value={`${Math.floor(m.system.uptime_seconds / 60)} min`} />
          </div>
        </Panel>
      </div>

      <Panel title="KYC media lab — Prototype KYC / Media Authenticity Detector"><KycLab /></Panel>
    </div>
  );
}
