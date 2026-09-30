import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Cpu, Globe, Landmark, Smartphone, User } from "lucide-react";
import type { CaseDetail, Entity } from "../api/types";
import { ChannelScores } from "../components/ChannelScores";
import { CaseActions, RiskTrajectory, WhyFlagged } from "../components/CaseParts";
import { DetectorOutputs } from "../components/DetectorOutputs";
import { EntityGraph, GraphLegend, type Selection } from "../components/EntityGraph";
import { RiskGauge } from "../components/RiskGauge";
import { Timeline } from "../components/Timeline";
import { Empty, ErrorState, Loading, Panel, PolicyBadge, SeverityBadge, StatusBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { dateTime, humanize, pct } from "../lib/format";
import { SelectionDetails } from "./GraphPage";

function EntityList({ title, icon: Icon, items }: { title: string; icon: typeof User; items: Entity[] }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-fg-muted mb-1.5"><Icon size={13} /> {title} ({items.length})</div>
      {items.length === 0 ? <div className="text-xs text-fg-dim">None</div> : (
        <ul className="space-y-1">
          {items.map((e) => (
            <li key={e.token} className="flex items-center gap-2 text-xs">
              <span className="font-mono text-fg">{e.label ?? e.token}</span>
              {e.bank && <span className="chip border-ink-600 text-fg-muted !py-0">{e.bank}</span>}
              {e.via_graph && <span className="text-fg-dim">via shared entity</span>}
              <span className="ml-auto font-mono text-fg-dim">{e.token}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function CaseInvestigation() {
  const { caseId } = useParams();
  const { data: d, error, loading, reload } = useApi<CaseDetail>(`/api/cases/${caseId}`, {
    refreshOn: ["case.updated", "analyst.action"], throttleMs: 400,
  });
  const [sel, setSel] = useState<Selection>(null);
  const [showPaths, setShowPaths] = useState(true);

  if (loading) return <Loading label="Loading case…" />;
  if (error) return <ErrorState error={error} onRetry={() => reload()} />;
  if (!d) return <Empty>Case not found.</Empty>;

  return (
    <div className="space-y-4">
      <Link to="/cases" className="text-xs text-fg-muted inline-flex items-center gap-1 hover:text-accent"><ArrowLeft size={13} /> All cases</Link>
      <div className="panel p-4 grid lg:grid-cols-[230px_1fr_auto] gap-6 items-center">
        <div className="flex flex-col items-center gap-2">
          <RiskGauge score={d.risk_score} severity={d.severity} size={210} />
          <SeverityBadge severity={d.severity} large />
        </div>
        <div className="space-y-2 min-w-0">
          <div className="text-[11px] uppercase tracking-[0.2em] text-fg-muted">FraudMesh case</div>
          <h1 className="text-2xl font-mono font-semibold">#{d.case_id}</h1>
          <div className="flex flex-wrap gap-2 items-center">
            <StatusBadge status={d.status} />
            <PolicyBadge label={d.policy.action_label} />
            {d.policy.analyst_override && <span className="chip text-rose-200 border-rose-400/40">analyst override: {d.policy.analyst_override}</span>}
            {d.scenario && <span className="chip border-ink-600 text-fg-muted">scenario: {humanize(d.scenario)}</span>}
            <span className="chip border-amber-400/40 text-amber-200">synthetic</span>
          </div>
          <p className="text-sm text-fg-muted">{d.summary}</p>
          <p className="text-xs text-fg-dim">{d.policy.reason}</p>
          <div className="text-xs text-fg-dim flex flex-wrap gap-x-4">
            <span>created {dateTime(d.created_at)}</span><span>updated {dateTime(d.updated_at)}</span>
            <span>{d.event_count} events</span><span>confidence {pct(d.confidence)}</span><span>banks {d.banks.join(", ")}</span>
          </div>
        </div>
        <div className="lg:w-[330px]">
          <div className="text-[11px] uppercase tracking-wider text-fg-muted mb-1">Risk trajectory</div>
          <RiskTrajectory detail={d} height={150} />
        </div>
      </div>

      <Panel title="Analyst decision" right={<span className="text-[11px] text-fg-dim">POST /api/cases/{d.case_id}/feedback</span>}>
        <CaseActions caseId={d.case_id} onDone={() => reload(true)} withNotes />
      </Panel>

      <Panel title="Channel scores" right={<span className="text-[11px] text-fg-dim">risk = 100 × Σ weight × score · demo weights</span>}>
        <ChannelScores scores={d.channel_scores} weights={d.fusion_weights} contributions={d.contributions} cards />
      </Panel>

      <div className="grid xl:grid-cols-[1fr_420px] gap-4">
        <Panel title="Entity graph" right={
          <label className="flex items-center gap-2 text-xs text-fg-muted">
            <input type="checkbox" className="accent-rose-500" checked={showPaths} onChange={(e) => setShowPaths(e.target.checked)} />
            highlight suspicious paths ({d.suspicious_paths.length})
          </label>
        }>
          <EntityGraph data={d.graph} paths={d.suspicious_paths} highlightPaths={showPaths} height={440} onSelect={setSel} />
          <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
            <GraphLegend />
          </div>
          {sel && <div className="mt-3"><SelectionDetails sel={sel} /></div>}
          {d.suspicious_paths.length > 0 && showPaths && (
            <ul className="mt-3 text-xs text-rose-200 space-y-0.5">
              {d.suspicious_paths.slice(0, 6).map((p, i) => <li key={i} className="font-mono">⟶ {p.description}</li>)}
            </ul>
          )}
        </Panel>
        <Panel title="Why flagged? — explanation" right={<span className="text-[11px] text-fg-dim">+pts = approx. share of risk</span>}>
          <WhyFlagged items={d.explanations} limit={20} detailed />
          <p className="text-[11px] text-fg-dim mt-3">
            Channel contributions are exact (linear fusion). Within a channel, points are shared by detector weights:
            TreeSHAP values for the transaction model, rule points for takeover/cloud, heuristic weights for the prototype KYC detector.
          </p>
        </Panel>
      </div>

      <div className="grid xl:grid-cols-2 gap-4">
        <Panel title="Evidence timeline" right={<span className="text-[11px] text-fg-dim">click an event for detector outputs</span>} bodyClass="p-4 max-h-[640px] overflow-y-auto">
          <Timeline events={d.events} expandable />
        </Panel>
        <div className="space-y-4">
          <Panel title="Related entities">
            <div className="space-y-4">
              <EntityList title="Accounts" icon={Landmark} items={d.related_accounts} />
              <EntityList title="Devices" icon={Smartphone} items={d.related_devices} />
              <EntityList title="IP tokens" icon={Globe} items={d.related_ips} />
              <EntityList title="Customers (pseudonymous)" icon={User} items={d.related_customers} />
            </div>
          </Panel>
          <Panel title="Graph signals">
            {d.graph_signals.length === 0 ? <div className="text-xs text-fg-dim">No structural anomalies.</div> : (
              <ul className="space-y-1 text-sm">
                {d.graph_signals.map((g) => <li key={g.name} className="flex gap-2"><Cpu size={14} className="mt-0.5 text-accent" />{g.label}</li>)}
              </ul>
            )}
          </Panel>
          <Panel title="Analyst feedback">
            {d.analyst_feedback.length === 0 ? <div className="text-xs text-fg-dim">No analyst actions yet.</div> : (
              <ul className="space-y-2">
                {d.analyst_feedback.map((f) => (
                  <li key={f.id} className="text-xs border-l-2 border-accent/50 pl-2">
                    <div><span className="font-semibold">{f.action.replace(/_/g, " ")}</span> by {f.analyst} · {dateTime(f.created_at)}</div>
                    <div className="text-fg-dim">{f.previous_status} → {f.new_status}{f.notes ? ` · “${f.notes}”` : ""}</div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      <Panel title="Detector outputs (peak score per detector)">
        <DetectorOutputs results={latestPerDetector(d)} />
      </Panel>
    </div>
  );
}

function latestPerDetector(d: CaseDetail) {
  const best = new Map<string, CaseDetail["events"][number]["detector_results"][number]>();
  for (const ev of d.events) for (const r of ev.detector_results) {
    const cur = best.get(r.detector);
    if (!cur || r.score >= cur.score) best.set(r.detector, r);
  }
  return [...best.values()];
}
