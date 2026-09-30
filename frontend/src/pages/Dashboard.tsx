import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { Bar, BarChart, ResponsiveContainer, Tooltip } from "recharts";
import type { CaseDetail, CaseSummary, Metrics } from "../api/types";
import { ChannelScores } from "../components/ChannelScores";
import { CaseActions, RiskTrajectory, WhyFlagged } from "../components/CaseParts";
import { EntityGraph, GraphLegend } from "../components/EntityGraph";
import { LiveStream } from "../components/LiveStream";
import { PipelineStrip } from "../components/PipelineStrip";
import { RiskGauge } from "../components/RiskGauge";
import { SimulationPanel } from "../components/SimulationPanel";
import { Timeline } from "../components/Timeline";
import { Empty, ErrorState, Loading, Panel, PolicyBadge, SeverityBadge, StatusBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useLive, useLiveRefresh } from "../hooks/live";
import { dateTime } from "../lib/format";

const LIVE_TYPES = ["event.received", "case.created", "case.updated", "analyst.action", "demo.reset"];

function Kpi({ label, value, hint, accent, children }: { label: string; value: string | number; hint?: string; accent?: string; children?: React.ReactNode }) {
  return (
    <div className="panel px-4 py-3 min-w-0">
      <div className="text-[11px] uppercase tracking-wider text-fg-muted truncate">{label}</div>
      <div className="flex items-end justify-between gap-2">
        <div className="font-mono text-2xl font-semibold tabular-nums mt-1" style={accent ? { color: accent } : undefined}>{value}</div>
        {children}
      </div>
      {hint && <div className="text-[11px] text-fg-dim truncate">{hint}</div>}
    </div>
  );
}

function Spark({ series }: { series: number[] }) {
  const data = series.map((v, i) => ({ i, v, label: `${30 - i} min ago` }));
  return (
    <div className="h-8 w-24">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} barCategoryGap={1}>
          <Tooltip cursor={false} contentStyle={{ background: "#0a1016", border: "1px solid #263545", borderRadius: 6, fontSize: 11 }}
                   labelFormatter={(_, p) => (p?.[0]?.payload?.label ?? "")} formatter={(v: number) => [v, "events"]} />
          <Bar dataKey="v" fill="#2dd4bf" radius={[2, 2, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function Dashboard() {
  const live = useLive();
  const metrics = useApi<Metrics>("/api/metrics", { refreshOn: LIVE_TYPES, throttleMs: 800 });
  const top = useApi<{ cases: CaseSummary[] }>("/api/cases?status=active&sort=risk&limit=1", { refreshOn: ["case.created", "analyst.action", "demo.reset"] });
  const [focus, setFocus] = useState<string | null>(null);
  const [newestEvent, setNewestEvent] = useState<string | null>(null);

  // follow the case that is developing live; otherwise spotlight the highest-risk active case
  useLiveRefresh(["case.created", "case.updated"], (m) => setFocus(m.data.case_id), 50);
  useLiveRefresh(["event.received"], (m) => setNewestEvent(m.data.event_id), 50);
  useLiveRefresh(["demo.reset"], () => setFocus(null), 50);
  useEffect(() => {
    if (!focus && top.data?.cases[0]) setFocus(top.data.cases[0].case_id);
  }, [focus, top.data]);
  useEffect(() => {
    if (live.simulation.case_id) setFocus(live.simulation.case_id);
  }, [live.simulation.case_id]);

  const detail = useApi<CaseDetail>(focus ? `/api/cases/${focus}` : null, {
    refreshOn: ["case.updated", "case.created", "analyst.action"], throttleMs: 300,
  });
  const m = metrics.data;
  const d = detail.data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-3">
        {m ? (
          <>
            <Kpi label="Active cases" value={m.active_cases} hint="NEW · INVESTIGATING · HOLD" />
            <Kpi label="High-risk cases" value={m.high_risk_cases} hint="active, risk ≥ 60" accent={m.high_risk_cases ? "#f97316" : undefined} />
            <Kpi label="Events / min" value={m.events_per_minute} hint="last 60 s (received)"><Spark series={m.events_per_minute_series} /></Kpi>
            <Kpi label="Cases today" value={m.cases_today} hint="UTC day" />
            <Kpi label="Confirmed fraud" value={m.confirmed_fraud} hint="analyst-confirmed" accent={m.confirmed_fraud ? "#e11d48" : undefined} />
            <Kpi label="False positives" value={m.false_positives} hint="marked legitimate" />
            <Kpi label="Avg risk score" value={m.average_risk_score.toFixed(1)} hint={`${m.alerts_merged_per_case} events merged / case`} />
          </>
        ) : metrics.error ? (
          <div className="col-span-full"><ErrorState error={metrics.error} onRetry={() => metrics.reload()} /></div>
        ) : (
          <div className="col-span-full"><Loading label="Loading metrics…" /></div>
        )}
      </div>

      <Panel title="Attack simulation" right={<PipelineStrip />} bodyClass="p-4">
        <SimulationPanel />
      </Panel>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-4">
        <div className="space-y-4 min-w-0">
          {!focus ? (
            <Panel title="Risk case"><Empty>No active cases. Start the simulated attack to watch one develop.</Empty></Panel>
          ) : detail.error ? (
            <Panel title="Risk case"><ErrorState error={detail.error} onRetry={() => detail.reload()} /></Panel>
          ) : !d ? (
            <Panel title="Risk case"><Loading /></Panel>
          ) : (
            <>
              <Panel title={<span>Risk case <span className="text-fg font-mono">#{d.case_id}</span></span>}
                     right={<Link to={`/cases/${d.case_id}`} className="text-xs text-accent inline-flex items-center gap-1">Investigate <ArrowUpRight size={13} /></Link>}>
                <div className="grid md:grid-cols-[240px_1fr] gap-6 items-center">
                  <div className="flex flex-col items-center gap-2">
                    <RiskGauge score={d.risk_score} severity={d.severity} size={220} />
                    <SeverityBadge severity={d.severity} large />
                    <div className="flex flex-wrap justify-center gap-1.5">
                      <StatusBadge status={d.status} />
                      <PolicyBadge label={d.policy.action_label} />
                    </div>
                  </div>
                  <div className="min-w-0 space-y-2">
                    <div className="text-sm text-fg-muted">{d.summary}</div>
                    <div className="text-xs text-fg-dim">
                      {d.event_count} correlated events · banks {d.banks.join(", ") || "—"} · opened {dateTime(d.created_at)} · confidence {(d.confidence * 100).toFixed(0)}%
                    </div>
                    <div className="text-[11px] uppercase tracking-wider text-fg-muted pt-1">Unified risk as evidence arrived</div>
                    <RiskTrajectory detail={d} height={140} />
                  </div>
                </div>
              </Panel>

              <div className="grid lg:grid-cols-2 gap-4">
                <Panel title="Channel scores"><ChannelScores scores={d.channel_scores} /></Panel>
                <Panel title="Attack timeline" bodyClass="p-4 max-h-[320px] overflow-y-auto">
                  <Timeline events={d.events} highlight={newestEvent} />
                </Panel>
              </div>

              <Panel title="Entity graph" right={<span className="text-[11px] text-fg-dim">synthetic demo graph · scroll to zoom · drag to pan</span>}>
                <EntityGraph data={d.graph} paths={d.suspicious_paths} height={340} />
                <div className="mt-2"><GraphLegend /></div>
              </Panel>

              <Panel title="Why flagged?">
                <WhyFlagged items={d.explanations} limit={8} />
                <div className="mt-4 pt-4 border-t border-ink-700">
                  <CaseActions caseId={d.case_id} onDone={() => detail.reload(true)} />
                </div>
              </Panel>
            </>
          )}
        </div>
        <Panel title="Live event stream" className="xl:sticky xl:top-20 xl:h-[calc(100vh-7rem)] h-[480px]" bodyClass="p-3 h-full">
          <LiveStream />
        </Panel>
      </div>
    </div>
  );
}
