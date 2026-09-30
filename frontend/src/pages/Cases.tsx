import { useState } from "react";
import { useNavigate } from "react-router-dom";
import type { CaseSummary } from "../api/types";
import { qs } from "../api/client";
import { Empty, ErrorState, Loading, Panel, SeverityBadge, StatusBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ago, scoreColor } from "../lib/format";

const STATUSES = ["active", "NEW", "INVESTIGATING", "HOLD", "RESOLVED", "FALSE_POSITIVE", "CONFIRMED_FRAUD"];

export function CasesPage() {
  const nav = useNavigate();
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [sort, setSort] = useState("updated");
  const { data, error, loading, reload } = useApi<{ cases: CaseSummary[] }>(
    `/api/cases${qs({ status, severity, sort, limit: 200 })}`,
    { refreshOn: ["case.created", "case.updated", "analyst.action", "demo.reset"] },
  );

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Case Investigation</h1>
        <p className="text-sm text-fg-muted">Correlated fraud cases built from related events, entities and time. Select a case to investigate.</p>
      </div>
      <Panel title="Cases" right={
        <div className="flex flex-wrap gap-2">
          <select className="input !py-1" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="status">
            <option value="">All statuses</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s === "active" ? "Active (open)" : s.replace(/_/g, " ")}</option>)}
          </select>
          <select className="input !py-1" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="severity">
            <option value="">All severities</option>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className="input !py-1" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="sort">
            <option value="updated">Recently updated</option>
            <option value="risk">Highest risk</option>
            <option value="created">Newest</option>
          </select>
        </div>
      } bodyClass="p-0">
        {loading ? <Loading /> : error ? <ErrorState error={error} onRetry={() => reload()} /> : !data?.cases.length ? (
          <Empty>No cases match these filters.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-fg-muted">
                <tr className="border-b border-ink-700">
                  {["Case", "Risk", "Severity", "Status", "Policy", "Events", "Banks", "Top signals", "Updated"].map((h) => (
                    <th key={h} className="text-left font-medium px-4 py-2">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.cases.map((c) => (
                  <tr key={c.case_id} onClick={() => nav(`/cases/${c.case_id}`)} className="border-b border-ink-700/50 hover:bg-ink-800 cursor-pointer">
                    <td className="px-4 py-2.5 font-mono text-accent">{c.case_id}</td>
                    <td className="px-4 py-2.5 font-mono font-semibold tabular-nums" style={{ color: scoreColor(c.risk_score / 100) }}>{Math.round(c.risk_score)}</td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={c.severity} /></td>
                    <td className="px-4 py-2.5"><StatusBadge status={c.status} /></td>
                    <td className="px-4 py-2.5 text-xs text-fg-muted whitespace-nowrap">{c.policy.action_label}{c.policy.analyst_override ? ` (analyst: ${c.policy.analyst_override})` : ""}</td>
                    <td className="px-4 py-2.5 font-mono">{c.event_count}</td>
                    <td className="px-4 py-2.5 text-xs text-fg-muted whitespace-nowrap">{c.banks.join(", ")}</td>
                    <td className="px-4 py-2.5 text-xs text-fg-muted max-w-[360px] truncate">{c.top_signals.slice(0, 3).join(" · ")}</td>
                    <td className="px-4 py-2.5 text-xs text-fg-dim whitespace-nowrap">{ago(c.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
