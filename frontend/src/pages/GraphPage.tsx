import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { Search } from "lucide-react";
import type { CaseSummary, GraphData } from "../api/types";
import { qs } from "../api/client";
import { EntityGraph, GraphLegend, NODE_STYLE, type Selection } from "../components/EntityGraph";
import { ErrorState, Loading, Panel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { dateTime, inr } from "../lib/format";

export function SelectionDetails({ sel }: { sel: Selection }) {
  if (!sel) return <div className="text-xs text-fg-dim">Click a node or an edge to inspect it.</div>;
  if (sel.kind === "node") {
    const n = sel.data;
    const rows: [string, React.ReactNode][] = [
      ["Type", NODE_STYLE[n.type]?.label ?? n.type],
      ["Label", <span className="font-mono">{n.label}</span>],
      ["Token", <span className="font-mono text-fg-dim">{n.id}</span>],
      ...(n.bank ? [["Bank", n.bank] as [string, React.ReactNode]] : []),
      ...(n.city ? [["City", n.city] as [string, React.ReactNode]] : []),
      ...(n.amount ? [["Amount", inr(n.amount)] as [string, React.ReactNode]] : []),
      ["Degree", n.degree],
      ["Events", n.events],
      ["Max signal", n.max_signal.toFixed(2)],
      ["Watch-listed", n.watchlist ? "yes (confirmed fraud)" : "no"],
      ["First seen", dateTime(n.first_seen)],
      ["Last seen", dateTime(n.last_seen)],
    ];
    return (
      <div className="rounded-lg border border-ink-700 bg-ink-900 p-3">
        <div className="panel-title mb-2">Node details</div>
        <dl className="grid grid-cols-[100px_1fr] gap-y-1 text-xs">
          {rows.map(([k, v]) => <Fragment key={k}><dt className="text-fg-muted">{k}</dt><dd>{v}</dd></Fragment>)}
        </dl>
        {["account", "device", "ip", "customer"].includes(n.type) && (
          <Link className="text-xs text-accent mt-2 inline-block"
                to={`/events${qs({ [n.type === "customer" ? "customer" : n.type]: n.id })}`}>Open in Event Explorer →</Link>
        )}
      </div>
    );
  }
  const e = sel.data;
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900 p-3">
      <div className="panel-title mb-2">Edge details</div>
      <dl className="grid grid-cols-[100px_1fr] gap-y-1 text-xs">
        <dt className="text-fg-muted">Relation</dt><dd className="font-mono">{e.relation}</dd>
        <dt className="text-fg-muted">From</dt><dd className="font-mono">{e.source}</dd>
        <dt className="text-fg-muted">To</dt><dd className="font-mono">{e.target}</dd>
        <dt className="text-fg-muted">Observed</dt><dd>{e.count}×</dd>
        <dt className="text-fg-muted">First seen</dt><dd>{dateTime(e.first_seen)}</dd>
        <dt className="text-fg-muted">Last seen</dt><dd>{dateTime(e.last_seen)}</dd>
        <dt className="text-fg-muted">Events</dt><dd className="font-mono text-fg-dim break-all">{e.event_ids.join(", ")}</dd>
      </dl>
    </div>
  );
}

export function GraphPage() {
  const cases = useApi<{ cases: CaseSummary[] }>("/api/cases?status=active&sort=risk&limit=50", { refreshOn: ["case.created", "demo.reset"] });
  const [caseId, setCaseId] = useState("");
  const [entityInput, setEntityInput] = useState("");
  const [entity, setEntity] = useState("");
  const [depth, setDepth] = useState(2);
  const [showPaths, setShowPaths] = useState(true);
  const [sel, setSel] = useState<Selection>(null);
  const path = `/api/graph${qs({ case_id: caseId, entity: caseId ? "" : entity, depth, limit: 250 })}`;
  const graph = useApi<GraphData>(path, { refreshOn: ["graph.updated", "demo.reset"], throttleMs: 700 });
  const g = graph.data;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Entity Graph</h1>
        <p className="text-sm text-fg-muted">Customers, accounts, devices, IPs, transactions, KYC records and cloud resources linked by observed relationships. Synthetic demo graph.</p>
      </div>
      <Panel title="View" bodyClass="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[260px]">
            <label className="label">Case</label>
            <select className="input w-full" value={caseId} onChange={(e) => { setCaseId(e.target.value); setSel(null); }}>
              <option value="">All active cases (overview)</option>
              {(cases.data?.cases ?? []).map((c) => <option key={c.case_id} value={c.case_id}>{c.case_id} · risk {Math.round(c.risk_score)} · {c.banks.join("/")}</option>)}
            </select>
          </div>
          <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); setCaseId(""); setEntity(entityInput.trim()); setSel(null); }}>
            <div>
              <label className="label">Entity (token or synthetic label)</label>
              <input className="input w-64" value={entityInput} onChange={(e) => setEntityInput(e.target.value)} placeholder="DEVICE-7F21, SBI-DEMO-1042, dev_…" />
            </div>
            <button className="btn-ghost" type="submit"><Search size={14} /> Focus</button>
          </form>
          <div>
            <label className="label">Depth (entity view)</label>
            <select className="input" value={depth} onChange={(e) => setDepth(+e.target.value)}>
              {[1, 2, 3].map((d) => <option key={d}>{d}</option>)}
            </select>
          </div>
          <label className="flex items-center gap-2 text-xs text-fg-muted pb-2">
            <input type="checkbox" className="accent-rose-500" checked={showPaths} onChange={(e) => setShowPaths(e.target.checked)} />
            highlight suspicious paths
          </label>
        </div>
      </Panel>
      <div className="grid xl:grid-cols-[1fr_340px] gap-4">
        <Panel title={g ? `${g.nodes.length} nodes · ${g.edges.length} edges` : "Graph"}>
          {graph.error ? <ErrorState error={graph.error} onRetry={() => graph.reload()} /> : graph.loading && !g ? <Loading /> : (
            <>
              <EntityGraph data={g} paths={g?.suspicious_paths ?? []} highlightPaths={showPaths} height="min(70vh, 640px)" onSelect={setSel} />
              <div className="mt-2"><GraphLegend /></div>
            </>
          )}
        </Panel>
        <div className="space-y-4">
          <Panel title="Selection"><SelectionDetails sel={sel} /></Panel>
          <Panel title="Graph risk of focus">
            {g?.graph_risk ? (
              <div className="space-y-2 text-sm">
                <div className="font-mono text-2xl">{(g.graph_risk.score * 100).toFixed(0)}%</div>
                {g.graph_risk.signals.length === 0 ? <div className="text-xs text-fg-dim">No structural anomalies.</div> :
                  <ul className="space-y-1">{g.graph_risk.signals.map((s) => <li key={s.name} className="text-xs">• {s.label} <span className="text-fg-dim">(+{s.weight})</span></li>)}</ul>}
                <p className="text-[11px] text-fg-dim">noisy-OR: 1 − Π(1 − wᵢ)</p>
              </div>
            ) : <div className="text-xs text-fg-dim">—</div>}
          </Panel>
          <Panel title="Suspicious paths">
            {!g?.suspicious_paths?.length ? <div className="text-xs text-fg-dim">None in view.</div> : (
              <ul className="space-y-1 text-xs font-mono text-rose-200">{g.suspicious_paths.slice(0, 12).map((p, i) => <li key={i}>⟶ {p.description}</li>)}</ul>
            )}
          </Panel>
          {g?.stats && (
            <Panel title="Whole-graph stats">
              <div className="text-xs text-fg-muted space-y-0.5">
                <div>{g.stats.nodes} nodes · {g.stats.edges} edges · {g.stats.shared_devices} devices shared by ≥2 accounts</div>
                <div className="flex flex-wrap gap-x-3">{Object.entries(g.stats.by_type ?? {}).map(([k, v]) => <span key={k}>{k}: {String(v)}</span>)}</div>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
