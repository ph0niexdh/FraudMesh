import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import type { EventRecord } from "../api/types";
import { qs } from "../api/client";
import { DetectorOutputs } from "../components/DetectorOutputs";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { EVENT_LABEL, dateTime, eventHeadline, inr, scoreColor } from "../lib/format";

const EMPTY = {
  customer: "", account: "", bank: "", device: "", ip: "", event_type: "", channel: "",
  since: "", until: "", min_risk: "", max_risk: "", suspicious: "", source: "",
};
const PAGE = 50;

function toIso(v: string) {
  return v ? new Date(v).toISOString() : "";
}

export function EventExplorer() {
  const [form, setForm] = useState(EMPTY);
  const [applied, setApplied] = useState(EMPTY);
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const path = `/api/events${qs({ ...applied, since: toIso(applied.since), until: toIso(applied.until), limit: PAGE, offset })}`;
  const { data, error, loading, reload } = useApi<{ total: number; events: EventRecord[] }>(path, {
    refreshOn: offset === 0 ? ["event.received", "demo.reset"] : [], throttleMs: 1200,
  });
  const set = (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    setApplied(form);
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Event Explorer</h1>
        <p className="text-sm text-fg-muted">Every normalized event with its detector outputs. Identifiers are tokens; synthetic demo labels may be used to filter (e.g. SBI-DEMO-1042, DEVICE-7F21).</p>
      </div>
      <Panel title="Filters">
        <form onSubmit={submit} className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-3">
          <div><label className="label">Customer</label><input className="input w-full" value={form.customer} onChange={set("customer")} placeholder="usr_… or CUSTOMER_…" /></div>
          <div><label className="label">Account</label><input className="input w-full" value={form.account} onChange={set("account")} placeholder="SBI-DEMO-1042" /></div>
          <div><label className="label">Bank</label>
            <select className="input w-full" value={form.bank} onChange={set("bank")}>
              <option value="">Any</option><option>SBI</option><option>HDFC Bank</option><option>ICICI Bank</option>
            </select></div>
          <div><label className="label">Device</label><input className="input w-full" value={form.device} onChange={set("device")} placeholder="DEVICE-7F21" /></div>
          <div><label className="label">IP</label><input className="input w-full" value={form.ip} onChange={set("ip")} placeholder="ip_… token" /></div>
          <div><label className="label">Event type</label>
            <select className="input w-full" value={form.event_type} onChange={set("event_type")}>
              <option value="">Any</option>
              {Object.entries(EVENT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select></div>
          <div><label className="label">Channel</label>
            <select className="input w-full" value={form.channel} onChange={set("channel")}>
              <option value="">Any</option><option>mobile</option><option>web</option><option>cloud</option>
            </select></div>
          <div><label className="label">From</label><input type="datetime-local" className="input w-full" value={form.since} onChange={set("since")} /></div>
          <div><label className="label">To</label><input type="datetime-local" className="input w-full" value={form.until} onChange={set("until")} /></div>
          <div><label className="label">Min risk</label><input type="number" min={0} max={100} className="input w-full" value={form.min_risk} onChange={set("min_risk")} /></div>
          <div><label className="label">Max risk</label><input type="number" min={0} max={100} className="input w-full" value={form.max_risk} onChange={set("max_risk")} /></div>
          <div><label className="label">Suspicious</label>
            <select className="input w-full" value={form.suspicious} onChange={set("suspicious")}>
              <option value="">Any</option><option value="true">Suspicious only</option><option value="false">Normal only</option>
            </select></div>
          <div><label className="label">Source</label>
            <select className="input w-full" value={form.source} onChange={set("source")}>
              <option value="">Any</option><option value="live">Live</option><option value="seed">Seeded history</option>
            </select></div>
          <div className="flex items-end gap-2">
            <button className="btn-primary" type="submit"><Search size={14} /> Apply</button>
            <button className="btn-ghost" type="button" onClick={() => { setForm(EMPTY); setApplied(EMPTY); setOffset(0); }}>Clear</button>
          </div>
        </form>
      </Panel>

      <Panel title={data ? `${data.total.toLocaleString()} events` : "Events"} bodyClass="p-0" right={data && (
        <div className="flex items-center gap-2 text-xs">
          <button className="btn-ghost !py-1" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Prev</button>
          <span className="text-fg-muted font-mono">{offset + 1}–{Math.min(offset + PAGE, data.total)}</span>
          <button className="btn-ghost !py-1" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
        </div>
      )}>
        {loading ? <Loading /> : error ? <ErrorState error={error} onRetry={() => reload()} /> : !data?.events.length ? (
          <Empty>No events match these filters.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-fg-muted">
                <tr className="border-b border-ink-700">
                  {["", "Time", "Event", "Bank", "Account", "Device", "IP", "Amount", "Signal", "Case"].map((h) => <th key={h} className="text-left font-medium px-3 py-2">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {data.events.map((e) => {
                  const isOpen = open === e.event_id;
                  return (
                    <Fragment key={e.event_id}>
                      <tr className="border-b border-ink-700/50 hover:bg-ink-800 cursor-pointer" onClick={() => setOpen(isOpen ? null : e.event_id)}>
                        <td className="pl-3">{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                        <td className="px-3 py-2 font-mono text-xs text-fg-muted whitespace-nowrap">{dateTime(e.timestamp)}</td>
                        <td className="px-3 py-2 font-medium whitespace-nowrap">{eventHeadline(e)}</td>
                        <td className="px-3 py-2 text-xs text-fg-muted whitespace-nowrap">{e.bank_name ?? "—"}</td>
                        <td className="px-3 py-2 font-mono text-xs">{e.account_label ?? "—"}</td>
                        <td className="px-3 py-2 font-mono text-xs">{e.device_label ?? "—"}</td>
                        <td className="px-3 py-2 font-mono text-xs text-fg-muted">{e.ip_label ?? "—"}</td>
                        <td className="px-3 py-2 font-mono text-xs">{e.event_type === "transaction" ? inr(e.amount) : ""}</td>
                        <td className="px-3 py-2 font-mono text-xs font-semibold" style={{ color: e.suspicious ? scoreColor(e.signal_score) : "#8a9bab" }}>{Math.round(e.signal_score * 100)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{e.case_id ? <Link to={`/cases/${e.case_id}`} className="text-accent" onClick={(ev) => ev.stopPropagation()}>{e.case_id}</Link> : ""}</td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-ink-900/60">
                          <td colSpan={10} className="px-4 py-3">
                            <div className="grid lg:grid-cols-2 gap-3">
                              <DetectorOutputs results={e.detector_results} />
                              <div className="text-xs">
                                <div className="panel-title mb-1">Normalized event (tokens only)</div>
                                <pre className="bg-ink-950 border border-ink-700 rounded-lg p-3 overflow-x-auto text-fg-muted">{JSON.stringify({
                                  event_id: e.event_id, event_type: e.event_type, timestamp: e.timestamp, customer_token: e.customer_token,
                                  account_token: e.account_token, device_token: e.device_token, ip_token: e.ip_token, channel: e.channel,
                                  amount: e.amount, metadata: e.metadata,
                                }, null, 2)}</pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
