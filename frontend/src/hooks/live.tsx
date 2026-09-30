import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { LiveMessage } from "../api/types";

type Listener = (msg: LiveMessage) => void;

interface SimulationState {
  running: boolean;
  scenario?: string;
  steps?: { offset: number; title: string; narrative: string }[];
  index?: number;
  total?: number;
  title?: string;
  narrative?: string;
  case_id?: string | null;
  risk_score?: number | null;
  final?: any;
  error?: string;
}

interface LiveCtx {
  connected: boolean;
  feed: LiveMessage[];
  simulation: SimulationState;
  lastPipeline: { event_id: string; stages: Record<string, number>; received: number } | null;
  subscribe: (fn: Listener) => () => void;
}

const Ctx = createContext<LiveCtx | null>(null);
const FEED_TYPES = new Set([
  "event.received", "case.created", "case.updated", "policy.triggered", "analyst.action", "risk.updated",
  "simulation.started", "simulation.completed", "demo.reset", "model.retrained", "config.updated", "policy.updated",
]);

export function LiveProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [feed, setFeed] = useState<LiveMessage[]>([]);
  const [simulation, setSimulation] = useState<SimulationState>({ running: false });
  const [lastPipeline, setLastPipeline] = useState<LiveCtx["lastPipeline"]>(null);
  const listeners = useRef(new Set<Listener>());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: number | undefined;
    let ping: number | undefined;
    let closed = false;

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/events`);
      ws.onopen = () => {
        setConnected(true);
        ping = window.setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 20000);
      };
      ws.onclose = () => {
        setConnected(false);
        window.clearInterval(ping);
        if (!closed) retry = window.setTimeout(connect, 2000);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (e) => {
        let msg: LiveMessage;
        try {
          msg = JSON.parse(e.data);
        } catch {
          return;
        }
        if (FEED_TYPES.has(msg.type)) setFeed((f) => [msg, ...f].slice(0, 250));
        if (msg.type === "event.processed")
          setLastPipeline({ event_id: msg.data.event_id, stages: msg.data.stages, received: Date.now() });
        if (msg.type === "simulation.started")
          setSimulation({ running: true, scenario: msg.data.scenario, steps: msg.data.steps, index: -1,
                          total: msg.data.total_steps, case_id: null });
        if (msg.type === "simulation.step") setSimulation((s) => ({ ...s, running: true, ...msg.data }));
        if (msg.type === "simulation.completed" || msg.type === "simulation.failed")
          setSimulation((s) => ({ ...s, running: false, final: msg.data.final, error: msg.data.error }));
        if (msg.type === "demo.reset") setFeed([]);
        listeners.current.forEach((fn) => fn(msg));
      };
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(retry);
      window.clearInterval(ping);
      ws?.close();
    };
  }, []);

  const subscribe = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  return <Ctx.Provider value={{ connected, feed, simulation, lastPipeline, subscribe }}>{children}</Ctx.Provider>;
}

export function useLive(): LiveCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useLive outside LiveProvider");
  return ctx;
}

/** Run `fn` (throttled) whenever a live message of one of `types` arrives. */
export function useLiveRefresh(types: string[], fn: (msg: LiveMessage) => void, throttleMs = 600) {
  const { subscribe } = useLive();
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const key = types.join(",");
  useEffect(() => {
    let timer: number | undefined;
    let last: LiveMessage | null = null;
    const unsub = subscribe((msg) => {
      if (!key.split(",").includes(msg.type)) return;
      last = msg;
      if (timer) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        if (last) fnRef.current(last);
      }, throttleMs);
    });
    return () => {
      unsub();
      window.clearTimeout(timer);
    };
  }, [key, subscribe, throttleMs]);
}
