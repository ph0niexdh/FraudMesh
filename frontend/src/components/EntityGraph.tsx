import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { useEffect, useRef } from "react";
import { Maximize2, ZoomIn, ZoomOut } from "lucide-react";
import type { GraphData, GraphEdge, GraphNode, SuspiciousPath } from "../api/types";

export const NODE_STYLE: Record<string, { color: string; shape: string; label: string }> = {
  customer: { color: "#60a5fa", shape: "ellipse", label: "Customer" },
  account: { color: "#2dd4bf", shape: "round-rectangle", label: "Account" },
  device: { color: "#fbbf24", shape: "diamond", label: "Device" },
  ip: { color: "#a78bfa", shape: "hexagon", label: "IP" },
  transaction: { color: "#34d399", shape: "tag", label: "Transaction" },
  kyc: { color: "#f472b6", shape: "star", label: "KYC record" },
  cloud_resource: { color: "#38bdf8", shape: "barrel", label: "Cloud resource" },
  cloud_principal: { color: "#7dd3fc", shape: "round-triangle", label: "Cloud principal" },
};

function nodeLabel(n: GraphNode): string {
  if (n.type === "account" && n.bank) return `${n.label}\n${n.bank}`;
  return n.label;
}

function isSuspicious(n: GraphNode): boolean {
  return n.watchlist || n.max_signal >= 0.5;
}

export type Selection = { kind: "node"; data: GraphNode } | { kind: "edge"; data: GraphEdge } | null;

export function EntityGraph({ data, paths = [], highlightPaths = true, height = 360, onSelect, focusIds = [] }: {
  data: GraphData | null;
  paths?: SuspiciousPath[];
  highlightPaths?: boolean;
  height?: number | string;
  onSelect?: (sel: Selection) => void;
  focusIds?: string[];
}) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      wheelSensitivity: 0.25,
      minZoom: 0.2,
      maxZoom: 3,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)", shape: "data(shape)" as any, width: 26, height: 26,
            label: "data(display)", color: "#c9d6df", "font-size": 9, "font-family": "Inter, sans-serif",
            "text-valign": "bottom", "text-margin-y": 4, "text-wrap": "wrap", "text-max-width": "110px",
            "border-width": 2, "border-color": "#0d141b", "text-outline-color": "#0a1016", "text-outline-width": 2,
          },
        },
        { selector: "node[?center]", style: { width: 32, height: 32 } },
        { selector: "node[?suspicious]", style: { "border-color": "#e11d48", "border-width": 3 } },
        { selector: "node[?watchlist]", style: { "border-style": "double", "border-width": 5 } },
        {
          selector: "edge",
          style: {
            width: 1.5, "line-color": "#2c3d4f", "target-arrow-color": "#2c3d4f", "target-arrow-shape": "triangle",
            "curve-style": "bezier", "arrow-scale": 0.7, label: "data(relation)", "font-size": 7, color: "#6b7f92",
            "text-rotation": "autorotate", "text-background-color": "#0d141b", "text-background-opacity": 1,
            "text-background-padding": "1px",
          },
        },
        { selector: ".path", style: { "line-color": "#e11d48", "target-arrow-color": "#e11d48", width: 3, color: "#fda4af" } },
        { selector: "node.path", style: { "border-color": "#e11d48", "border-width": 4 } },
        { selector: ".faded", style: { opacity: 0.25 } },
        { selector: ".new", style: { "overlay-color": "#2dd4bf", "overlay-opacity": 0.35, "overlay-padding": 6 } },
        { selector: ":selected", style: { "overlay-color": "#2dd4bf", "overlay-opacity": 0.2, "overlay-padding": 5 } },
      ],
    });
    cy.on("tap", "node", (e) => onSelectRef.current?.({ kind: "node", data: e.target.data("raw") }));
    cy.on("tap", "edge", (e) => onSelectRef.current?.({ kind: "edge", data: e.target.data("raw") }));
    cy.on("tap", (e) => e.target === cy && onSelectRef.current?.(null));
    cyRef.current = cy;
    return () => cy.destroy();
  }, []);

  // incremental updates so the audience sees the graph expand
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !data) return;
    const wanted = new Set<string>([...data.nodes.map((n) => n.id), ...data.edges.map((e) => e.id)]);
    const added: string[] = [];
    cy.batch(() => {
      cy.elements().forEach((el) => {
        if (!wanted.has(el.id())) el.remove();
      });
      const els: ElementDefinition[] = [];
      for (const n of data.nodes) {
        const st = NODE_STYLE[n.type] ?? { color: "#94a3b8", shape: "ellipse" };
        const d = { id: n.id, display: nodeLabel(n), color: st.color, shape: st.shape, suspicious: isSuspicious(n),
                    watchlist: n.watchlist, center: n.center, raw: n };
        const existing = cy.getElementById(n.id);
        if (existing.nonempty()) existing.data(d);
        else {
          els.push({ group: "nodes", data: d });
          added.push(n.id);
        }
      }
      for (const e of data.edges) {
        const existing = cy.getElementById(e.id);
        if (existing.nonempty()) existing.data("raw", e);
        else els.push({ group: "edges", data: { id: e.id, source: e.source, target: e.target, relation: e.relation, raw: e } });
      }
      cy.add(els);
    });
    if (added.length) {
      const firstRender = added.length === data.nodes.length;
      added.forEach((id) => {
        const el = cy.getElementById(id);
        el.addClass("new");
        window.setTimeout(() => el.removeClass("new"), 2200);
      });
      cy.layout({ name: "cose", animate: !firstRender, animationDuration: 600, randomize: firstRender, fit: true,
                  padding: 24, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, numIter: 1200 } as any).run();
    }
  }, [data]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("path faded");
    if (highlightPaths && paths.length) {
      const pathEls = cy.collection();
      for (const p of paths) {
        p.nodes.forEach((id, i) => {
          pathEls.merge(cy.getElementById(id));
          if (i > 0) {
            const a = p.nodes[i - 1];
            pathEls.merge(cy.edges().filter((e) =>
              (e.source().id() === a && e.target().id() === id) || (e.source().id() === id && e.target().id() === a)));
          }
        });
      }
      pathEls.addClass("path");
    }
    if (focusIds.length) {
      const focus = cy.collection();
      focusIds.forEach((id) => focus.merge(cy.getElementById(id)));
      cy.elements().not(focus.closedNeighborhood()).addClass("faded");
    }
  }, [paths, highlightPaths, data, focusIds]);

  const zoom = (f: number) => {
    const cy = cyRef.current;
    if (cy) cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  return (
    <div className="relative rounded-lg border border-ink-700 bg-ink-900" style={{ height }}>
      <div ref={ref} className="absolute inset-0" />
      <div className="absolute right-2 top-2 flex flex-col gap-1">
        <button className="btn-ghost !p-1.5" onClick={() => zoom(1.25)} aria-label="Zoom in"><ZoomIn size={14} /></button>
        <button className="btn-ghost !p-1.5" onClick={() => zoom(0.8)} aria-label="Zoom out"><ZoomOut size={14} /></button>
        <button className="btn-ghost !p-1.5" onClick={() => cyRef.current?.fit(undefined, 24)} aria-label="Fit"><Maximize2 size={14} /></button>
      </div>
      {data && data.nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-fg-dim">No entities to display.</div>
      )}
    </div>
  );
}

export function GraphLegend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-muted">
      {Object.entries(NODE_STYLE).map(([k, v]) => (
        <span key={k} className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: v.color }} /> {v.label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5">
        <span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-sev-critical" /> Suspicious
      </span>
      <span className="inline-flex items-center gap-1.5">
        <span className="inline-block h-0.5 w-4 bg-sev-critical" /> Suspicious path
      </span>
    </div>
  );
}
