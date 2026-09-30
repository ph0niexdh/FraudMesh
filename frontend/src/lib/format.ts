export function inr(amount: number | null | undefined): string {
  if (amount === null || amount === undefined) return "—";
  return "₹" + Math.round(amount).toLocaleString("en-IN");
}

export function time(ts: string | null | undefined, seconds = true): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: seconds ? "2-digit" : undefined });
}

export function dateTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return `${d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" })} ${time(ts, false)}`;
}

export function ago(ts: string | null | undefined): string {
  if (!ts) return "—";
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const pct = (v: number | null | undefined, digits = 0) =>
  v === null || v === undefined ? "—" : `${(v * 100).toFixed(digits)}%`;

export const EVENT_LABEL: Record<string, string> = {
  transaction: "TRANSACTION",
  login: "LOGIN",
  device_change: "DEVICE CHANGE",
  mfa_reset: "MFA RESET",
  kyc_verification: "KYC",
  cloud_event: "CLOUD",
};

export const CHANNELS = ["transaction", "takeover", "kyc", "cloud", "graph", "temporal"] as const;
export const CHANNEL_LABEL: Record<string, string> = {
  transaction: "Transaction",
  takeover: "Takeover",
  kyc: "KYC / Media",
  cloud: "Cloud",
  graph: "Graph",
  temporal: "Temporal",
};

export function severityOf(score: number): string {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "MEDIUM";
  return "LOW";
}

export const SEV_COLOR: Record<string, string> = {
  LOW: "#10b981",
  MEDIUM: "#eab308",
  HIGH: "#f97316",
  CRITICAL: "#e11d48",
};

export function scoreColor(score01: number): string {
  return SEV_COLOR[severityOf(score01 * 100)];
}

export function humanize(s: string | null | undefined): string {
  if (!s) return "—";
  return s.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}

export function eventHeadline(e: { event_type: string; metadata?: Record<string, any> }): string {
  const sub = e.metadata?.subtype as string | undefined;
  if (sub && sub !== "PAYMENT" && sub !== "API_CALL") return sub.replace(/_/g, " ");
  return EVENT_LABEL[e.event_type] ?? e.event_type;
}
