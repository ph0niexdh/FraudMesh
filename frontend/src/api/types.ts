export interface SignalDetail {
  name: string;
  label?: string;
  weight?: number;
  value?: number | string;
  points?: number;
  current_event?: boolean;
  [k: string]: unknown;
}

export interface DetectorResult {
  score: number;
  confidence: number;
  signals: string[];
  detector: string;
  timestamp: string;
  channel: string;
  model_version: string;
  signal_details: SignalDetail[];
  details: Record<string, any>;
  latency_ms: number;
}

export interface EventRecord {
  event_id: string;
  event_type: string;
  timestamp: string;
  received_at: string;
  customer_token: string | null;
  account_token: string | null;
  device_token: string | null;
  ip_token: string | null;
  customer_label: string | null;
  account_label: string | null;
  device_label: string | null;
  ip_label: string | null;
  channel: string;
  bank_name: string | null;
  amount: number;
  metadata: Record<string, any>;
  signal_score: number;
  suspicious: boolean;
  detector_results: DetectorResult[];
  case_id: string | null;
  source: string;
}

export interface Policy {
  action: string;
  action_label: string;
  reason: string;
  policy_id: string;
  threshold: number;
  severity: string;
  analyst_override?: string;
}

export type ChannelScores = Record<"transaction" | "takeover" | "kyc" | "cloud" | "graph" | "temporal", number>;

export interface CaseSummary {
  case_id: string;
  risk_score: number;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  first_event_at: string;
  last_event_at: string;
  channel_scores: ChannelScores;
  graph_score: number;
  temporal_score: number;
  confidence: number;
  policy_action: string;
  policy: Policy;
  summary: string;
  banks: string[];
  scenario: string | null;
  source: string;
  event_count: number | null;
  top_signals: string[];
}

export interface Explanation {
  rank: number;
  signal: string;
  text: string;
  channel: string;
  channel_name: string;
  detector: string;
  contribution: number;
  detector_score: number;
  event_id: string | null;
  event_type: string | null;
  timestamp: string | null;
  value: unknown;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  bank: string | null;
  city: string | null;
  amount: number | null;
  beneficiary: boolean;
  watchlist: boolean;
  max_signal: number;
  degree: number;
  events: number;
  first_seen: string | null;
  last_seen: string | null;
  center: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  count: number;
  first_seen: string;
  last_seen: string;
  event_ids: string[];
}

export interface SuspiciousPath {
  nodes: string[];
  hub: string;
  description: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  suspicious_paths?: SuspiciousPath[];
  graph_risk?: { score: number; signals: SignalDetail[] };
  stats?: Record<string, any>;
  centers?: string[];
}

export interface Entity {
  token: string;
  type: string;
  label: string | null;
  bank: string | null;
  via_graph?: boolean;
}

export interface Feedback {
  id: number;
  case_id: string;
  action: string;
  previous_status: string | null;
  new_status: string | null;
  analyst: string;
  notes: string;
  created_at: string;
}

export interface CaseDetail extends CaseSummary {
  events: EventRecord[];
  entities: Entity[];
  related_accounts: Entity[];
  related_devices: Entity[];
  related_ips: Entity[];
  related_customers: Entity[];
  explanations: Explanation[];
  contributions: Record<string, number>;
  graph_signals: SignalDetail[];
  detector_outputs: { event_id: string; event_type: string; timestamp: string; results: DetectorResult[] }[];
  risk_history: { event_id: string; risk_score: number; timestamp: string; channel_scores: ChannelScores; policy_action: string }[];
  analyst_feedback: Feedback[];
  graph: GraphData;
  suspicious_paths: SuspiciousPath[];
  fusion_weights: Record<string, number>;
}

export interface Metrics {
  active_cases: number;
  high_risk_cases: number;
  events_per_minute: number;
  cases_today: number;
  confirmed_fraud: number;
  false_positives: number;
  average_risk_score: number;
  total_cases: number;
  total_events: number;
  suspicious_events: number;
  events_by_type: Record<string, number>;
  events_by_bank: Record<string, number>;
  open_cases_by_severity: Record<string, number>;
  cases_by_status: Record<string, number>;
  alerts_merged_per_case: number;
  avg_investigation_minutes: number | null;
  events_per_minute_series: number[];
  pipeline_latency_ms: { avg: number | null; p95: number | null; samples: number };
  case_construction_latency_ms: { avg: number | null; samples: number };
  websocket_clients: number | null;
}

export interface FusionConfig {
  weights: Record<string, number>;
  temporal_window_minutes: number;
  suspicious_event_threshold: number;
  min_correlated_signals: number;
  case_creation_min_risk: number;
  weights_sum?: number;
  note?: string;
  formula?: string;
}

export interface PolicyTier {
  policy_id: string;
  severity: string;
  min_score: number;
  max_score: number;
  action: string;
}

export interface PolicyConfig {
  tiers: PolicyTier[];
  action_labels: Record<string, string>;
}

export interface LiveMessage {
  type: string;
  data: any;
  server_ts?: string;
}
