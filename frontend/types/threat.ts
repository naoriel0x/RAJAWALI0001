export type ThreatLevel = "minimal" | "low" | "medium" | "high" | "critical";
export type ThreatCategory =
  | "reconnaissance"
  | "brute_force"
  | "exploitation"
  | "lateral_movement"
  | "exfiltration"
  | "apt"
  | "botnet"
  | "unknown";

export interface Threat {
  id: string;
  attacker_id: string;
  threat_level: ThreatLevel;
  threat_category: ThreatCategory;
  threat_score: number;
  is_human: number;
  human_confidence: number;
  mitre_tactics: string[];
  mitre_techniques: string[];
  kill_chain_phase: string | null;
  detected_tools: string[];
  timing_pattern: string | null;
  known_apt_group: string | null;
  avg_interval_ms: number | null;
  summary: string | null;
  recommendations: string[];
  analyzed_at: string;
}

export interface MitreHeatmapEntry {
  technique_id: string;
  name: string;
  count: number;
}

export interface DashboardStats {
  total_attackers: number;
  active_threats: number;
  blocked_ips: number;
  events_last_24h: number;
  critical_threats: number;
  top_countries: { country: string; count: number }[];
  attack_types_breakdown: Record<string, number>;
  mitre_heatmap: MitreHeatmapEntry[];
  recent_events: RecentEvent[];
  threat_score_avg: number;
}

export interface RecentEvent {
  id: string;
  event_type: string;
  src_ip: string;
  severity: string;
  timestamp: string;
  tool_detected?: string;
  mitre_technique?: string;
}