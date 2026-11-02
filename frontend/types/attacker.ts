export type AttackerType = "human" | "bot" | "unknown";
export type SkillLevel = "low" | "medium" | "high" | "advanced";
export type AttackerStatus = "active" | "blocked" | "monitoring" | "resolved";

export interface Attacker {
  id: string;
  ip_address: string;
  hostname: string | null;
  country_code: string | null;
  country_name: string | null;
  isp: string | null;
  org: string | null;
  threat_score: number;
  attacker_type: AttackerType;
  skill_level: SkillLevel;
  status: AttackerStatus;
  tools_detected: string[];
  mitre_ttps: string[];
  mitre_stages: string[];
  total_events: number;
  ssh_attempts: number;
  http_attempts: number;
  login_attempts: number;
  commands_executed: number;
  is_known_malicious: number;
  abuse_confidence: number;
  is_blocked: number;
  is_tarpitted: number;
  first_seen: string;
  last_seen: string | null;
  blocked_at: string | null;
}

export interface AttackerListResponse {
  total: number;
  page: number;
  page_size: number;
  data: AttackerSummary[];
}

export interface AttackerSummary {
  id: string;
  ip_address: string;
  country_code: string | null;
  country_name: string | null;
  isp: string | null;
  org: string | null;
  threat_score: number;
  attacker_type: AttackerType;
  skill_level: SkillLevel;
  status: AttackerStatus;
  total_events: number;
  is_blocked: number;
  first_seen: string;
  last_seen: string | null;
}