export interface Report {
  attacker_id: string;
  ip_address: string;
  generated_at: string;
  threat_score: number;
  threat_level: string;
  summary: string | null;
  recommendations: string[];
}

export interface ReportSummaryRow {
  id: string;
  ip: string;
  country: string | null;
  country_code: string | null;
  isp: string | null;
  org: string | null;
  threat_score: number;
  skill_level: string;
  attacker_type: string;
  status: string;
  total_events: number;
}

export interface ReportSummary {
  generated_at: string;
  system: string;
  total_attackers: number;
  attackers: ReportSummaryRow[];
}