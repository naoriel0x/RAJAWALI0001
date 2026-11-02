export const APP_NAME = "RAJAWALI";
export const APP_TAGLINE = "Reconnaissance Awareness & Judgment for Active Warfare Intelligence";
export const APP_HEADLINE = "OPERATIONS CENTER";
export const APP_DESCRIPTION = "Preemptive cyber defense through deception technology and behavioral threat intelligence.";

export const REFRESH_INTERVAL = 10000;

export const THREAT_LEVELS = ["minimal", "low", "medium", "high", "critical"] as const;

export const EVENT_TYPE_LABELS: Record<string, string> = {
  port_scan: "Port Scan",
  dns_recon: "DNS Recon",
  banner_grab: "Banner Grab",
  threat_intel: "Threat Intel",
  ssh_connect: "SSH Connect",
  ssh_login: "SSH Login",
  ssh_command: "SSH Command",
  http_request: "HTTP Request",
  http_crawl: "HTTP Crawl",
  lure_access: "Lure Access",
  ip_blocked: "IP Blocked",
  tarpit_applied: "Tarpit",
  fake_intel_fed: "Fake Intel Fed",
};

export const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: "LayoutDashboard" },
  { href: "/attackers", label: "Attackers", icon: "Users" },
  { href: "/alerts", label: "Alerts", icon: "Bell" },
  { href: "/reports", label: "Reports", icon: "FileText" },
];