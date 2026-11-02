import { AttackerListResponse, Attacker } from "@/types/attacker";
import { DashboardStats, Threat, RecentEvent } from "@/types/threat";
import { ReportSummary } from "@/types/report";

const BASE = process.env.NEXT_PUBLIC_API_URL || "";

function headers(contentType = false): HeadersInit {
  return contentType ? { "Content-Type": "application/json" } : {};
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    cache: "no-store",
    credentials: "include",
    headers: headers(),
  });
  if (res.status === 401 && typeof window !== "undefined") window.location.assign("/login");
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`);
  return res.json();
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: headers(true),
    credentials: "include",
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (res.status === 401 && typeof window !== "undefined") window.location.assign("/login");
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`);
  return res.json();
}

export async function login(username: string, password: string): Promise<void> {
  const body = new URLSearchParams({ username, password });
  const res = await fetch(`${BASE}/api/auth/token`, {
    method: "POST",
    body,
    credentials: "include",
  });
  if (!res.ok) throw new Error("Invalid username or password");
}

export const api = {
  dashboard: {
    getStats: () => get<DashboardStats>("/api/dashboard"),
    getLiveFeed: () => get<RecentEvent[]>("/api/dashboard/live"),
  },
  attackers: {
    list: (page = 1, pageSize = 20) =>
      get<AttackerListResponse>(`/api/threats/attackers?page=${page}&page_size=${pageSize}`),
    get: (id: string) => get<Attacker>(`/api/threats/attackers/${id}`),
    block: (id: string) => post(`/api/threats/attackers/${id}/block`),
  },
  threats: {
    listProfiles: () => get<Threat[]>("/api/threats/profiles"),
    getProfile: (attackerId: string) => get<Threat>(`/api/threats/profiles/${attackerId}`),
    analyze: (attackerId: string) => post(`/api/profiler/analyze/${attackerId}`),
  },
  reports: {
    download: (attackerId: string) => `${BASE}/api/reports/attacker/${attackerId}/pdf`,
    downloadPdf: async (attackerId: string) => {
      const res = await fetch(`${BASE}/api/reports/attacker/${attackerId}/pdf`, {
        credentials: "include",
      });
      if (res.status === 401 && typeof window !== "undefined") window.location.assign("/login");
      if (!res.ok) throw new Error(`API error ${res.status}: report`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `rajawali-report-${attackerId}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    },
    summary: () => get<ReportSummary>("/api/reports/summary/json"),
  },
};
