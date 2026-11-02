import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { ThreatLevel } from "@/types/threat";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function threatColor(level: ThreatLevel): string {
  const map: Record<ThreatLevel, string> = {
    critical: "text-[#ff6b35]",
    high: "text-[#ff8c62]",
    medium: "text-[#ffb000]",
    low: "text-[#00ff41]",
    minimal: "text-[#68717d]",
  };
  return map[level] ?? "text-[#68717d]";
}

export function threatBg(level: ThreatLevel): string {
  const map: Record<ThreatLevel, string> = {
    critical: "bg-[#ff6b35]/10 border-[#ff6b35]/50",
    high: "bg-[#ff8c62]/10 border-[#ff8c62]/40",
    medium: "bg-[#ffb000]/10 border-[#ffb000]/40",
    low: "bg-[#00ff41]/5 border-[#00ff41]/30",
    minimal: "bg-[#68717d]/10 border-[#68717d]/30",
  };
  return map[level] ?? "bg-[#68717d]/10";
}

export function scoreToLevel(score: number): ThreatLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "minimal";
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "text-[#ff6b35]",
    high: "text-[#ff8c62]",
    medium: "text-[#ffb000]",
    low: "text-[#00ff41]",
    info: "text-[#68717d]",
  };
  return map[severity] ?? "text-[#68717d]";
}