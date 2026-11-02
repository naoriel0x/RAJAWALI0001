"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, Filter, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { RecentEvent } from "@/types/threat";
import { cn } from "@/lib/utils";
import AlertCard from "@/components/cards/AlertCard";
import LiveIndicator from "@/components/ui/LiveIndicator";

const filters = ["all", "critical", "high", "medium", "low", "info"] as const;
export default function AlertsPage() {
  const [events, setEvents] = useState<RecentEvent[]>([]);
  const [filter, setFilter] = useState<(typeof filters)[number]>("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => { setRefreshing(true); try { setEvents(await api.dashboard.getLiveFeed()); setError(null); } catch (err) { setError(err instanceof Error ? err.message : "Failed to load alerts."); } finally { setLoading(false); setRefreshing(false); } }, []);
  useEffect(() => { void load(); const timer = setInterval(() => void load(), 5000); return () => clearInterval(timer); }, [load]);
  const visible = useMemo(() => events.filter((event) => (filter === "all" || event.severity === filter) && `${event.src_ip} ${event.event_type} ${event.tool_detected ?? ""}`.toLowerCase().includes(query.toLowerCase())), [events, filter, query]);
  const criticalCount = events.filter((event) => event.severity === "critical").length;
  return <div className="min-h-screen p-4 sm:p-6">
    <header className="dashboard-panel mb-5 rounded-2xl p-5 sm:p-6"><div className="flex flex-wrap items-start justify-between gap-5"><div><div className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-[#82909b]"><ShieldAlert size={14} className="text-[#ff6b35]" />Threat monitoring <span className="text-[#3b5360]">/</span> live alerts</div><h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Alert center</h1><p className="mt-2 text-sm text-[#82909b]">Prioritize and investigate the latest signals captured by the deception layer.</p></div><div className="flex items-center gap-3"><LiveIndicator /><button onClick={() => void load()} disabled={refreshing} className="rounded-xl border border-[#263842] bg-[#101a20] p-2.5 text-[#82909b] hover:border-[#00ff41]/50 hover:text-[#00ff41]" title="Refresh alerts"><RefreshCw size={15} className={cn(refreshing && "animate-spin")} /></button></div></div><div className="mt-6 grid grid-cols-2 gap-3 border-t border-[#1c2a32] pt-4 sm:grid-cols-4"><div><p className="text-[10px] uppercase tracking-widest text-[#82909b]">Visible alerts</p><p className="mt-1 text-xl font-bold text-white">{visible.length}</p></div><div><p className="text-[10px] uppercase tracking-widest text-[#82909b]">Critical</p><p className="mt-1 text-xl font-bold text-[#ff6b35]">{criticalCount}</p></div><div><p className="text-[10px] uppercase tracking-widest text-[#82909b]">Refresh rate</p><p className="mt-1 text-xl font-bold text-[#00b4d8]">5s</p></div><div><p className="text-[10px] uppercase tracking-widest text-[#82909b]">Response</p><p className="mt-1 text-xl font-bold text-[#00ff41]">Active</p></div></div></header>
    <section className="dashboard-panel mb-4 rounded-xl p-3"><div className="flex flex-col gap-3 lg:flex-row lg:items-center"><div className="relative flex-1"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#50616b]" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IP, event type, or detected tool..." className="w-full rounded-lg border border-[#263842] bg-[#0a1115] py-2.5 pl-10 pr-3 text-sm text-white outline-none placeholder:text-[#50616b] focus:border-[#00b4d8]" /></div><div className="flex items-center gap-2 overflow-x-auto"><Filter size={14} className="shrink-0 text-[#82909b]" />{filters.map((item) => <button key={item} onClick={() => setFilter(item)} className={cn("rounded-lg px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition", filter === item ? "bg-[#ff6b35]/15 text-[#ff8c62]" : "text-[#82909b] hover:bg-[#16242c] hover:text-white")}>{item}</button>)}</div></div></section>
    {error && <p role="alert" className="mb-4 rounded-xl border border-[#ff6b35]/30 bg-[#ff6b35]/10 p-4 text-xs text-[#ff8c62]">{error}</p>}
    <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold text-white">Incoming telemetry</h2><p className="mt-1 text-xs text-[#82909b]">Newest events appear first</p></div><AlertTriangle size={17} className="text-[#ff6b35]" /></div><div className="space-y-2">{loading ? <p className="p-10 text-center text-xs text-[#00ff41]">Loading threat data...</p> : visible.map((event) => <div key={event.id} className="animate-[slideIn_300ms_ease-out]"><AlertCard event={event} /></div>)}{!loading && !error && visible.length === 0 && <p className="rounded-xl border border-dashed border-[#263842] p-12 text-center text-xs text-[#82909b]">No alerts match the current view.</p>}</div></section>
  </div>;
}
