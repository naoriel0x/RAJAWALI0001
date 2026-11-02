"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Ban,
  Clock3,
  Globe2,
  RefreshCw,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api";
import { DashboardStats, RecentEvent } from "@/types/threat";
import { APP_HEADLINE, EVENT_TYPE_LABELS, REFRESH_INTERVAL } from "@/lib/constants";
import { cn, timeAgo } from "@/lib/utils";
import LiveIndicator from "@/components/ui/LiveIndicator";
import MitreHeatmap from "@/components/charts/MitreHeatmap";
import AlertCard from "@/components/cards/AlertCard";

const statCards = [
  { key: "total_attackers", label: "Tracked attackers", icon: Users, color: "text-[#00b4d8]", helper: "all time" },
  { key: "active_threats", label: "Active threats", icon: AlertTriangle, color: "text-[#ff6b35]", helper: "under monitoring" },
  { key: "blocked_ips", label: "Blocked IPs", icon: Ban, color: "text-[#ff8c62]", helper: "response actions" },
  { key: "events_last_24h", label: "Events / 24h", icon: Activity, color: "text-[#00ff41]", helper: "recent telemetry" },
] as const;

const chartTooltip = {
  contentStyle: { background: "#0d1217", border: "1px solid #263842", borderRadius: 8, fontSize: 11 },
  labelStyle: { color: "#c9d1d9" },
};

function buildTimeline(events: RecentEvent[]) {
  const hours = Array.from({ length: 12 }, (_, index) => {
    const date = new Date(Date.now() - (11 - index) * 2 * 60 * 60 * 1000);
    return { key: date.toISOString().slice(0, 13), time: date.toLocaleTimeString("en", { hour: "2-digit" }), events: 0 };
  });
  events.forEach((event) => {
    const bucket = hours.find((item) => item.key === new Date(event.timestamp).toISOString().slice(0, 13));
    if (bucket) bucket.events += 1;
  });
  return hours;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [live, setLive] = useState<RecentEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [apiError, setApiError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setRefreshing(true);
    try {
      const [nextStats, nextLive] = await Promise.all([api.dashboard.getStats(), api.dashboard.getLiveFeed()]);
      setStats(nextStats);
      setLive(nextLive);
      setLastUpdate(new Date());
      setApiError(null);
    } catch (error) {
      console.error("Dashboard fetch error:", error);
      setApiError("The backend API is unavailable. Start the RAJAWALI services to load live threat data.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void fetchData();
    const interval = setInterval(() => void fetchData(), REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

  const attackTypeData = useMemo(
    () => (stats ? Object.entries(stats.attack_types_breakdown).map(([type, count]) => ({ name: EVENT_TYPE_LABELS[type] ?? type, count })).sort((a, b) => b.count - a.count).slice(0, 8) : []),
    [stats],
  );
  const severityData = useMemo(() => {
    const counts = live.reduce<Record<string, number>>((result, event) => {
      result[event.severity] = (result[event.severity] ?? 0) + 1;
      return result;
    }, {});
    return [
      { name: "Critical", value: counts.critical ?? 0, color: "#ef4444" },
      { name: "High", value: counts.high ?? 0, color: "#ff6b35" },
      { name: "Medium", value: counts.medium ?? 0, color: "#fbbf24" },
      { name: "Low / info", value: (counts.low ?? 0) + (counts.info ?? 0), color: "#00b4d8" },
    ].filter((item) => item.value > 0);
  }, [live]);
  const timelineData = useMemo(() => buildTimeline(live), [live]);

  if (loading) {
    return <div className="flex min-h-screen items-center justify-center"><div className="rounded-xl border border-[#1c2a32] bg-[#0d1217] p-8 font-mono text-xs leading-7 text-[#00ff41] shadow-2xl">Initializing operations center...<br />Loading threat telemetry...<span className="animate-pulse">_</span></div></div>;
  }

  return (
    <div className="min-h-screen p-4 sm:p-6">
      <header className="dashboard-panel scan-line mb-6 rounded-2xl p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div>
            <p className="font-mono text-xs text-[#82909b]">&gt;_ <span className="text-[#c9d1d9]">RAJAWALI</span> <span className="text-[#3b5360]">/</span> SECURE TELEMETRY</p>
            <h1 className="mt-3 text-2xl font-bold tracking-tight text-white sm:text-3xl">{APP_HEADLINE}</h1>
            <p className="mt-2 max-w-2xl text-sm text-[#82909b]">A live view of reconnaissance activity, deception coverage, and response posture across the monitored surface.</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden text-right sm:block"><p className="font-mono text-[10px] uppercase tracking-widest text-[#82909b]">Last sync</p><p className="mt-1 font-mono text-xs text-[#c9d1d9]">{timeAgo(lastUpdate.toISOString())}</p></div>
            <button onClick={() => void fetchData()} disabled={refreshing} className="rounded-lg border border-[#263842] bg-[#101a20] p-2.5 text-[#82909b] transition hover:border-[#00ff41]/50 hover:text-[#00ff41] disabled:opacity-50" title="Refresh telemetry"><RefreshCw size={15} className={cn(refreshing && "animate-spin")} /></button>
            <LiveIndicator />
          </div>
        </div>
        <div className="mt-6 grid gap-3 border-t border-[#1c2a32] pt-4 sm:grid-cols-3">
          <div className="flex items-center gap-2 text-xs text-[#82909b]"><ShieldCheck size={14} className="text-[#00ff41]" />Deception layer operational</div>
          <div className="flex items-center gap-2 text-xs text-[#82909b]"><Clock3 size={14} className="text-[#00b4d8]" />Auto-refresh every {REFRESH_INTERVAL / 1000}s</div>
          <div className="flex items-center gap-2 text-xs text-[#82909b]"><Globe2 size={14} className="text-[#b58cff]" />Global telemetry enabled</div>
        </div>
      </header>

      {apiError && <div role="alert" className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#ff6b35]/40 bg-[#ff6b35]/10 px-4 py-3"><p className="text-xs text-[#ff8c62]"><span className="font-bold">API OFFLINE</span> — {apiError}</p><button onClick={() => void fetchData()} className="rounded border border-[#ff6b35]/50 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-[#ff8c62] hover:bg-[#ff6b35]/10">Retry</button></div>}

      <div className="mb-6 grid grid-cols-2 gap-3 xl:grid-cols-4">
        {statCards.map(({ key, label, icon: Icon, color, helper }) => <div key={key} className="dashboard-panel rounded-xl p-4"><div className="flex items-center justify-between"><span className="text-[10px] font-semibold uppercase tracking-widest text-[#82909b]">{label}</span><Icon size={16} className={color} /></div><p className={cn("mt-4 text-3xl font-bold tracking-tight", color)}>{stats?.[key as keyof DashboardStats] as number}</p><div className="mt-3 flex items-center justify-between border-t border-[#1c2a32] pt-3 text-[10px] text-[#82909b]"><span>{helper}</span><span className="text-[#00ff41]">● monitored</span></div></div>)}
      </div>

      <div className="mb-4 grid gap-4 xl:grid-cols-[1.4fr_0.6fr]">
        <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-5 flex items-start justify-between"><div><h2 className="font-semibold text-white">Telemetry volume</h2><p className="mt-1 text-xs text-[#82909b]">Observed events across the last 24 hours</p></div><span className="rounded-full border border-[#00ff41]/30 bg-[#00ff41]/5 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-[#00ff41]">Live</span></div><ResponsiveContainer width="100%" height={250}><AreaChart data={timelineData}><defs><linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#00ff41" stopOpacity={0.3} /><stop offset="100%" stopColor="#00ff41" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#1c2a32" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" tick={{ fill: "#82909b", fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#82909b", fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip {...chartTooltip} /><Area type="monotone" dataKey="events" name="Events" stroke="#00ff41" strokeWidth={2} fill="url(#eventFill)" /></AreaChart></ResponsiveContainer></section>
        <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-2"><h2 className="font-semibold text-white">Severity mix</h2><p className="mt-1 text-xs text-[#82909b]">Current live feed</p></div>{severityData.length ? <ResponsiveContainer width="100%" height={210}><PieChart><Pie data={severityData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={78} paddingAngle={3}>{severityData.map((item) => <Cell key={item.name} fill={item.color} />)}</Pie><Tooltip {...chartTooltip} /><Legend verticalAlign="bottom" height={28} iconSize={8} formatter={(value) => <span className="text-[10px] text-[#82909b]">{value}</span>} /></PieChart></ResponsiveContainer> : <div className="flex h-[210px] items-center justify-center text-xs text-[#82909b]">No live severity data</div>}</section>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-5 flex items-center justify-between"><div><h2 className="font-semibold text-white">Attack vectors</h2><p className="mt-1 text-xs text-[#82909b]">Distribution by observed event type</p></div><span className="text-[10px] uppercase tracking-wider text-[#82909b]">24h window</span></div>{attackTypeData.length ? <ResponsiveContainer width="100%" height={250}><BarChart data={attackTypeData} layout="vertical" margin={{ left: 8, right: 12 }}><CartesianGrid stroke="#1c2a32" horizontal={false} /><XAxis type="number" allowDecimals={false} tick={{ fill: "#82909b", fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis type="category" dataKey="name" tick={{ fill: "#c9d1d9", fontSize: 10 }} width={110} axisLine={false} tickLine={false} /><Tooltip {...chartTooltip} cursor={{ fill: "#142027" }} /><Bar dataKey="count" name="Events" barSize={12} radius={[0, 4, 4, 0]}>{attackTypeData.map((_, index) => <Cell key={index} fill={index === 0 ? "#ff6b35" : index < 3 ? "#00b4d8" : "#00ff41"} />)}</Bar></BarChart></ResponsiveContainer> : <div className="flex h-[250px] items-center justify-center text-xs text-[#82909b]">No attack vector data</div>}</section>
        <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-5"><h2 className="font-semibold text-white">Top origins</h2><p className="mt-1 text-xs text-[#82909b]">Source geography by attacker count</p></div><div className="space-y-4">{stats?.top_countries?.length ? stats.top_countries.slice(0, 6).map((country, index) => { const pct = Math.round((country.count / (stats.top_countries[0]?.count || 1)) * 100); return <div key={country.country} className="grid grid-cols-[1.5rem_2rem_1fr_2rem] items-center gap-2 text-xs"><span className="font-mono text-[#82909b]">{String(index + 1).padStart(2, "0")}</span><span className="font-semibold text-white">{country.country ?? "??"}</span><div className="h-1.5 overflow-hidden rounded-full bg-[#142027]"><div className="h-full rounded-full bg-gradient-to-r from-[#00b4d8] to-[#00ff41]" style={{ width: `${pct}%` }} /></div><span className="text-right font-mono text-[#82909b]">{country.count}</span></div>; }) : <div className="py-20 text-center text-xs text-[#82909b]">No origin data</div>}</div></section>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold text-white">Live event feed</h2><p className="mt-1 text-xs text-[#82909b]">Newest activity from the deception layer</p></div><span className="font-mono text-[10px] text-[#82909b]">AUTO {REFRESH_INTERVAL / 1000}s</span></div><div className="space-y-1">{live.length ? live.slice(0, 8).map((event) => <AlertCard key={event.id} event={event} />) : <p className="py-8 text-center text-xs text-[#82909b]">Waiting for events...</p>}</div></section>
        <section className="dashboard-panel rounded-xl p-4 sm:p-5"><div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold text-white">MITRE ATT&amp;CK coverage</h2><p className="mt-1 text-xs text-[#82909b]">Technique frequency from telemetry</p></div><span className="text-[10px] font-semibold uppercase tracking-wider text-[#b58cff]">Tactics</span></div><MitreHeatmap data={stats?.mitre_heatmap ?? []} /></section>
      </div>
    </div>
  );
}
