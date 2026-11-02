import { RecentEvent } from "@/types/threat";
import { EVENT_TYPE_LABELS } from "@/lib/constants";
import { severityColor, timeAgo } from "@/lib/utils";

export default function ThreatTimeline({ events }: { events: RecentEvent[] }) {
  return <div className="space-y-3">{events.length ? events.map((event) => <div key={event.id} className="flex gap-3"><span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${event.severity === "critical" ? "bg-red-500" : event.severity === "high" ? "bg-orange-500" : "bg-blue-500"}`} /><div className="min-w-0 flex-1"><div className="flex justify-between gap-2 text-xs"><span className={severityColor(event.severity)}>{EVENT_TYPE_LABELS[event.event_type] ?? event.event_type}</span><time className="text-slate-600">{timeAgo(event.timestamp)}</time></div><p className="mt-1 font-mono text-xs text-slate-400">{event.src_ip}</p></div></div>) : <p className="text-center text-xs text-slate-600">No events yet.</p>}</div>;
}