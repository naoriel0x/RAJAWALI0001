import { AlertTriangle } from "lucide-react";
import { RecentEvent } from "@/types/threat";
import { EVENT_TYPE_LABELS } from "@/lib/constants";
import { cn, severityColor, timeAgo } from "@/lib/utils";

export default function AlertCard({ event }: { event: RecentEvent }) {
  const timestamp = new Date(event.timestamp).toLocaleTimeString("en-GB");
  return <article className="group flex items-center gap-3 rounded-lg border border-[#1c2a32] border-l-2 border-l-[#ff6b35] bg-[#0b1115]/80 p-3 transition hover:border-[#35515d] hover:bg-[#101a20]"><AlertTriangle size={15} className={severityColor(event.severity)} /><time className="hidden font-mono text-[10px] text-[#68717d] sm:block">[{timestamp}]</time><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2 font-mono text-[10px]"><span className={cn("border border-current px-1.5 py-0.5 uppercase", severityColor(event.severity))}>[{EVENT_TYPE_LABELS[event.event_type] ?? event.event_type}]</span><span className="text-[#00b4d8]">{event.src_ip}</span>{event.mitre_technique && <span className="text-[#b58cff]">({event.mitre_technique})</span>}{event.tool_detected && <span className="text-[#ffb000]">{"{"}{event.tool_detected}{"}"}</span>}</div></div><time className="text-[10px] text-[#68717d]">{timeAgo(event.timestamp)}</time></article>;
}