import Link from "next/link";
import { Eye, MapPin } from "lucide-react";
import { Attacker } from "@/types/attacker";
import { cn, scoreToLevel, threatColor } from "@/lib/utils";
import Badge from "@/components/ui/Badge";
import ThreatScore from "@/components/ui/ThreatScore";

export default function AttackerProfileCard({ attacker }: { attacker: Attacker }) {
  const level = scoreToLevel(attacker.threat_score);
  return <article className={cn("border border-[#1e1e1e] border-l-2 bg-[#0d0d0d] p-4 transition hover:border-[#00ff41]/30", attacker.status === "blocked" ? "border-l-[#ff6b35]" : "border-l-[#00ff41]")}><div className="flex items-start justify-between gap-3"><div><p className="font-mono text-sm text-[#00b4d8]">{attacker.ip_address}</p><p className="mt-1 flex items-center gap-1 text-xs text-[#68717d]"><MapPin size={12} />{attacker.country_name ?? attacker.country_code ?? "Unknown"}</p></div><ThreatScore score={attacker.threat_score} compact /></div><div className="mt-4 flex flex-wrap gap-2"><Badge tone={attacker.status === "blocked" ? "danger" : "success"}>{attacker.status}</Badge><span className={cn("font-mono text-xs capitalize", threatColor(level))}>{attacker.skill_level} skill</span><span className="font-mono text-xs text-[#68717d]">{attacker.total_events} events</span></div><Link href={`/attackers/${attacker.id}`} className="mt-4 inline-flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-[#00ff41] hover:text-white"><Eye size={13} /> View profile</Link></article>;
}