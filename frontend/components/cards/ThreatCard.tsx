import { ShieldAlert } from "lucide-react";
import { Threat } from "@/types/threat";
import { cn, threatBg, threatColor } from "@/lib/utils";
import Badge from "@/components/ui/Badge";
import ThreatScore from "@/components/ui/ThreatScore";

export default function ThreatCard({ threat }: { threat: Threat }) {
  return <article className={cn("border border-l-2 bg-[#0d0d0d] p-4 transition hover:border-[#00ff41]/30", threatBg(threat.threat_level), threat.threat_level === "critical" && "animate-pulse")}><div className="mb-3 flex items-start justify-between"><h3 className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-[#c9d1d9]"><ShieldAlert size={15} className={threatColor(threat.threat_level)} />Threat profile</h3><ThreatScore score={threat.threat_score} compact /></div><div className="mb-3 flex flex-wrap gap-2"><Badge tone={threat.threat_level === "critical" || threat.threat_level === "high" ? "danger" : "warning"}>{threat.threat_level}</Badge><Badge>{threat.threat_category.replace("_", " ")}</Badge></div><p className="text-xs leading-5 text-[#9da7b3]">{threat.summary ?? "No summary available."}</p>{threat.known_apt_group && <p className="mt-3 font-mono text-xs text-[#b58cff]">APT: {threat.known_apt_group}</p>}</article>;
}