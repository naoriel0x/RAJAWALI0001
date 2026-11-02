import { Attacker } from "@/types/attacker";
import { cn, scoreToLevel, threatColor } from "@/lib/utils";

export default function AttackerStats({ attackers }: { attackers: Attacker[] }) {
  const counts = attackers.reduce<Record<string, number>>((result, attacker) => { result[scoreToLevel(attacker.threat_score)] = (result[scoreToLevel(attacker.threat_score)] ?? 0) + 1; return result; }, {});
  return <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">{["minimal", "low", "medium", "high", "critical"].map((level) => <div key={level} className="rounded-lg border border-[#1e2a3a] bg-[#111118] p-3"><p className={cn("text-xs capitalize", threatColor(level as Parameters<typeof threatColor>[0]))}>{level}</p><p className="mt-1 text-xl font-bold text-slate-200">{counts[level] ?? 0}</p></div>)}</div>;
}