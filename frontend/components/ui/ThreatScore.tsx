import { cn, scoreToLevel, threatColor } from "@/lib/utils";

export default function ThreatScore({ score, compact = false }: { score: number; compact?: boolean }) {
  const level = scoreToLevel(score);
  return <div className={cn("font-mono", compact ? "text-xs" : "text-lg")}><span className={cn("font-bold", threatColor(level))}>[ {score.toFixed(1)} ]</span>{!compact && <span className={cn("ml-2 text-[10px] uppercase tracking-wider", threatColor(level))}>{level}</span>}</div>;
}