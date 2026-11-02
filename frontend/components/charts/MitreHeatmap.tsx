import { MitreHeatmapEntry } from "@/types/threat";
import { cn } from "@/lib/utils";

export default function MitreHeatmap({ data }: { data: MitreHeatmapEntry[] }) {
  const max = Math.max(...data.map((entry) => entry.count), 1);
  return <div className="space-y-2">{data.length ? data.slice(0, 10).map((entry) => { const width = Math.max(4, Math.round((entry.count / max) * 100)); return <div key={entry.technique_id} title={entry.name} className="grid grid-cols-[4.5rem_1fr_2rem] items-center gap-3 font-mono text-[10px]"><span className="text-[#b58cff]">{entry.technique_id}</span><div className="h-2 bg-[#111111]"><div className="h-full bg-[#00ff41]" style={{ width: `${width}%` }} /></div><span className="text-right text-[#68717d]">{entry.count}</span></div>; }) : <p className="w-full py-4 text-center text-xs text-[#68717d]">No MITRE techniques yet.</p>}</div>;
}