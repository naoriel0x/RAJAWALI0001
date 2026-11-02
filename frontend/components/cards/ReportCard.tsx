import { Download, FileText } from "lucide-react";
import { api } from "@/lib/api";
import { scoreToLevel, threatColor } from "@/lib/utils";
import ThreatScore from "@/components/ui/ThreatScore";

export interface ReportCardData {
  attacker_id: string;
  ip: string;
  country: string | null;
  threat_score: number;
  status: string;
  total_events: number;
}

export default function ReportCard({ report }: { report: ReportCardData }) {
  const level = scoreToLevel(report.threat_score);
  return <article className="border border-[#1e1e1e] bg-[#0d0d0d] p-4 transition hover:border-[#00ff41]/30"><div className="flex items-start justify-between"><div><h3 className="flex items-center gap-2 font-mono text-sm text-[#c9d1d9]"><FileText size={15} className="text-[#00b4d8]" />{report.ip}</h3><p className="mt-1 text-xs text-[#68717d]">{report.country ?? "Unknown"} · {report.total_events} events</p></div><ThreatScore score={report.threat_score} compact /></div><p className={`mt-3 font-mono text-xs capitalize ${threatColor(level)}`}>{level} · {report.status}</p><a href={api.reports.download(report.attacker_id)} className="mt-4 inline-flex items-center gap-2 border border-[#00b4d8]/30 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-[#00b4d8] hover:bg-[#00b4d8]/10"><Download size={13} /> Download PDF</a></article>;
}