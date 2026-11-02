import { cn } from "@/lib/utils";

type BadgeTone = "default" | "success" | "warning" | "danger" | "info";

const toneClasses: Record<BadgeTone, string> = {
  default: "border-[#2a2a2a] bg-[#151515] text-[#9da7b3]",
  success: "border-[#00ff41]/30 bg-[#00ff41]/5 text-[#00ff41]",
  warning: "border-[#ffb000]/30 bg-[#ffb000]/5 text-[#ffb000]",
  danger: "border-[#ff6b35]/40 bg-[#ff6b35]/10 text-[#ff8c62]",
  info: "border-[#00b4d8]/30 bg-[#00b4d8]/5 text-[#00b4d8]",
};

export default function Badge({
  children,
  tone = "default",
  className,
}: {
  children: React.ReactNode;
  tone?: BadgeTone;
  className?: string;
}) {
  return <span className={cn("inline-flex items-center border px-2 py-1 text-[10px] font-mono uppercase tracking-wider", toneClasses[tone], className)}>{children}</span>;
}