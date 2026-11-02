"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";
import { ArrowUpRight, Bell, FileText, LayoutDashboard, Shield, Users } from "lucide-react";
import { cn } from "@/lib/utils";
import HeadlineLogo from "../../app/Headline.png";

const navItems = [
  { href: "/dashboard", label: "Overview", hint: "Command center", icon: LayoutDashboard },
  { href: "/attackers", label: "Attackers", hint: "Threat actors", icon: Users },
  { href: "/alerts", label: "Alerts", hint: "Live telemetry", icon: Bell },
  { href: "/reports", label: "Reports", hint: "Intel exports", icon: FileText },
];

export default function Sidebar() {
  const pathname = usePathname();
  return (
    <>
      <aside className="fixed inset-y-0 left-0 z-50 hidden w-64 flex-col border-r border-[#1c2a32] bg-[#080d11]/90 p-4 backdrop-blur-2xl lg:flex">
        <Link href="/dashboard" aria-label="RAJAWALI Defense Intelligence home" className="group mb-8 block transition duration-300 hover:-translate-y-0.5">
          <Image
            src={HeadlineLogo}
            alt="RAJAWALI Defense Intelligence"
            priority
            className="h-auto w-[calc(100%+2rem)] max-w-none -translate-x-4 object-contain transition duration-300 group-hover:brightness-110"
          />
        </Link>
        <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-[#50616b]">Workspace</div>
        <nav className="space-y-2">
          {navItems.map(({ href, label, hint, icon: Icon }) => {
            const active = pathname.startsWith(href);
            return <Link key={href} href={href} className={cn("nav-item group relative flex items-center gap-3 overflow-hidden rounded-xl px-3 py-3", active ? "nav-item-active text-[#00ff41]" : "text-[#82909b]")}><span className={cn("nav-icon relative z-10 flex h-9 w-9 items-center justify-center rounded-lg", active ? "bg-[#00ff41]/10" : "bg-[#101a20]")}><Icon size={17} /></span><span className="relative z-10 min-w-0"><span className="block text-sm font-medium">{label}</span><span className="mt-0.5 block text-[10px] text-[#50616b]">{hint}</span></span><ArrowUpRight size={14} className="nav-arrow absolute right-3 z-10 text-[#00ff41]" /></Link>;
          })}
        </nav>
        <div className="sidebar-utility mt-auto rounded-2xl border border-[#1c2a32] bg-gradient-to-br from-[#0d151a] to-[#0a1115] p-4">
          <div className="mb-3 flex items-center justify-between"><span className="text-[10px] font-semibold uppercase tracking-widest text-[#82909b]">Operator shortcuts</span><ArrowUpRight size={14} className="text-[#00b4d8]" /></div>
          <div className="space-y-1">
            <Link href="/alerts" className="utility-link flex items-center justify-between rounded-lg px-2 py-2 text-[11px] text-[#82909b]"><span>Review live alerts</span><span className="text-[#ff8c62]">→</span></Link>
            <Link href="/attackers" className="utility-link flex items-center justify-between rounded-lg px-2 py-2 text-[11px] text-[#82909b]"><span>Investigate actors</span><span className="text-[#00b4d8]">→</span></Link>
            <Link href="/reports" className="utility-link flex items-center justify-between rounded-lg px-2 py-2 text-[11px] text-[#82909b]"><span>Export intelligence</span><span className="text-[#b58cff]">→</span></Link>
          </div>
        </div>
      </aside>
      <nav className="fixed inset-x-3 bottom-3 z-50 flex items-center justify-around rounded-2xl border border-[#263842] bg-[#0b1419]/95 p-2 shadow-2xl backdrop-blur-xl lg:hidden">
        {navItems.map(({ href, label, icon: Icon }) => { const active = pathname.startsWith(href); return <Link key={href} href={href} aria-label={label} className={cn("flex min-w-[4rem] flex-col items-center gap-1 rounded-xl px-3 py-2 text-[10px] transition", active ? "bg-[#00ff41]/10 text-[#00ff41]" : "text-[#82909b]")}><Icon size={17} /><span>{label}</span></Link>; })}
      </nav>
    </>
  );
}
