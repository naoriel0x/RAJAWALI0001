"use client";
import { useEffect, useState } from "react";

export default function LiveIndicator() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="live-indicator flex items-center gap-2 rounded-full border border-[#00ff41]/20 bg-[#00ff41]/5 px-3 py-2">
      <span className="live-dot relative h-1.5 w-1.5 rounded-full bg-[#00ff41]" />
      <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-[#00ff41]">Live</span>
      <span className="font-mono text-[10px] text-[#82909b]">{time.toLocaleTimeString("en-GB")}</span>
    </div>
  );
}