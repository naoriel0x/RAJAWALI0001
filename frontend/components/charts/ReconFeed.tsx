import { RecentEvent } from "@/types/threat";
import AlertCard from "@/components/cards/AlertCard";

export default function ReconFeed({ events }: { events: RecentEvent[] }) {
  const reconEvents = events.filter((event) => event.event_type === "port_scan" || event.event_type === "dns_recon" || event.event_type === "banner_grab");
  return <div className="space-y-1">{reconEvents.length ? reconEvents.map((event) => <AlertCard key={event.id} event={event} />) : <p className="py-4 text-center text-xs text-[#68717d]">No reconnaissance events yet.</p>}</div>;
}