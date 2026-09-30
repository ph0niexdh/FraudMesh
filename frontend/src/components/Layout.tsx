import { NavLink, Outlet } from "react-router-dom";
import { Activity, Briefcase, Cpu, LayoutDashboard, ListFilter, Network, SlidersHorizontal } from "lucide-react";
import { useLive } from "../hooks/live";
import { SimBanner } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/cases", label: "Case Investigation", icon: Briefcase },
  { to: "/events", label: "Event Explorer", icon: ListFilter },
  { to: "/graph", label: "Entity Graph", icon: Network },
  { to: "/policies", label: "Policy Center", icon: SlidersHorizontal },
  { to: "/models", label: "Model Monitoring", icon: Cpu },
];

function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="h-8 w-8" aria-hidden>
      <rect width="32" height="32" rx="7" fill="#0f3b37" />
      <g stroke="#2dd4bf" strokeWidth="2" fill="none">
        <path d="M8 10 16 6l8 4v8l-8 8-8-8z" />
        <path d="M8 10l8 6 8-6M16 16v10" />
      </g>
      <circle cx="16" cy="16" r="2.5" fill="#e11d48" />
    </svg>
  );
}

export function Layout() {
  const { connected } = useLive();
  return (
    <div className="min-h-full flex flex-col">
      <SimBanner />
      <header className="sticky top-0 z-20 flex items-center gap-4 px-4 md:px-6 h-14 border-b border-ink-700 bg-ink-950/90 backdrop-blur">
        <Logo />
        <div className="leading-tight">
          <div className="font-bold tracking-[0.2em] text-fg">FRAUDMESH</div>
          <div className="text-[11px] text-fg-muted hidden sm:block">Connect the signals. Expose the attack. Explain the risk.</div>
        </div>
        <div className="ml-auto flex items-center gap-2 text-xs">
          <span className={`relative flex h-2.5 w-2.5 ${connected ? "" : "opacity-50"}`}>
            {connected && <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-60 animate-ping" />}
            <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${connected ? "bg-accent" : "bg-fg-dim"}`} />
          </span>
          <span className={connected ? "text-accent font-semibold tracking-widest" : "text-fg-dim"}>{connected ? "LIVE" : "OFFLINE"}</span>
        </div>
      </header>
      <div className="flex-1 flex min-h-0">
        <nav className="hidden md:flex w-56 shrink-0 flex-col gap-1 border-r border-ink-700 p-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}
                     className={({ isActive }) => `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${isActive ? "bg-accent/10 text-accent" : "text-fg-muted hover:bg-ink-800 hover:text-fg"}`}>
              <Icon size={16} /> {label}
            </NavLink>
          ))}
          <div className="mt-auto p-3 rounded-lg border border-ink-700 text-[11px] text-fg-dim leading-relaxed">
            <Activity size={14} className="text-accent mb-1" />
            Hackathon prototype. Synthetic data only. Not a production fraud system.
          </div>
        </nav>
        <main className="flex-1 min-w-0 p-4 md:p-6 pb-24 md:pb-6">
          <Outlet />
        </main>
      </div>
      <nav className="md:hidden fixed bottom-0 inset-x-0 z-20 grid grid-cols-6 border-t border-ink-700 bg-ink-950/95">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink key={to} to={to} end={end} aria-label={label}
                   className={({ isActive }) => `flex flex-col items-center py-2 text-[10px] ${isActive ? "text-accent" : "text-fg-muted"}`}>
            <Icon size={18} />
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
