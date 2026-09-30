import { useEffect, useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { api } from "../api/client";

/** Waits for /api/health to report ready (models train + synthetic data seeds on first start). */
export function StartupGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "initialising" | "down" | "ready">("checking");

  useEffect(() => {
    let stop = false;
    let timer: number;
    const check = async () => {
      try {
        const h = await api<{ ready: boolean }>("/api/health");
        if (stop) return;
        if (h.ready) return setState("ready");
        setState("initialising");
      } catch {
        if (!stop) setState("down");
      }
      timer = window.setTimeout(check, 1500);
    };
    check();
    return () => {
      stop = true;
      window.clearTimeout(timer);
    };
  }, []);

  if (state === "ready") return <>{children}</>;
  return (
    <div className="h-full flex flex-col items-center justify-center gap-3 text-center p-6">
      <div className="font-bold tracking-[0.3em] text-2xl">FRAUDMESH</div>
      <div className="text-sm text-fg-muted">Connect the signals. Expose the attack. Explain the risk.</div>
      <div className="flex items-center gap-2 text-sm text-fg-muted mt-4">
        <Loader2 className="animate-spin" size={16} />
        {state === "down" && "Waiting for the backend at /api … (is uvicorn running on :8000?)"}
        {state === "initialising" && "Backend initialising — training models and generating synthetic demo data…"}
        {state === "checking" && "Connecting…"}
      </div>
    </div>
  );
}
