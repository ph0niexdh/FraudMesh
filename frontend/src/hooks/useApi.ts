import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { useLiveRefresh } from "./live";

interface Options {
  /** live message types that trigger a silent refetch */
  refreshOn?: string[];
  throttleMs?: number;
  skip?: boolean;
}

export function useApi<T>(path: string | null, opts: Options = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(!!path && !opts.skip);
  const seq = useRef(0);

  const load = useCallback(
    async (silent = false) => {
      if (!path || opts.skip) return;
      const id = ++seq.current;
      if (!silent) setLoading(true);
      try {
        const res = await api<T>(path);
        if (id === seq.current) {
          setData(res);
          setError(null);
        }
      } catch (e) {
        if (id === seq.current) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (id === seq.current) setLoading(false);
      }
    },
    [path, opts.skip],
  );

  useEffect(() => {
    setData(null);
    load();
  }, [load]);

  useLiveRefresh(opts.refreshOn ?? [], () => load(true), opts.throttleMs ?? 600);

  return { data, error, loading, reload: load, setData };
}
