const ADMIN_KEY = "fraudmesh.adminToken";

export function getAdminToken(): string {
  try {
    return localStorage.getItem(ADMIN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setAdminToken(token: string): void {
  try {
    localStorage.setItem(ADMIN_KEY, token);
  } catch {
    /* storage unavailable — token lives for this page only */
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function describe(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail))
    return detail.map((d: any) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}`).join("; ");
  return JSON.stringify(detail);
}

export async function api<T>(path: string, init: RequestInit & { admin?: boolean } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (init.admin) {
    const token = getAdminToken();
    if (token) headers.set("X-Admin-Token", token);
  }
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, body?.detail ? describe(body.detail) : res.statusText);
  return body as T;
}

export const post = <T,>(path: string, data: unknown, admin = false) =>
  api<T>(path, { method: "POST", body: JSON.stringify(data), admin });
export const put = <T,>(path: string, data: unknown, admin = true) =>
  api<T>(path, { method: "PUT", body: JSON.stringify(data), admin });

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  });
  const s = p.toString();
  return s ? `?${s}` : "";
}
