// Centralised fetch wrapper. Every JSON-API call goes through here so
// auth, error handling, and base-URL prefixing live in one place.

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

interface RequestOpts {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | string[] | undefined>;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: RequestOpts["query"]): string {
  const u = new URL(path, window.location.origin);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) {
        v.forEach((val) => u.searchParams.append(k, String(val)));
      } else {
        u.searchParams.set(k, String(v));
      }
    }
  }
  return u.pathname + (u.search ? u.search : "");
}

export async function api<T = unknown>(
  path: string,
  opts: RequestOpts = {},
): Promise<T> {
  const url = buildUrl(`/api${path}`, opts.query);
  const init: RequestInit = {
    method: opts.method ?? "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    signal: opts.signal,
  };
  if (opts.body !== undefined) {
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, init);

  // Cookie session expired? Bounce to /login. The dashboard cookie
  // route does this server-side via 303 redirect; for fetch() we have
  // to detect 401/403 from /api/* and redirect explicitly.
  if (res.status === 401 && !url.endsWith("/health")) {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    throw new ApiError(401, "unauthorized");
  }

  let body: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!res.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body
        ? (body as { detail: unknown }).detail
        : body;
    const msg = typeof detail === "string" ? detail : JSON.stringify(detail);
    throw new ApiError(res.status, msg || res.statusText, body);
  }
  return body as T;
}

export const get = <T = unknown>(
  path: string,
  query?: RequestOpts["query"],
  signal?: AbortSignal,
) => api<T>(path, { query, signal });

export const post = <T = unknown>(path: string, body?: unknown) =>
  api<T>(path, { method: "POST", body });

export const put = <T = unknown>(path: string, body?: unknown) =>
  api<T>(path, { method: "PUT", body });

export const del = <T = unknown>(path: string) =>
  api<T>(path, { method: "DELETE" });
