import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api, ApiError, get, post } from "@/api/client";

const mkResponse = (status: number, body: unknown): Response =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

// We coerce the global.fetch spy to any to avoid leaking the dom-lib
// fetch overload into vitest's MockInstance generic; the per-call
// inspection (.mock.calls) is what matters here.
describe("api client", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    (global as unknown as { fetch: typeof fetchSpy }).fetch = fetchSpy;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prefixes /api on every request", async () => {
    fetchSpy.mockResolvedValueOnce(mkResponse(200, { ok: true }));
    await api("/engagements");
    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url.startsWith("/api/engagements")).toBe(true);
  });

  it("includes credentials so cookie auth works cross-origin", async () => {
    fetchSpy.mockResolvedValueOnce(mkResponse(200, []));
    await get("/workers");
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(init.credentials).toBe("include");
  });

  it("serialises body as JSON for POST", async () => {
    fetchSpy.mockResolvedValueOnce(mkResponse(201, { id: 1 }));
    await post("/engagements", { client: "ACME" });
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ client: "ACME" }));
  });

  it("throws ApiError on non-2xx with parsed body", async () => {
    fetchSpy.mockResolvedValueOnce(
      mkResponse(403, { detail: { error: "blocked_by_tool_policy" } }),
    );
    await expect(api("/steps/run", { method: "POST", body: {} })).rejects.toThrow(
      ApiError,
    );
  });

  it("appends array query params as repeated keys", async () => {
    fetchSpy.mockResolvedValueOnce(mkResponse(200, null));
    await get("/jobs/next", { capabilities: ["dig", "nmap"], runtime: "linux" });
    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toContain("capabilities=dig");
    expect(url).toContain("capabilities=nmap");
    expect(url).toContain("runtime=linux");
  });
});
