import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { WorkflowStepper } from "@/components/WorkflowStepper";

const mkResponse = (body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

const FAKE_STATE = {
  engagement_id: 1,
  steps: [
    { id: "setup", label: "Setup", completion: 1.0, summary: "client + scope (3 rules)" },
    { id: "tooling", label: "Tooling", completion: 1.0, summary: "4 caps blocked, 0 steps blocked" },
    { id: "execute", label: "Execute", completion: 0.5, summary: "12/24 done" },
    { id: "triage", label: "Triage", completion: 0, summary: "no findings yet" },
    { id: "report", label: "Report", completion: 0, summary: "—" },
    { id: "finalize", label: "Finalize", completion: 0, summary: "archive not configured" },
  ],
  stats: {},
};

function renderWithProviders(ui: React.ReactElement, path = "/engagements/1") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("WorkflowStepper", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue(mkResponse(FAKE_STATE));
    (global as unknown as { fetch: typeof fetchSpy }).fetch = fetchSpy;
  });

  afterEach(() => vi.restoreAllMocks());

  it("renders all six step labels", async () => {
    renderWithProviders(<WorkflowStepper engagementId={1} />);
    // Labels render synchronously (placeholder data) before the query resolves
    expect(screen.getByText("Setup")).toBeInTheDocument();
    expect(screen.getByText("Tooling")).toBeInTheDocument();
    expect(screen.getByText("Execute")).toBeInTheDocument();
    expect(screen.getByText("Triage")).toBeInTheDocument();
    expect(screen.getByText("Report")).toBeInTheDocument();
    expect(screen.getByText("Finalize")).toBeInTheDocument();
  });

  it("shows the per-step summary once the query resolves", async () => {
    renderWithProviders(<WorkflowStepper engagementId={1} />);
    expect(await screen.findByText("12/24 done")).toBeInTheDocument();
    expect(await screen.findByText(/4 caps blocked/)).toBeInTheDocument();
  });

  it("sends the workflow-state request to /api/engagements/:id/workflow-state", async () => {
    renderWithProviders(<WorkflowStepper engagementId={42} />);
    await screen.findByText(/12\/24 done/);
    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toBe("/api/engagements/42/workflow-state");
  });
});
