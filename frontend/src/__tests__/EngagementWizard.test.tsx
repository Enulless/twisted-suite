import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { EngagementWizardPage } from "@/pages/EngagementWizard";

const mkResponse = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

function renderApp() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/engagements/new"]}>
      <QueryClientProvider client={qc}>
        <Routes>
          <Route path="/engagements/new" element={<EngagementWizardPage />} />
          <Route path="/engagements/:id" element={<div>landed</div>} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("EngagementWizard", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    (global as unknown as { fetch: typeof fetchSpy }).fetch = fetchSpy;
  });

  afterEach(() => vi.restoreAllMocks());

  it("step 1 disables Next until client name is supplied", () => {
    renderApp();
    const next = screen.getByRole("button", { name: /^Next$/i });
    expect(next).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Client name/i), {
      target: { value: "ACME" },
    });
    expect(next).not.toBeDisabled();
  });

  it("walks step1 → step2 → step3 → step4 and posts on confirm", async () => {
    fetchSpy.mockResolvedValue(mkResponse(201, { id: 17, client: "ACME" }));
    renderApp();
    fireEvent.change(screen.getByLabelText(/Client name/i), {
      target: { value: "ACME" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^Next$/i }));
    // step 2 — has a default rule already in the textarea, so it's >= 1
    expect(screen.getByText(/valid rule/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^Next$/i }));
    // step 3 — preset picker, default = open_bug_bounty
    expect(screen.getByText(/Open bug bounty/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^Next$/i }));
    // step 4 — review, click create
    fireEvent.click(screen.getByRole("button", { name: /Create engagement/i }));
    await screen.findByText("landed");
    expect(fetchSpy.mock.calls[0]![0]).toBe("/api/engagements");
  });
});
