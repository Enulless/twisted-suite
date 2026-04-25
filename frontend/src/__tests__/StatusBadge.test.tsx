import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityBadge, StatusPill } from "@/components/StatusBadge";

describe("SeverityBadge", () => {
  it("renders critical with the critical pill class", () => {
    const { container } = render(<SeverityBadge severity="critical" />);
    expect(screen.getByText(/critical/i)).toBeInTheDocument();
    expect(container.firstChild).toHaveClass("pill-sev-critical");
  });

  it("falls back to info for unknown severities", () => {
    const { container } = render(<SeverityBadge severity="bogus" />);
    expect(container.firstChild).toHaveClass("pill-sev-info");
  });

  it("normalises 'informational' to info pill", () => {
    const { container } = render(<SeverityBadge severity="informational" />);
    expect(container.firstChild).toHaveClass("pill-sev-info");
  });
});

describe("StatusPill", () => {
  it("renders the status text", () => {
    render(<StatusPill status="online" />);
    expect(screen.getByText("online")).toBeInTheDocument();
  });

  it("uses the green color hint for 'done'", () => {
    const { container } = render(<StatusPill status="done" />);
    expect(container.firstChild).toHaveClass("text-green-400");
  });

  it("uses muted color for unknown statuses", () => {
    const { container } = render(<StatusPill status="custom-state" />);
    expect(container.firstChild).toHaveClass("text-foreground");
  });
});
