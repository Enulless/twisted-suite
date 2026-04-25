import { describe, it, expect } from "vitest";
import { cn, formatRelative, formatDate } from "@/lib/utils";

describe("cn", () => {
  it("merges tailwind classes intelligently (last-one-wins for conflicts)", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");
    expect(cn("text-sm", undefined, "font-medium")).toContain("text-sm");
    expect(cn("text-sm", "font-medium")).toContain("font-medium");
  });

  it("filters out falsy values", () => {
    expect(cn("a", false, null, "b")).toBe("a b");
  });
});

describe("formatRelative", () => {
  it("returns em-dash for nullish", () => {
    expect(formatRelative(null)).toBe("—");
    expect(formatRelative(undefined)).toBe("—");
  });

  it("falls through to ISO date when older than 30 days", () => {
    const oldIso = "2020-01-01T00:00:00Z";
    expect(formatRelative(oldIso)).toBe("2020-01-01");
  });

  it("uses 's' for seconds", () => {
    const recent = new Date(Date.now() - 5_000).toISOString();
    expect(formatRelative(recent)).toMatch(/s ago$/);
  });
});

describe("formatDate", () => {
  it("returns the YYYY-MM-DD prefix", () => {
    expect(formatDate("2026-04-25T13:35:00Z")).toBe("2026-04-25");
  });

  it("em-dash for nullish", () => {
    expect(formatDate(null)).toBe("—");
  });
});
