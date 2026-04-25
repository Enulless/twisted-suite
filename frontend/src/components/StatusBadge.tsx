import { Badge } from "./ui/badge";
import type { Severity, EngagementStatus, FindingStatus, StepStatus, WorkerStatus } from "@/api/types";
import { cn } from "@/lib/utils";

interface Props {
  status: string;
  className?: string;
}

const SEVERITY_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  informational: "info",
};

export function SeverityBadge({ severity, className }: { severity: Severity | string; className?: string }) {
  const v = SEVERITY_VARIANT[severity.toLowerCase()] ?? "info";
  return (
    <Badge variant={v} className={cn(className, "uppercase tracking-wider")}>
      {severity}
    </Badge>
  );
}

export function StatusPill({ status, className }: Props) {
  const colorMap: Record<string, string> = {
    online: "text-green-400 border-green-400/40 bg-green-500/10",
    offline: "text-muted-foreground border-muted",
    busy: "text-amber-400 border-amber-400/40 bg-amber-500/10",
    pending: "text-muted-foreground border-muted",
    running: "text-sky-400 border-sky-400/40 bg-sky-500/10",
    done: "text-green-400 border-green-400/40 bg-green-500/10",
    failed: "text-red-400 border-red-400/40 bg-red-500/10",
    skipped: "text-muted-foreground border-muted",
    planning: "text-muted-foreground border-muted",
    active: "text-sky-400 border-sky-400/40 bg-sky-500/10",
    reporting: "text-amber-400 border-amber-400/40 bg-amber-500/10",
    closed: "text-muted-foreground border-muted",
    draft: "text-muted-foreground border-muted",
    confirmed: "text-sky-400 border-sky-400/40 bg-sky-500/10",
    reported: "text-green-400 border-green-400/40 bg-green-500/10",
    up: "text-green-400 border-green-400/40 bg-green-500/10",
    down: "text-muted-foreground border-muted",
    partial: "text-amber-400 border-amber-400/40 bg-amber-500/10",
    unknown: "text-muted-foreground border-muted",
  };
  const color = colorMap[status.toLowerCase()] ?? "text-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 " +
          "text-[10px] font-semibold uppercase tracking-wider",
        color,
        className,
      )}
    >
      {status}
    </span>
  );
}

export type AnyStatus = Severity | EngagementStatus | FindingStatus | StepStatus | WorkerStatus;
