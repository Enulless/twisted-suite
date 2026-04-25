import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "react-router-dom";
import { Check, ChevronRight } from "lucide-react";
import {
  type WorkflowState,
  type WorkflowStateStep,
  getWorkflowState,
} from "@/api/engagements";
import { cn } from "@/lib/utils";

interface Props {
  engagementId: number;
}

// Maps a stepper-step id to the engagement sub-route that page lives at.
const STEP_ROUTES: Record<WorkflowStateStep["id"], string> = {
  setup: "scope",
  tooling: "tooling",
  execute: "procedures",
  triage: "findings",
  report: "report",
  finalize: "report",
};

function activeStepFromPath(pathname: string): WorkflowStateStep["id"] | null {
  if (pathname.endsWith("/scope")) return "setup";
  if (pathname.endsWith("/tooling")) return "tooling";
  if (pathname.endsWith("/procedures") || pathname.endsWith("/runs"))
    return "execute";
  if (pathname.includes("/findings")) return "triage";
  if (pathname.endsWith("/report")) return "report";
  if (pathname.endsWith("/assets")) return "execute";
  return null;
}

export function WorkflowStepper({ engagementId }: Props) {
  const { data } = useQuery<WorkflowState>({
    queryKey: ["workflow-state", engagementId],
    queryFn: () => getWorkflowState(engagementId),
    refetchInterval: 10_000,
  });
  const location = useLocation();
  const active = activeStepFromPath(location.pathname);

  const steps =
    data?.steps ??
    ([
      { id: "setup", label: "Setup", completion: 0, summary: "" },
      { id: "tooling", label: "Tooling", completion: 0, summary: "" },
      { id: "execute", label: "Execute", completion: 0, summary: "" },
      { id: "triage", label: "Triage", completion: 0, summary: "" },
      { id: "report", label: "Report", completion: 0, summary: "" },
      { id: "finalize", label: "Finalize", completion: 0, summary: "" },
    ] as WorkflowStateStep[]);

  return (
    <div className="rounded-lg border border-border bg-card p-3 mb-6">
      <div className="flex items-stretch gap-1">
        {steps.map((step, i) => {
          const isActive = step.id === active;
          const isComplete = step.completion >= 1.0;
          const isStarted = step.completion > 0;
          const subroute = `/engagements/${engagementId}/${STEP_ROUTES[step.id]}`;
          return (
            <div key={step.id} className="flex items-center flex-1 min-w-0">
              <Link
                to={subroute}
                className={cn(
                  "flex flex-1 flex-col gap-1 px-3 py-2 rounded-md transition",
                  isActive && "bg-accent",
                  !isActive && "hover:bg-accent/50",
                )}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "flex h-5 w-5 items-center justify-center rounded-full",
                      "text-[10px] font-bold border",
                      isComplete &&
                        "bg-green-500/20 border-green-400 text-green-300",
                      !isComplete && isStarted &&
                        "bg-primary/20 border-primary text-primary",
                      !isStarted &&
                        "bg-muted border-muted-foreground/40 text-muted-foreground",
                    )}
                  >
                    {isComplete ? <Check className="h-3 w-3" /> : i + 1}
                  </span>
                  <span
                    className={cn(
                      "text-sm font-medium",
                      isActive ? "text-foreground" : "text-muted-foreground",
                    )}
                  >
                    {step.label}
                  </span>
                </div>
                {step.summary && (
                  <span className="text-[10px] text-muted-foreground pl-7 truncate">
                    {step.summary}
                  </span>
                )}
              </Link>
              {i < steps.length - 1 && (
                <ChevronRight className="h-4 w-4 text-muted-foreground/40 flex-shrink-0" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
