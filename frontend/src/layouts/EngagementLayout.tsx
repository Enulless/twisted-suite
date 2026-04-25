import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { getEngagement } from "@/api/engagements";
import { WorkflowStepper } from "@/components/WorkflowStepper";
import { StatusPill } from "@/components/StatusBadge";
import { cn } from "@/lib/utils";

const SUBNAV: { to: string; label: string }[] = [
  { to: "", label: "Overview" },
  { to: "scope", label: "Scope" },
  { to: "tooling", label: "Tooling (RoE)" },
  { to: "procedures", label: "Procedures" },
  { to: "assets", label: "Assets" },
  { to: "findings", label: "Findings" },
  { to: "runs", label: "Runs" },
  { to: "report", label: "Report" },
];

export function EngagementLayout() {
  const id = Number(useParams().id);
  const { data: eng } = useQuery({
    queryKey: ["engagement", id],
    queryFn: () => getEngagement(id),
    enabled: !Number.isNaN(id),
  });

  if (Number.isNaN(id)) {
    return (
      <div className="text-destructive">Invalid engagement id.</div>
    );
  }

  return (
    <>
      <Link
        to="/"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-3"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> all engagements
      </Link>

      <div className="flex items-baseline justify-between mb-2">
        <h1 className="text-2xl font-semibold tracking-tight">
          {eng?.client ?? "Loading…"}
        </h1>
        {eng && (
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <span className="font-mono text-xs">
              {eng.primary_domain ?? "no primary domain"}
            </span>
            <StatusPill status={eng.status} />
          </div>
        )}
      </div>

      <WorkflowStepper engagementId={id} />

      <nav className="flex items-center gap-1 border-b border-border mb-6 overflow-x-auto">
        {SUBNAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === ""}
            className={({ isActive }) =>
              cn(
                "px-3 py-2 text-sm font-medium border-b-2 transition-colors -mb-px",
                isActive
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </>
  );
}
