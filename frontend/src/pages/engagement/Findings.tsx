import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { listFindings } from "@/api/findings";
import type { Finding } from "@/api/types";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const COLUMNS: { key: string; label: string; color: string }[] = [
  { key: "critical", label: "Critical", color: "text-sev-critical border-l-sev-critical" },
  { key: "high", label: "High", color: "text-sev-high border-l-sev-high" },
  { key: "medium", label: "Medium", color: "text-sev-medium border-l-sev-medium" },
  { key: "low", label: "Low", color: "text-sev-low border-l-sev-low" },
  { key: "info", label: "Informational", color: "text-sev-info border-l-sev-info" },
];

export function FindingsPage() {
  const id = Number(useParams().id);
  const { data } = useQuery({
    queryKey: ["engagement", id, "findings"],
    queryFn: () => listFindings(id),
  });

  const buckets: Record<string, Finding[]> = {};
  for (const c of COLUMNS) buckets[c.key] = [];
  for (const f of data ?? []) {
    const key = f.severity === "informational" ? "info" : f.severity;
    (buckets[key] ??= []).push(f);
  }

  return (
    <div className="grid grid-cols-5 gap-3">
      {COLUMNS.map((col) => (
        <div key={col.key} className="space-y-2">
          <h3
            className={cn(
              "text-xs font-semibold uppercase tracking-wider pb-2",
              "border-b",
              col.color,
            )}
          >
            {col.label}{" "}
            <span className="text-muted-foreground font-normal">
              ({buckets[col.key].length})
            </span>
          </h3>
          {buckets[col.key].map((f) => (
            <Link key={f.id} to={`/engagements/${id}/findings/${f.id}`}>
              <Card
                className={cn(
                  "transition hover:border-primary/50 border-l-4",
                  col.color,
                )}
              >
                <CardContent className="p-3">
                  <div className="text-sm font-medium leading-tight">
                    {f.title}
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-1.5 flex items-center gap-1.5 flex-wrap">
                    {f.cwe && <span>{f.cwe}</span>}
                    {f.cvss_score != null && <span>· CVSS {f.cvss_score.toFixed(1)}</span>}
                    <span>· {f.status}</span>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
          {buckets[col.key].length === 0 && (
            <p className="text-xs text-muted-foreground py-3 text-center">
              none
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
