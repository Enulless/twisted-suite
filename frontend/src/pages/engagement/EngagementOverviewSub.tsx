import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { getEngagement, getEngagementScope } from "@/api/engagements";
import { listFindings } from "@/api/findings";
import { listAssetDetail } from "@/api/assets";
import { listRuns } from "@/api/jobs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/StatusBadge";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { RiskHistogram } from "@/components/charts/RiskHistogram";
import { formatRelative } from "@/lib/utils";

function tier(total: number): string {
  if (total >= 21) return "critical";
  if (total >= 13) return "high";
  if (total >= 6) return "medium";
  if (total >= 1) return "low";
  return "none";
}

export function EngagementOverviewSubPage() {
  const id = Number(useParams().id);
  const { data: eng } = useQuery({
    queryKey: ["engagement", id], queryFn: () => getEngagement(id),
  });
  const { data: scope } = useQuery({
    queryKey: ["engagement", id, "scope"],
    queryFn: () => getEngagementScope(id),
  });
  const { data: assets } = useQuery({
    queryKey: ["engagement", id, "assets"],
    queryFn: () => listAssetDetail(id),
  });
  const { data: findings } = useQuery({
    queryKey: ["engagement", id, "findings"],
    queryFn: () => listFindings(id),
  });
  const { data: runs } = useQuery({
    queryKey: ["engagement", id, "runs"],
    queryFn: () => listRuns(id),
  });

  const sevCounts: Record<string, number> = {};
  for (const f of findings ?? []) {
    const k = f.severity === "informational" ? "info" : f.severity;
    sevCounts[k] = (sevCounts[k] ?? 0) + 1;
  }
  const inScope = (assets ?? []).filter((a) => a.in_scope).length;
  const tierBuckets: Record<string, number> = {};
  for (const a of assets ?? []) {
    const t = tier(a.risk_total);
    tierBuckets[t] = (tierBuckets[t] ?? 0) + 1;
  }

  return (
    <>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Assets" value={String(assets?.length ?? "—")}
                  hint={`${inScope} in scope`} />
        <StatCard label="Findings" value={String(findings?.length ?? "—")}
                  hint={Object.entries(sevCounts).map(([s, c]) =>
                    `${c} ${s}`).join(" · ") || "—"} />
        <StatCard label="Step runs" value={String(runs?.length ?? "—")}
                  hint={`${(runs ?? []).filter((r) => r.status === "done").length} done`} />
        <StatCard label="Created" value={formatRelative(eng?.created_at)} />
      </div>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <Card>
          <CardHeader><CardTitle className="text-base">Findings by severity</CardTitle></CardHeader>
          <CardContent className="flex items-center justify-center pb-6">
            <SeverityDonut counts={sevCounts} size={180} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Asset risk distribution</CardTitle></CardHeader>
          <CardContent>
            <RiskHistogram buckets={tierBuckets} />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle>Scope</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {(scope ?? []).length === 0 && (
              <p className="text-muted-foreground">no scope rules</p>
            )}
            {(scope ?? []).map((r, i) => (
              <div key={i} className="flex items-center gap-2 font-mono text-xs">
                <span className={
                  r.kind === "oos" ? "text-destructive"
                  : r.kind === "wildcard" ? "text-amber-400"
                  : "text-sky-400"
                }>
                  {r.kind.padEnd(8)}
                </span>
                <span>{r.pattern}</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Recent findings</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {(findings ?? []).slice(0, 6).map((f) => (
              <div key={f.id} className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <span className="truncate">{f.title}</span>
              </div>
            ))}
            {findings && findings.length === 0 && (
              <p className="text-muted-foreground">no findings yet</p>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function StatCard({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card>
      <CardContent className="p-5">
        <p className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</p>
        <p className="text-2xl font-semibold mt-1">{value}</p>
        {hint && <p className="text-xs text-muted-foreground mt-1">{hint}</p>}
      </CardContent>
    </Card>
  );
}
