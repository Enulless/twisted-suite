import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { listRuns } from "@/api/jobs";
import { Card, CardContent } from "@/components/ui/card";
import { StatusPill } from "@/components/StatusBadge";
import { formatRelative } from "@/lib/utils";

export function RunsPage() {
  const id = Number(useParams().id);
  const { data } = useQuery({
    queryKey: ["engagement", id, "runs"],
    queryFn: () => listRuns(id),
    refetchInterval: 5_000,
  });

  return (
    <Card>
      <CardContent className="p-0">
        <table className="w-full text-sm">
          <thead className="bg-secondary/40 text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="text-left px-3 py-2 font-medium w-16">id</th>
              <th className="text-left px-3 py-2 font-medium">step</th>
              <th className="text-left px-3 py-2 font-medium">stage</th>
              <th className="text-left px-3 py-2 font-medium">mode</th>
              <th className="text-left px-3 py-2 font-medium">status</th>
              <th className="text-left px-3 py-2 font-medium">worker</th>
              <th className="text-left px-3 py-2 font-medium">started</th>
              <th className="text-left px-3 py-2 font-medium">summary</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {(data ?? []).map((r) => (
              <tr key={r.id} className="hover:bg-accent/40">
                <td className="px-3 py-2 text-xs">#{r.id}</td>
                <td className="px-3 py-2 font-mono text-xs">{r.step_id}</td>
                <td className="px-3 py-2 text-xs">{r.stage ?? "—"}</td>
                <td className="px-3 py-2 text-xs">{r.mode}</td>
                <td className="px-3 py-2"><StatusPill status={r.status} /></td>
                <td className="px-3 py-2 font-mono text-xs">
                  {r.worker_id ?? "—"}
                </td>
                <td className="px-3 py-2 text-xs text-muted-foreground">
                  {formatRelative(r.started_at)}
                </td>
                <td className="px-3 py-2 text-xs text-muted-foreground truncate max-w-md">
                  {r.output_summary ?? "—"}
                </td>
              </tr>
            ))}
            {(data ?? []).length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-10 text-center text-muted-foreground">
                  No step runs yet. Queue one from the Procedures tab.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
