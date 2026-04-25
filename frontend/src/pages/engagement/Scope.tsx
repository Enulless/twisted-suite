import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { getEngagementScope } from "@/api/engagements";
import { Card, CardContent } from "@/components/ui/card";

export function ScopePage() {
  const id = Number(useParams().id);
  const { data } = useQuery({
    queryKey: ["engagement", id, "scope"],
    queryFn: () => getEngagementScope(id),
  });
  return (
    <Card>
      <CardContent className="p-5">
        <h2 className="text-lg font-semibold mb-2">Scope rules</h2>
        <p className="text-sm text-muted-foreground mb-4">
          Read-only for now. Edit scope via{" "}
          <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
            twisted engagement
          </code>{" "}
          CLI for the moment; in-app editing lands in 8C.
        </p>
        {(data ?? []).length === 0 && (
          <p className="text-sm text-muted-foreground">No scope rules.</p>
        )}
        <table className="w-full text-sm">
          <thead className="bg-secondary/40 text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="text-left px-2 py-2 font-medium w-32">kind</th>
              <th className="text-left px-2 py-2 font-medium">pattern</th>
              <th className="text-left px-2 py-2 font-medium">note</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {(data ?? []).map((r, i) => (
              <tr key={i} className="hover:bg-accent/40">
                <td className="px-2 py-2 font-mono text-xs">
                  <span className={
                    r.kind === "oos" ? "text-destructive"
                    : r.kind === "wildcard" ? "text-amber-400"
                    : "text-sky-400"
                  }>{r.kind}</span>
                </td>
                <td className="px-2 py-2 font-mono text-xs">{r.pattern}</td>
                <td className="px-2 py-2 text-muted-foreground text-xs">
                  {r.note ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
