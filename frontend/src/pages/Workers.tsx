import { useQuery } from "@tanstack/react-query";
import { listWorkers } from "@/api/workers";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusBadge";
import { formatRelative } from "@/lib/utils";

export function WorkersPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["workers"],
    queryFn: listWorkers,
    refetchInterval: 5_000,
  });

  return (
    <>
      <PageHeader
        title="Workers"
        description="Live worker registry. Auto-refreshes every 5 seconds."
      />
      {isLoading && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            Loading workers…
          </CardContent>
        </Card>
      )}
      {data && data.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            No workers connected. Run{" "}
            <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
              twisted worker linux
            </code>
            .
          </CardContent>
        </Card>
      )}
      {data && data.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead className="bg-secondary/40 text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="text-left px-4 py-2 font-medium">id</th>
                  <th className="text-left px-4 py-2 font-medium">os</th>
                  <th className="text-left px-4 py-2 font-medium">status</th>
                  <th className="text-left px-4 py-2 font-medium">capabilities</th>
                  <th className="text-left px-4 py-2 font-medium">last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.map((w) => (
                  <tr key={w.id} className="hover:bg-accent/40">
                    <td className="px-4 py-2 font-mono text-xs">{w.id}</td>
                    <td className="px-4 py-2">{w.os}</td>
                    <td className="px-4 py-2"><StatusPill status={w.status} /></td>
                    <td className="px-4 py-2 text-muted-foreground text-xs">
                      {w.capabilities.slice(0, 8).join(", ")}
                      {w.capabilities.length > 8 ? ` +${w.capabilities.length - 8} more` : ""}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {formatRelative(w.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </>
  );
}
