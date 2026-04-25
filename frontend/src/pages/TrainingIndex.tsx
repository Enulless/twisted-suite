import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listLessons } from "@/api/training";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Check } from "lucide-react";

const PROCS = ["all", "bb", "wp_stress", "wifi"] as const;

export function TrainingIndexPage() {
  const [proc, setProc] = useState<(typeof PROCS)[number]>("all");
  const { data } = useQuery({
    queryKey: ["training", proc],
    queryFn: () => listLessons("default", proc === "all" ? undefined : proc),
  });

  const byProc: Record<string, typeof data> = {};
  for (const lsn of data ?? []) {
    (byProc[lsn.procedure] ??= []).push(lsn);
  }

  return (
    <>
      <PageHeader
        title="Training"
        description="Auto-extracted lessons + hand-curated quizzes per procedure step."
        actions={
          <div className="flex items-center gap-1">
            {PROCS.map((p) => (
              <Button
                key={p}
                size="sm"
                variant={proc === p ? "default" : "outline"}
                onClick={() => setProc(p)}
              >
                {p}
              </Button>
            ))}
          </div>
        }
      />
      <div className="space-y-5">
        {Object.entries(byProc).map(([procId, lessons]) => (
          <Card key={procId}>
            <CardHeader>
              <CardTitle>
                <span className="font-mono text-primary">{procId}</span>{" "}
                <span className="text-muted-foreground text-sm font-normal">
                  · {(lessons ?? []).length} lessons
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead className="bg-secondary/40 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="text-left px-4 py-2 font-medium w-8"></th>
                    <th className="text-left px-4 py-2 font-medium">step</th>
                    <th className="text-left px-4 py-2 font-medium">title</th>
                    <th className="text-left px-4 py-2 font-medium">stage</th>
                    <th className="text-left px-4 py-2 font-medium">quiz</th>
                    <th className="text-left px-4 py-2 font-medium">last score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {(lessons ?? []).map((l) => (
                    <tr key={l.step_id} className="hover:bg-accent/40">
                      <td className="px-4 py-2 text-green-400">
                        {l.completed && <Check className="h-4 w-4" />}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs">{l.step_id}</td>
                      <td className="px-4 py-2">{l.title}</td>
                      <td className="px-4 py-2 text-muted-foreground text-xs">
                        {l.stage ?? "—"}
                      </td>
                      <td className="px-4 py-2">
                        {l.has_quiz ? (
                          <Badge variant="secondary" className="text-[10px]">
                            yes
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-xs">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-xs">
                        {l.last_score == null
                          ? "—"
                          : `${Math.round(l.last_score * 100)}%`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}
