import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { toast } from "sonner";
import { Loader2, Play } from "lucide-react";
import { listProcedures, queueStep } from "@/api/jobs";
import { getPolicyInventory } from "@/api/toolPolicy";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function EngagementProceduresPage() {
  const id = Number(useParams().id);
  const qc = useQueryClient();
  const { data: procs } = useQuery({
    queryKey: ["procedures"],
    queryFn: listProcedures,
  });
  const { data: inv } = useQuery({
    queryKey: ["tool-policy-inventory", id],
    queryFn: () => getPolicyInventory(id),
  });

  const blockedSet = new Set(
    (inv?.steps ?? []).filter((s) => !s.allowed).map((s) => s.step_id),
  );
  const blockReasonMap = Object.fromEntries(
    (inv?.steps ?? []).map((s) => [s.step_id, s.block_reason]),
  );

  const queueMut = useMutation({
    mutationFn: (stepId: string) => queueStep(id, stepId),
    onSuccess: (sr) => toast.success(
      `Queued ${sr.step_id}`,
      { description: `step run #${sr.id}` },
    ),
    onError: (e) => toast.error("Queue failed", {
      description: (e as Error).message,
    }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["engagement", id, "runs"] }),
  });

  return (
    <div className="space-y-5">
      {(procs ?? []).map((p) => (
        <Card key={p.id}>
          <CardHeader>
            <CardTitle>
              <span className="font-mono text-primary">{p.id}</span>{" "}
              <span className="text-muted-foreground text-sm font-normal">
                — {p.name}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {p.stages.map((stage) => (
              <details
                key={stage.id}
                open
                className="border border-border rounded-md p-3"
              >
                <summary className="cursor-pointer text-sm font-medium">
                  <span className="font-mono">{stage.id}</span> · {stage.name}{" "}
                  <span className="text-muted-foreground">
                    ({stage.steps.length} steps)
                  </span>
                </summary>
                <div className="mt-3 space-y-1.5">
                  {stage.steps.map((s) => {
                    const blocked = blockedSet.has(s.id);
                    const reason = blockReasonMap[s.id];
                    return (
                      <div
                        key={s.id}
                        className={cn(
                          "flex items-center justify-between gap-2 px-2 py-1.5 rounded",
                          blocked
                            ? "bg-destructive/5 opacity-70"
                            : "hover:bg-accent/40",
                        )}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 font-mono text-xs">
                            <Badge variant="outline" className="text-[9px]">
                              {s.mode}
                            </Badge>
                            <Badge variant="outline" className="text-[9px]">
                              {s.runtime}
                            </Badge>
                            <span>{s.id}</span>
                          </div>
                          <div className="text-xs text-muted-foreground truncate mt-0.5 ml-1">
                            {s.name}
                          </div>
                          {reason && (
                            <div className="text-[10px] text-amber-400 mt-0.5 ml-1">
                              blocked: {reason}
                            </div>
                          )}
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => queueMut.mutate(s.id)}
                          disabled={blocked || queueMut.isPending || s.mode !== "auto"}
                          className="h-7 px-2 text-xs"
                        >
                          {queueMut.isPending && queueMut.variables === s.id ? (
                            <Loader2 className="animate-spin h-3 w-3" />
                          ) : (
                            <Play className="h-3 w-3" />
                          )}
                          Run
                        </Button>
                      </div>
                    );
                  })}
                </div>
              </details>
            ))}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
