import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { labDown, labMeta, labUp, listLabs } from "@/api/labs";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusBadge";

export function LabsPage() {
  const qc = useQueryClient();
  const { data: labs } = useQuery({ queryKey: ["labs"], queryFn: listLabs });
  const { data: meta } = useQuery({ queryKey: ["labs-meta"], queryFn: labMeta });

  const upMut = useMutation({
    mutationFn: (id: string) => labUp(id),
    onSettled: () => qc.invalidateQueries({ queryKey: ["labs"] }),
  });
  const downMut = useMutation({
    mutationFn: (id: string) => labDown(id),
    onSettled: () => qc.invalidateQueries({ queryKey: ["labs"] }),
  });

  return (
    <>
      <PageHeader
        title="Practice Labs"
        description="Docker-managed vulnerable targets. Each runs on its own isolated bridge network."
      />
      {meta && !meta.docker_available && (
        <Card className="mb-4 border-amber-500/40 bg-amber-500/5">
          <CardContent className="py-3 text-sm text-amber-300">
            Docker isn't available on the engine host. Install
            <code className="mx-1 px-1 bg-muted rounded">docker.io</code>
            and restart <code className="px-1 bg-muted rounded">twisted serve</code>.
          </CardContent>
        </Card>
      )}
      <div className="grid grid-cols-2 gap-4">
        {(labs ?? []).map((lab) => (
          <Card key={lab.id}>
            <CardHeader className="flex-row items-start justify-between gap-2">
              <div>
                <CardTitle className="text-lg">{lab.name}</CardTitle>
                <p className="text-sm text-muted-foreground mt-1">
                  {lab.description}
                </p>
              </div>
              <StatusPill status={lab.state} />
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="font-mono text-xs text-muted-foreground">
                target: {lab.target_url}
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  onClick={() => upMut.mutate(lab.id)}
                  disabled={upMut.isPending || (meta && !meta.docker_available)}
                >
                  Up
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downMut.mutate(lab.id)}
                  disabled={downMut.isPending || (meta && !meta.docker_available)}
                >
                  Down
                </Button>
                {lab.state === "up" && (
                  <a
                    className="inline-flex items-center gap-1 text-sm text-primary hover:underline ml-auto"
                    href={lab.target_url}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Open <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                )}
              </div>
              {lab.practice_for.length > 0 && (
                <details>
                  <summary className="text-xs text-muted-foreground cursor-pointer">
                    {lab.practice_for.length} practice steps
                  </summary>
                  <ul className="mt-2 space-y-1 text-xs font-mono">
                    {lab.practice_for.map((sid) => (
                      <li key={sid}>{sid}</li>
                    ))}
                  </ul>
                </details>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}
