import { useQuery } from "@tanstack/react-query";
import { listProcedures } from "@/api/jobs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";

export function ProceduresPage() {
  const { data } = useQuery({
    queryKey: ["procedures"],
    queryFn: listProcedures,
  });

  return (
    <>
      <PageHeader
        title="Procedures"
        description="Three loaded procedures, derived from the docx manuals via YAML."
      />
      <div className="space-y-5">
        {(data ?? []).map((p) => (
          <Card key={p.id}>
            <CardHeader>
              <CardTitle>
                <span className="font-mono text-primary">{p.id}</span>{" "}
                <span className="text-muted-foreground">— {p.name}</span>
              </CardTitle>
              {p.description && (
                <p className="text-sm text-muted-foreground mt-1">
                  {p.description}
                </p>
              )}
            </CardHeader>
            <CardContent className="space-y-3">
              {p.stages.map((stage) => (
                <details
                  key={stage.id}
                  className="border border-border rounded-md p-3"
                >
                  <summary className="cursor-pointer text-sm font-medium">
                    <span className="font-mono">{stage.id}</span> ·{" "}
                    {stage.name}{" "}
                    <span className="text-muted-foreground">
                      ({stage.steps.length} steps)
                    </span>
                  </summary>
                  <ul className="mt-3 space-y-1.5 text-sm">
                    {stage.steps.map((s) => (
                      <li
                        key={s.id}
                        className="flex items-center gap-2 font-mono text-xs"
                      >
                        <Badge variant="outline" className="text-[9px]">
                          {s.mode}
                        </Badge>
                        <Badge variant="outline" className="text-[9px]">
                          {s.runtime}
                        </Badge>
                        <span className="text-foreground">{s.id}</span>
                        <span className="text-muted-foreground truncate font-sans">
                          {s.name}
                        </span>
                      </li>
                    ))}
                  </ul>
                </details>
              ))}
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}
