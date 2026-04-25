import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowRight, Plus } from "lucide-react";
import { listEngagements } from "@/api/engagements";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusBadge";
import { formatRelative } from "@/lib/utils";

export function EngagementListPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["engagements"],
    queryFn: listEngagements,
  });

  return (
    <>
      <PageHeader
        title="Engagements"
        description="Each engagement is a sealed RoE-bounded test target."
        actions={
          <Button asChild>
            <Link to="/engagements/new">
              <Plus />
              New engagement
            </Link>
          </Button>
        }
      />

      {isLoading && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            Loading engagements…
          </CardContent>
        </Card>
      )}

      {error && (
        <Card className="border-destructive/50">
          <CardContent className="py-6 text-destructive text-sm">
            Failed to load: {(error as Error).message}
          </CardContent>
        </Card>
      )}

      {data && data.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <h3 className="font-medium">No engagements yet</h3>
            <p className="text-muted-foreground text-sm mt-1">
              Use <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                twisted engagement new --client &lt;name&gt;
              </code>{" "}
              to seed one.
            </p>
          </CardContent>
        </Card>
      )}

      {data && data.length > 0 && (
        <div className="grid gap-3">
          {data.map((e) => (
            <Card key={e.id} className="transition hover:border-primary/50">
              <Link to={`/engagements/${e.id}`} className="block">
                <CardHeader className="flex flex-row items-center justify-between">
                  <div className="space-y-1">
                    <CardTitle className="text-lg">{e.client}</CardTitle>
                    <p className="text-sm text-muted-foreground">
                      {e.primary_domain ?? "no primary domain set"}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <StatusPill status={e.status} />
                    <span>created {formatRelative(e.created_at)}</span>
                    <ArrowRight className="h-4 w-4" />
                  </div>
                </CardHeader>
              </Link>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
