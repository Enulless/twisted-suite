import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { ArrowDown, ArrowUp } from "lucide-react";
import { listAssetDetail } from "@/api/assets";
import type { AssetDetail } from "@/api/types";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type SortKey = "host" | "ip" | "env_type" | "risk_total" | "ports" | "cves";
type SortDir = "asc" | "desc";

function tier(total: number): string {
  if (total >= 21) return "critical";
  if (total >= 13) return "high";
  if (total >= 6) return "medium";
  if (total >= 1) return "low";
  return "info";
}

export function AssetsPage() {
  const id = Number(useParams().id);
  const { data } = useQuery({
    queryKey: ["engagement", id, "assets"],
    queryFn: () => listAssetDetail(id),
  });
  const [filter, setFilter] = useState("");
  const [scope, setScope] = useState<"all" | "in" | "oos">("all");
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({
    key: "risk_total",
    dir: "desc",
  });

  const rows = useMemo(() => {
    let r = data ?? [];
    if (scope === "in") r = r.filter((a) => a.in_scope);
    if (scope === "oos") r = r.filter((a) => !a.in_scope);
    if (filter) {
      const f = filter.toLowerCase();
      r = r.filter((a) =>
        a.host.toLowerCase().includes(f) ||
        (a.ip ?? "").toLowerCase().includes(f) ||
        a.techs.some((t) => t.name.toLowerCase().includes(f)),
      );
    }
    const cmp = (a: AssetDetail, b: AssetDetail) => {
      const dir = sort.dir === "asc" ? 1 : -1;
      switch (sort.key) {
        case "host": return a.host.localeCompare(b.host) * dir;
        case "ip": return (a.ip ?? "").localeCompare(b.ip ?? "") * dir;
        case "env_type": return (a.env_type ?? "").localeCompare(b.env_type ?? "") * dir;
        case "risk_total": return (a.risk_total - b.risk_total) * dir;
        case "ports": return (a.ports.length - b.ports.length) * dir;
        case "cves": return (a.cves.length - b.cves.length) * dir;
      }
    };
    return [...r].sort(cmp);
  }, [data, filter, scope, sort]);

  const exportCsv = () => {
    const header = ["host", "ip", "env_type", "in_scope", "risk_total", "tier", "open_ports", "techs", "cve_count"];
    const lines = [header.join(",")];
    for (const a of rows) {
      lines.push([
        a.host, a.ip ?? "", a.env_type ?? "",
        a.in_scope ? "yes" : "no",
        String(a.risk_total),
        tier(a.risk_total),
        a.ports.map((p) => p.port).join(";"),
        a.techs.map((t) => `${t.name}/${t.version ?? ""}`).join(";"),
        String(a.cves.length),
      ].map((v) => `"${v.replace(/"/g, '""')}"`).join(","));
    }
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `engagement-${id}-assets.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const SortHeader = ({ k, label }: { k: SortKey; label: string }) => (
    <th
      className="text-left px-3 py-2 font-medium cursor-pointer select-none"
      onClick={() =>
        setSort((s) =>
          s.key === k
            ? { key: k, dir: s.dir === "asc" ? "desc" : "asc" }
            : { key: k, dir: "asc" })
      }
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {sort.key === k &&
          (sort.dir === "asc" ? (
            <ArrowUp className="h-3 w-3" />
          ) : (
            <ArrowDown className="h-3 w-3" />
          ))}
      </span>
    </th>
  );

  return (
    <Card>
      <CardContent className="p-0">
        <div className="flex items-center gap-2 p-3 border-b border-border">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filter host / IP / tech…"
            className="max-w-sm"
          />
          {(["all", "in", "oos"] as const).map((s) => (
            <Button
              key={s}
              size="sm"
              variant={scope === s ? "default" : "outline"}
              onClick={() => setScope(s)}
            >
              {s === "all" ? "All" : s === "in" ? "In scope" : "OOS"}
            </Button>
          ))}
          <span className="ml-auto text-xs text-muted-foreground">
            {rows.length} asset(s)
          </span>
          <Button size="sm" variant="outline" onClick={exportCsv}
                  disabled={rows.length === 0}>
            Export CSV
          </Button>
        </div>
        <table className="w-full text-sm">
          <thead className="bg-secondary/40 text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr>
              <SortHeader k="host" label="host" />
              <SortHeader k="ip" label="ip" />
              <SortHeader k="env_type" label="env" />
              <SortHeader k="risk_total" label="risk" />
              <SortHeader k="ports" label="ports" />
              <th className="text-left px-3 py-2 font-medium">techs</th>
              <SortHeader k="cves" label="cves" />
              <th className="text-left px-3 py-2 font-medium">scope</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.map((a) => (
              <tr
                key={a.id}
                className={cn(
                  "hover:bg-accent/40",
                  !a.in_scope && "opacity-60",
                )}
              >
                <td className="px-3 py-2 font-mono text-xs">{a.host}</td>
                <td className="px-3 py-2 font-mono text-xs">{a.ip ?? "—"}</td>
                <td className="px-3 py-2 text-xs">{a.env_type ?? "—"}</td>
                <td className="px-3 py-2">
                  <Badge variant={tier(a.risk_total) as "critical" | "high" | "medium" | "low" | "info"}>
                    {a.risk_total}
                  </Badge>
                </td>
                <td className="px-3 py-2 text-xs text-muted-foreground">
                  {a.ports.map((p) => p.port).join(", ") || "—"}
                </td>
                <td className="px-3 py-2 text-xs text-muted-foreground">
                  {a.techs.map((t) => t.name).join(", ") || "—"}
                </td>
                <td className="px-3 py-2 text-xs">{a.cves.length}</td>
                <td className="px-3 py-2 text-xs">
                  {a.in_scope ? "in" : <span className="text-destructive">OOS</span>}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-10 text-center text-muted-foreground">
                  No assets {filter ? "match this filter" : "yet"}.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
