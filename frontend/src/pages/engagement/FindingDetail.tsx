import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { archiveStatus, finalizeFinding, listFindings } from "@/api/findings";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge, StatusPill } from "@/components/StatusBadge";

const METRICS: {
  code: string; label: string; values: { v: string; n: string }[];
}[] = [
  { code: "AV", label: "Attack Vector",
    values: [{ v: "N", n: "Network" }, { v: "A", n: "Adjacent" },
             { v: "L", n: "Local" }, { v: "P", n: "Physical" }] },
  { code: "AC", label: "Attack Complexity",
    values: [{ v: "L", n: "Low" }, { v: "H", n: "High" }] },
  { code: "PR", label: "Privileges Required",
    values: [{ v: "N", n: "None" }, { v: "L", n: "Low" }, { v: "H", n: "High" }] },
  { code: "UI", label: "User Interaction",
    values: [{ v: "N", n: "None" }, { v: "R", n: "Required" }] },
  { code: "S",  label: "Scope",
    values: [{ v: "U", n: "Unchanged" }, { v: "C", n: "Changed" }] },
  { code: "C",  label: "Confidentiality",
    values: [{ v: "N", n: "None" }, { v: "L", n: "Low" }, { v: "H", n: "High" }] },
  { code: "I",  label: "Integrity",
    values: [{ v: "N", n: "None" }, { v: "L", n: "Low" }, { v: "H", n: "High" }] },
  { code: "A",  label: "Availability",
    values: [{ v: "N", n: "None" }, { v: "L", n: "Low" }, { v: "H", n: "High" }] },
];

export function FindingDetailPage() {
  const id = Number(useParams().id);
  const fid = Number(useParams().fid);
  const qc = useQueryClient();

  const { data: findings } = useQuery({
    queryKey: ["engagement", id, "findings"],
    queryFn: () => listFindings(id),
  });
  const { data: archive } = useQuery({
    queryKey: ["engagement", id, "archive-status"],
    queryFn: () => archiveStatus(id),
  });
  const finding = (findings ?? []).find((f) => f.id === fid);

  const [metrics, setMetrics] = useState<Record<string, string>>({
    AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "L", A: "L",
  });

  const finalizeMut = useMutation({
    mutationFn: () => finalizeFinding(id, fid),
    onSettled: () => qc.invalidateQueries({ queryKey: ["engagement", id, "findings"] }),
  });

  // Local CVSS calc helper (mirror of core/cvss.py)
  const score = computeCvss(metrics);
  const sev = severityForScore(score);

  if (!finding) {
    return <div className="text-muted-foreground">Loading…</div>;
  }

  return (
    <>
      <Link
        to={`/engagements/${id}/findings`}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-3"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> all findings
      </Link>
      <Card className="mb-5">
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-lg">
              #{finding.id} — {finding.title}
            </CardTitle>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <StatusPill status={finding.status} />
            </div>
          </div>
        </CardHeader>
        <CardContent className="text-sm space-y-2">
          {finding.cvss_vector && (
            <div className="font-mono text-xs text-muted-foreground">
              {finding.cvss_vector}{" "}
              {finding.cvss_score != null && `(${finding.cvss_score.toFixed(1)})`}
            </div>
          )}
          {finding.cwe && (
            <div className="text-xs text-muted-foreground">CWE: {finding.cwe}</div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-5">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">CVSS calculator</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2 text-xs mb-3">
              {METRICS.map((m) => (
                <label key={m.code} className="flex flex-col gap-1">
                  <span className="text-muted-foreground">
                    {m.code} ({m.label})
                  </span>
                  <select
                    value={metrics[m.code]}
                    onChange={(e) =>
                      setMetrics((prev) => ({ ...prev, [m.code]: e.target.value }))
                    }
                    className="rounded-md border border-input bg-background px-2 py-1"
                  >
                    {m.values.map((v) => (
                      <option key={v.v} value={v.v}>
                        {v.v} — {v.n}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
            </div>
            <div className="border-t border-border pt-3 mt-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Score:</span>
                <SeverityBadge severity={sev} />
              </div>
              <div className="text-2xl font-bold mt-1">{score.toFixed(1)}</div>
              <div className="font-mono text-[10px] text-muted-foreground mt-1">
                CVSS:3.1/AV:{metrics.AV}/AC:{metrics.AC}/PR:{metrics.PR}/UI:{metrics.UI}/
                S:{metrics.S}/C:{metrics.C}/I:{metrics.I}/A:{metrics.A}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Evidence + Finalize</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-muted-foreground text-xs">
              The legacy dashboard's screenshot redactor is at{" "}
              <a
                href={`/dashboard/engagements/${id}/findings/${fid}/redact`}
                className="text-primary hover:underline inline-flex items-center gap-1"
              >
                /dashboard…/redact <ExternalLink className="h-3 w-3" />
              </a>
              . An in-SPA redactor lands in 8C.
            </p>
            <div className="border-t border-border pt-3">
              <div className="text-xs uppercase tracking-wider text-muted-foreground mb-1">
                OneDrive archive
              </div>
              {archive?.configured ? (
                <p className="text-xs text-muted-foreground font-mono">
                  {archive.evidence_dir}
                </p>
              ) : (
                <p className="text-xs text-amber-400">
                  archive_root not configured
                </p>
              )}
              <Button
                onClick={() => finalizeMut.mutate()}
                disabled={finalizeMut.isPending || !archive?.configured}
                size="sm"
                className="mt-3"
              >
                Mark Final
              </Button>
              {finalizeMut.data && (
                <p className="text-xs mt-2 text-green-400">
                  Archived {finalizeMut.data.archived_paths.length} file(s).
                </p>
              )}
              {finalizeMut.error && (
                <p className="text-xs mt-2 text-destructive">
                  {(finalizeMut.error as Error).message}
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

// CVSS v3.1 base score (same formula as core/cvss.py).
const W_AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const W_AC: Record<string, number> = { L: 0.77, H: 0.44 };
const W_PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const W_PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
const W_UI: Record<string, number> = { N: 0.85, R: 0.62 };
const W_CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

function roundUp(v: number): number {
  const i = Math.round(v * 100000);
  if (i % 10000 === 0) return i / 100000;
  return Math.floor(i / 10000) / 10 + 0.1;
}

function computeCvss(m: Record<string, string>): number {
  const iss = 1 - ((1 - W_CIA[m.C]) * (1 - W_CIA[m.I]) * (1 - W_CIA[m.A]));
  const impact = m.S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const pr = m.S === "C" ? W_PR_C[m.PR] : W_PR_U[m.PR];
  const expl = 8.22 * W_AV[m.AV] * W_AC[m.AC] * pr * W_UI[m.UI];
  const score = m.S === "U" ? Math.min(impact + expl, 10) : Math.min(1.08 * (impact + expl), 10);
  return roundUp(score);
}

function severityForScore(s: number): string {
  if (s === 0) return "info";
  if (s < 4) return "low";
  if (s < 7) return "medium";
  if (s < 9) return "high";
  return "critical";
}
