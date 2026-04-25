import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Loader2, Sparkles } from "lucide-react";
import { queueStep } from "@/api/jobs";
import { archiveStatus } from "@/api/findings";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const FORMATS = [
  { id: "markdown", label: "Markdown" },
  { id: "html", label: "HTML" },
  { id: "executive", label: "Executive HTML" },
  { id: "pdf", label: "Full PDF (WeasyPrint)" },
  { id: "executive_pdf", label: "Executive PDF" },
];

export function ReportPage() {
  const id = Number(useParams().id);
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(
    new Set(["html", "executive_pdf"]),
  );
  const { data: archive } = useQuery({
    queryKey: ["engagement", id, "archive-status"],
    queryFn: () => archiveStatus(id),
  });

  const buildMut = useMutation({
    mutationFn: () =>
      queueStep(id, "bb.stage5.build_report", {
        formats: Array.from(selected),
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["engagement", id, "runs"] }),
  });

  const exportMut = useMutation({
    mutationFn: () => queueStep(id, "bb.stage5.export_findings"),
    onSettled: () => qc.invalidateQueries({ queryKey: ["engagement", id, "runs"] }),
  });

  return (
    <div className="grid grid-cols-2 gap-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Build report</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-xs text-muted-foreground">
            Pick output formats and queue a build. Renders against the
            current findings + assets snapshot.
          </p>
          <div className="space-y-1.5">
            {FORMATS.map((f) => (
              <label
                key={f.id}
                className={cn(
                  "flex items-center gap-2 rounded px-2 py-1.5 cursor-pointer",
                  selected.has(f.id) ? "bg-accent" : "hover:bg-accent/40",
                )}
              >
                <input
                  type="checkbox"
                  checked={selected.has(f.id)}
                  onChange={() =>
                    setSelected((s) => {
                      const n = new Set(s);
                      if (n.has(f.id)) n.delete(f.id);
                      else n.add(f.id);
                      return n;
                    })
                  }
                />
                <span>{f.label}</span>
              </label>
            ))}
          </div>
          <Button
            onClick={() => buildMut.mutate()}
            disabled={buildMut.isPending || selected.size === 0}
          >
            {buildMut.isPending ? <Loader2 className="animate-spin" /> : <Sparkles />}
            Queue report build
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export findings spreadsheet</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-xs text-muted-foreground">
            XLSX with Summary / Findings / Assets / CVEs / Risk_Scores /
            Remediation sheets, plus a CSV.
          </p>
          <Button
            onClick={() => exportMut.mutate()}
            disabled={exportMut.isPending}
            variant="outline"
          >
            {exportMut.isPending ? <Loader2 className="animate-spin" /> : null}
            Queue spreadsheet export
          </Button>
        </CardContent>
      </Card>

      <Card className="col-span-2">
        <CardHeader>
          <CardTitle className="text-base">OneDrive archive</CardTitle>
        </CardHeader>
        <CardContent className="text-sm space-y-2">
          {archive?.configured ? (
            <>
              <p className="text-xs text-muted-foreground">
                Reports → <code>{archive.reports_dir}</code>
                <br />
                Evidence → <code>{archive.evidence_dir}</code>
              </p>
              <p className="text-xs text-muted-foreground">
                Promote individual findings to the archive on the
                Findings detail page (Mark Final).
              </p>
            </>
          ) : (
            <p className="text-amber-400 text-xs">
              <code>TWISTED_ARCHIVE_ROOT</code> isn't configured. Set it in
              the engine environment to enable finalize / archive.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
