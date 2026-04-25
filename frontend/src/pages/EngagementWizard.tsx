import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Check, ChevronLeft, ChevronRight, Loader2 } from "lucide-react";
import { createEngagement } from "@/api/engagements";
import { applyPreset } from "@/api/toolPolicy";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/PageHeader";
import { cn } from "@/lib/utils";

type Step = 1 | 2 | 3 | 4;
const STEP_LABELS: Record<Step, string> = {
  1: "Client",
  2: "Scope",
  3: "RoE preset",
  4: "Review",
};

const PRESETS: { id: string; label: string; blurb: string }[] = [
  {
    id: "open_bug_bounty",
    label: "Open bug bounty",
    blurb: "Everything allowed. Standard bounty engagement default.",
  },
  {
    id: "no_dos",
    label: "No DoS",
    blurb:
      "Blocks wrk / aireplay-ng / locust / monitor-mode and any 'stress' / 'escalating' steps.",
  },
  {
    id: "read_only_recon",
    label: "Read-only recon",
    blurb:
      "Blocks every active scanner (nmap / nikto / sqlmap / wpscan / hashcat / wifi attacks). Passive recon stays open.",
  },
];

interface ScopeRule {
  kind: "exact" | "wildcard" | "oos";
  pattern: string;
}

function parseScopeText(raw: string): ScopeRule[] {
  const out: ScopeRule[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx < 0) continue;
    const kind = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const pattern = trimmed.slice(colonIdx + 1).trim();
    if (!["exact", "wildcard", "oos"].includes(kind) || !pattern) continue;
    out.push({ kind: kind as ScopeRule["kind"], pattern });
  }
  return out;
}

export function EngagementWizardPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>(1);
  const [client, setClient] = useState("");
  const [domain, setDomain] = useState("");
  const [notes, setNotes] = useState("");
  const [scopeText, setScopeText] = useState(
    "# one rule per line: <kind>: <pattern>\n" +
      "# kind = exact | wildcard | oos\n" +
      "wildcard: example.com\n",
  );
  const [preset, setPreset] = useState<string>("open_bug_bounty");

  const scopeRules = parseScopeText(scopeText);

  const createMut = useMutation({
    mutationFn: async () => {
      const eng = await createEngagement({
        client,
        primary_domain: domain || null,
        notes: notes || null,
        scope: scopeRules,
      });
      if (preset !== "open_bug_bounty") {
        await applyPreset(eng.id, preset);
      }
      return eng;
    },
    onSuccess: (eng) => {
      navigate(`/engagements/${eng.id}`);
    },
  });

  const canProceed =
    step === 1 ? client.trim().length > 0 :
    step === 2 ? scopeRules.length > 0 :
    step === 3 ? !!preset :
    true;

  return (
    <>
      <PageHeader
        title="New engagement"
        description="Four steps. Cancel any time — nothing is persisted until step 4."
      />

      <div className="flex items-center gap-2 mb-6">
        {([1, 2, 3, 4] as Step[]).map((s) => (
          <div key={s} className="flex items-center gap-2 flex-1">
            <div
              className={cn(
                "flex h-7 w-7 items-center justify-center rounded-full",
                "text-xs font-bold border",
                s < step && "bg-green-500/20 border-green-400 text-green-300",
                s === step && "bg-primary/20 border-primary text-primary",
                s > step && "bg-muted border-muted-foreground/40 text-muted-foreground",
              )}
            >
              {s < step ? <Check className="h-3 w-3" /> : s}
            </div>
            <span
              className={cn(
                "text-sm font-medium",
                s === step ? "text-foreground" : "text-muted-foreground",
              )}
            >
              {STEP_LABELS[s]}
            </span>
            {s < 4 && (
              <div className="flex-1 h-px bg-border" />
            )}
          </div>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{STEP_LABELS[step]}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {step === 1 && (
            <div className="space-y-3">
              <div>
                <Label htmlFor="client">Client name *</Label>
                <Input
                  id="client" value={client}
                  onChange={(e) => setClient(e.target.value)}
                  placeholder="e.g. ACME Corp"
                  className="mt-1.5"
                />
              </div>
              <div>
                <Label htmlFor="domain">Primary domain</Label>
                <Input
                  id="domain" value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="e.g. acme.example"
                  className="mt-1.5"
                />
              </div>
              <div>
                <Label htmlFor="notes">Operator notes</Label>
                <Textarea
                  id="notes" value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Anything to remember about this engagement"
                  className="mt-1.5"
                  rows={3}
                />
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-3">
              <Label htmlFor="scope">Scope rules</Label>
              <p className="text-xs text-muted-foreground">
                One rule per line. Format: <code>kind: pattern</code>.
                Kinds: <code>exact</code> (single host), <code>wildcard</code>{" "}
                (host suffix), <code>oos</code> (out-of-scope override —
                always wins).
              </p>
              <Textarea
                id="scope" value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                rows={10}
                className="font-mono text-xs"
              />
              <p className="text-xs">
                <span className="font-semibold text-primary">{scopeRules.length}</span>{" "}
                valid rule(s) parsed.
              </p>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                The RoE preset seeds the engagement's tool policy.
                You can change individual toggles later on the
                Tooling page.
              </p>
              {PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setPreset(p.id)}
                  className={cn(
                    "w-full text-left rounded-md border p-4 transition",
                    preset === p.id
                      ? "border-primary bg-primary/5"
                      : "border-border hover:bg-accent/40",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium">{p.label}</span>
                    {preset === p.id && (
                      <Check className="h-4 w-4 text-primary" />
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {p.blurb}
                  </p>
                </button>
              ))}
            </div>
          )}

          {step === 4 && (
            <div className="space-y-3 text-sm">
              <ReviewRow label="Client" value={client} />
              <ReviewRow label="Domain" value={domain || "—"} />
              <ReviewRow label="Notes" value={notes || "—"} />
              <ReviewRow
                label="Scope"
                value={`${scopeRules.length} rule(s)`}
              />
              {scopeRules.length > 0 && (
                <pre className="text-xs bg-muted p-3 rounded font-mono">
                  {scopeRules
                    .map((r) => `${r.kind}: ${r.pattern}`)
                    .join("\n")}
                </pre>
              )}
              <ReviewRow
                label="Preset"
                value={
                  PRESETS.find((p) => p.id === preset)?.label ?? preset
                }
              />
              {createMut.error && (
                <p className="text-destructive text-xs">
                  {(createMut.error as Error).message}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center justify-between mt-6">
        <Button
          variant="outline"
          onClick={() => setStep((s) => (s === 1 ? 1 : ((s - 1) as Step)))}
          disabled={step === 1}
        >
          <ChevronLeft /> Back
        </Button>
        {step < 4 ? (
          <Button
            onClick={() =>
              setStep((s) => (s === 4 ? 4 : ((s + 1) as Step)))
            }
            disabled={!canProceed}
          >
            Next <ChevronRight />
          </Button>
        ) : (
          <Button
            onClick={() => createMut.mutate()}
            disabled={createMut.isPending || !client}
          >
            {createMut.isPending ? (
              <>
                <Loader2 className="animate-spin" /> Creating…
              </>
            ) : (
              "Create engagement"
            )}
          </Button>
        )}
      </div>
    </>
  );
}

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="text-xs uppercase tracking-wider text-muted-foreground w-16">
        {label}
      </span>
      <span className="text-sm">{value}</span>
    </div>
  );
}
