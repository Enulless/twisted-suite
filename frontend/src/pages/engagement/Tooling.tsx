import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { toast } from "sonner";
import { AlertTriangle, Loader2, Search, Shield, ShieldOff } from "lucide-react";
import {
  applyPreset,
  clearPolicy,
  getPolicy,
  getPolicyInventory,
  toggleCapability,
  toggleStep,
} from "@/api/toolPolicy";
import type {
  ToolPolicyCapabilityInventoryItem,
  ToolPolicyStepInventoryItem,
} from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const PRESETS = [
  { id: "open_bug_bounty", label: "Open bug bounty",
    blurb: "Allow everything (clears all blocks)." },
  { id: "no_dos", label: "No DoS",
    blurb: "Block wrk / aireplay-ng / locust / monitor-mode + stress steps." },
  { id: "read_only_recon", label: "Read-only recon",
    blurb: "Block every active scanner; passive recon stays open." },
];

export function ToolingPage() {
  const id = Number(useParams().id);
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const [showOnlyBlocked, setShowOnlyBlocked] = useState(false);

  const inventoryQ = useQuery({
    queryKey: ["tool-policy-inventory", id],
    queryFn: () => getPolicyInventory(id),
  });
  const policyQ = useQuery({
    queryKey: ["tool-policy", id],
    queryFn: () => getPolicy(id),
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["tool-policy-inventory", id] });
    qc.invalidateQueries({ queryKey: ["tool-policy", id] });
    qc.invalidateQueries({ queryKey: ["workflow-state", id] });
  };

  const presetMut = useMutation({
    mutationFn: (preset: string) => applyPreset(id, preset),
    onSuccess: (r) => toast.success(`Applied preset: ${r.preset}`, {
      description: `${r.capability_blocks.length} caps + ${r.step_blocks.length} steps blocked`,
    }),
    onError: (e) => toast.error("Preset failed", { description: (e as Error).message }),
    onSettled: invalidate,
  });
  const clearMut = useMutation({
    mutationFn: () => clearPolicy(id),
    onSuccess: () => toast.success("Cleared all blocks"),
    onError: (e) => toast.error("Clear failed", { description: (e as Error).message }),
    onSettled: invalidate,
  });
  const stepMut = useMutation({
    mutationFn: ({ stepId, allowed }: { stepId: string; allowed: boolean }) =>
      toggleStep(id, stepId, allowed),
    onSuccess: (_d, vars) => toast.success(
      `${vars.allowed ? "Allowed" : "Blocked"} step ${vars.stepId}`,
    ),
    onError: (e) => toast.error("Toggle failed", { description: (e as Error).message }),
    onSettled: invalidate,
  });
  const capMut = useMutation({
    mutationFn: ({ cap, allowed }: { cap: string; allowed: boolean }) =>
      toggleCapability(id, cap, allowed),
    onSuccess: (_d, vars) => toast.success(
      `${vars.allowed ? "Allowed" : "Blocked"} capability '${vars.cap}'`,
    ),
    onError: (e) => toast.error("Toggle failed", { description: (e as Error).message }),
    onSettled: invalidate,
  });

  // Group steps by procedure → stage for the right panel
  const grouped = useMemo(() => {
    const filtered = (inventoryQ.data?.steps ?? []).filter((s) => {
      if (showOnlyBlocked && s.allowed) return false;
      if (filter) {
        const f = filter.toLowerCase();
        return (
          s.step_id.toLowerCase().includes(f) ||
          s.name.toLowerCase().includes(f)
        );
      }
      return true;
    });
    const out: Record<string, Record<string, ToolPolicyStepInventoryItem[]>> = {};
    for (const step of filtered) {
      const stage = step.stage ?? "_misc";
      ((out[step.procedure] ??= {})[stage] ??= []).push(step);
    }
    return out;
  }, [inventoryQ.data?.steps, filter, showOnlyBlocked]);

  return (
    <>
      {/* Preset buttons */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="text-base">Apply a preset</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-3">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                disabled={presetMut.isPending}
                onClick={() => presetMut.mutate(p.id)}
                className={cn(
                  "text-left rounded-md border border-border p-3",
                  "hover:bg-accent/50 transition-colors",
                  "disabled:opacity-60",
                )}
              >
                <div className="font-medium text-sm">{p.label}</div>
                <div className="text-xs text-muted-foreground mt-1">{p.blurb}</div>
              </button>
            ))}
          </div>
          <div className="mt-3 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Currently blocked:{" "}
              <strong>{policyQ.data?.capabilities_blocked.length ?? 0}</strong>{" "}
              capabilities,{" "}
              <strong>{policyQ.data?.steps_blocked.length ?? 0}</strong> steps.
            </p>
            <Button
              variant="ghost" size="sm"
              onClick={() => clearMut.mutate()}
              disabled={clearMut.isPending}
            >
              {clearMut.isPending ? <Loader2 className="animate-spin" /> : null}
              Clear all blocks
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-[280px_1fr] gap-4 items-start">
        {/* Capability panel */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">By capability</CardTitle>
            <p className="text-xs text-muted-foreground">
              Blocking a capability cascades — every step requiring it
              gets blocked too.
            </p>
          </CardHeader>
          <CardContent className="space-y-1.5 max-h-[600px] overflow-y-auto">
            {(inventoryQ.data?.capabilities ?? []).map((cap) => (
              <CapabilityRow
                key={cap.capability}
                cap={cap}
                onToggle={(allowed) =>
                  capMut.mutate({ cap: cap.capability, allowed })
                }
                pending={capMut.isPending}
              />
            ))}
          </CardContent>
        </Card>

        {/* Step panel */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">By step</CardTitle>
            <div className="flex items-center gap-2 mt-2">
              <div className="relative flex-1">
                <Search className="h-4 w-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="search step id or name…"
                  className="pl-8"
                />
              </div>
              <Button
                variant={showOnlyBlocked ? "default" : "outline"}
                size="sm"
                onClick={() => setShowOnlyBlocked((v) => !v)}
              >
                {showOnlyBlocked ? "All" : "Blocked only"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3 max-h-[700px] overflow-y-auto">
            {Object.entries(grouped).map(([procId, stages]) => (
              <div key={procId} className="space-y-2">
                <div className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  {procId}
                </div>
                {Object.entries(stages).map(([stageId, steps]) => (
                  <details key={stageId} open className="border border-border rounded-md p-2">
                    <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
                      {stageId} · {steps.length} step(s)
                    </summary>
                    <div className="mt-2 space-y-1">
                      {steps.map((step) => (
                        <StepRow
                          key={step.step_id}
                          step={step}
                          onToggle={(allowed) =>
                            stepMut.mutate({ stepId: step.step_id, allowed })
                          }
                          pending={stepMut.isPending}
                        />
                      ))}
                    </div>
                  </details>
                ))}
              </div>
            ))}
            {inventoryQ.data && inventoryQ.data.steps.length > 0 &&
             Object.keys(grouped).length === 0 && (
              <p className="text-sm text-muted-foreground py-6 text-center">
                No steps match the current filter.
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function CapabilityRow({
  cap,
  onToggle,
  pending,
}: {
  cap: ToolPolicyCapabilityInventoryItem;
  onToggle: (allowed: boolean) => void;
  pending: boolean;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-2 px-2 py-1.5 rounded",
        cap.allowed ? "" : "bg-destructive/5",
      )}
    >
      <div className="flex items-center gap-2 min-w-0">
        {cap.allowed ? (
          <Shield className="h-3.5 w-3.5 text-green-400 flex-shrink-0" />
        ) : (
          <ShieldOff className="h-3.5 w-3.5 text-destructive flex-shrink-0" />
        )}
        <code className="text-xs truncate">{cap.capability}</code>
        <span className="text-[10px] text-muted-foreground">
          ({cap.step_count})
        </span>
      </div>
      <Button
        size="sm"
        variant={cap.allowed ? "outline" : "destructive"}
        onClick={() => onToggle(!cap.allowed)}
        disabled={pending}
        className="h-6 px-2 text-[10px]"
      >
        {cap.allowed ? "Block" : "Allow"}
      </Button>
    </div>
  );
}

function StepRow({
  step,
  onToggle,
  pending,
}: {
  step: ToolPolicyStepInventoryItem;
  onToggle: (allowed: boolean) => void;
  pending: boolean;
}) {
  const cascadedFromCap =
    !step.allowed && step.block_kind === "capability";
  return (
    <div
      className={cn(
        "flex items-start gap-2 px-2 py-1.5 rounded",
        step.allowed ? "hover:bg-accent/50"
                     : cascadedFromCap ? "bg-amber-500/5"
                     : "bg-destructive/5",
      )}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <code className="text-xs">{step.step_id}</code>
          <Badge variant="outline" className="text-[9px]">
            {step.runtime}
          </Badge>
          {cascadedFromCap && (
            <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-400/40">
              <AlertTriangle className="h-3 w-3 mr-1" />
              via cap
            </Badge>
          )}
        </div>
        <div className="text-xs text-muted-foreground truncate mt-0.5">
          {step.name}
        </div>
        {step.block_reason && (
          <div className="text-[10px] text-amber-400 mt-0.5">
            {step.block_reason}
          </div>
        )}
      </div>
      <Button
        size="sm"
        variant={step.allowed ? "outline" : "destructive"}
        onClick={() => onToggle(!step.allowed)}
        disabled={pending || cascadedFromCap}
        title={cascadedFromCap
          ? "Allow the underlying capability first"
          : undefined}
        className="h-6 px-2 text-[10px] flex-shrink-0"
      >
        {step.allowed ? "Block" : "Allow"}
      </Button>
    </div>
  );
}
