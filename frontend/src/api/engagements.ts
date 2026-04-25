import { get, post } from "./client";
import type { Engagement, ScopeRule } from "./types";

export const listEngagements = () =>
  get<Engagement[]>("/engagements");

export const getEngagement = (id: number) =>
  get<Engagement>(`/engagements/${id}`);

export const getEngagementScope = (id: number) =>
  get<ScopeRule[]>(`/engagements/${id}/scope`);

export interface EngagementCreate {
  client: string;
  primary_domain?: string | null;
  notes?: string | null;
  scope?: { kind: string; pattern: string }[];
}

export const createEngagement = (body: EngagementCreate) =>
  post<Engagement>("/engagements", body);

export interface WorkflowStateStep {
  id: "setup" | "tooling" | "execute" | "triage" | "report" | "finalize";
  label: string;
  completion: number;       // 0.0 ... 1.0
  summary: string;
}

export interface WorkflowState {
  engagement_id: number;
  steps: WorkflowStateStep[];
  stats: {
    scope_rules: number;
    asset_count: number;
    finding_count: number;
    step_runs_done: number;
    step_runs_running: number;
    step_runs_failed: number;
    policy_caps_blocked: number;
    policy_steps_blocked: number;
    archive_configured: boolean;
  };
}

export const getWorkflowState = (id: number) =>
  get<WorkflowState>(`/engagements/${id}/workflow-state`);
