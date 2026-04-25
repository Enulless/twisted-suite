// TypeScript mirrors of the Pydantic schemas exposed by the engine API.
// Keep in sync with src/twisted/engine/schemas.py + the per-router
// inline models.

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "informational";

export type EngagementStatus =
  | "planning"
  | "active"
  | "reporting"
  | "closed";

export type FindingStatus =
  | "draft"
  | "needs_verification"
  | "confirmed"
  | "false_positive"
  | "reported"
  | "remediated";

export type StepStatus =
  | "pending"
  | "running"
  | "done"
  | "failed"
  | "skipped";

export type WorkerStatus = "online" | "busy" | "offline";

// ──────────────────────────── Domain ────────────────────────────

export interface Engagement {
  id: number;
  client: string;
  primary_domain: string | null;
  status: EngagementStatus;
  root_dir: string | null;
  created_at: string;
}

export interface ScopeRule {
  kind: "exact" | "wildcard" | "oos";
  pattern: string;
  note?: string | null;
}

export interface Worker {
  id: string;
  hostname: string;
  os: string;
  capabilities: string[];
  tags?: string[] | null;
  status: WorkerStatus;
  registered_at: string;
  last_seen: string;
  version?: string | null;
}

export interface Asset {
  id: number;
  engagement_id: number;
  host: string;
  ip: string | null;
  env_type: string | null;
  source: string | null;
  in_scope: boolean;
  risk_total: number;
  discovered_at: string;
  last_seen: string;
}

export interface AssetDetail {
  id: number;
  host: string;
  ip: string | null;
  env_type: string | null;
  in_scope: boolean;
  risk_total: number;
  ports: { port: number; proto: string; service?: string; version?: string }[];
  techs: { name: string; version?: string; category?: string; source?: string }[];
  cves: { cve_id: string; cvss_score?: number; severity?: string; summary?: string }[];
  risk_scores: { factor: string; points: number; note?: string }[];
}

export interface Finding {
  id: number;
  engagement_id: number;
  title: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe: string | null;
  status: FindingStatus;
}

export interface StepRun {
  id: number;
  engagement_id: number;
  procedure: string;
  stage: string | null;
  step_id: string;
  mode: "auto" | "walkthrough" | "hybrid";
  status: StepStatus;
  started_at: string | null;
  ended_at: string | null;
  worker_id: string | null;
  output_summary: string | null;
}

export interface Procedure {
  id: string;
  name: string;
  description: string | null;
  stages: ProcedureStage[];
}

export interface ProcedureStage {
  id: string;
  name: string;
  objective: string | null;
  steps: ProcedureStep[];
}

export interface ProcedureStep {
  id: string;
  name: string;
  mode: string;
  runtime: string;
  requires: string[];
}

// ──────────────────────────── Tool policy ────────────────────────────

export interface ToolPolicyRow {
  target_kind: "step" | "capability";
  target_value: string;
  allowed: boolean;
  note: string | null;
  updated_at: string | null;
}

export interface ToolPolicySnapshot {
  engagement_id: number;
  rows: ToolPolicyRow[];
  capabilities_blocked: string[];
  steps_blocked: string[];
  presets_available: string[];
}

export interface ToolPolicyStepInventoryItem {
  step_id: string;
  name: string;
  procedure: string;
  stage: string | null;
  mode: string;
  runtime: string;
  requires: string[];
  allowed: boolean;
  block_reason: string | null;
  block_kind: "step" | "capability" | null;
}

export interface ToolPolicyCapabilityInventoryItem {
  capability: string;
  allowed: boolean;
  step_count: number;
  note: string | null;
}

export interface ToolPolicyInventory {
  engagement_id: number;
  capabilities: ToolPolicyCapabilityInventoryItem[];
  steps: ToolPolicyStepInventoryItem[];
}

// ──────────────────────────── Labs ────────────────────────────

export interface Lab {
  id: string;
  name: string;
  description: string;
  state: "up" | "down" | "partial" | "unknown";
  target_url: string;
  project_name: string;
  services: Record<string, string>;
  practice_for: string[];
}

export interface LabActionResponse {
  success: boolean;
  available: boolean;
  state: string | null;
  output: string;
  error: string | null;
}

// ──────────────────────────── Training ────────────────────────────

export interface LessonSummary {
  step_id: string;
  procedure: string;
  stage: string | null;
  title: string;
  has_quiz: boolean;
  estimated_minutes: number | null;
  completed: boolean;
  last_score: number | null;
}

export interface LessonDetail {
  step_id: string;
  procedure: string;
  stage: string | null;
  title: string;
  body: string;
  sections: Record<string, string>;
  estimated_minutes: number | null;
  quiz: QuizDetail | null;
  progress: QuizAttempt | null;
}

export interface QuizDetail {
  id: string;
  step_id: string;
  title: string;
  pass_threshold: number;
  questions: QuizQuestion[];
}

export interface QuizQuestion {
  id: string;
  type: "multiple_choice" | "short_answer";
  prompt: string;
  choices: Record<string, string>;
}

export interface QuizAttempt {
  quiz_id: string;
  step_id: string;
  user: string;
  correct_count: number;
  total: number;
  score: number;
  passed: boolean;
  completed_at: string;
  per_question?: {
    question_id: string;
    correct: boolean;
    response: string | null;
    expected: string;
    explain: string | null;
  }[];
}
