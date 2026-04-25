import { get, post } from "./client";
import type { Procedure, StepRun } from "./types";

export const listProcedures = () => get<Procedure[]>("/procedures");

export const listRuns = (engagementId: number) =>
  get<StepRun[]>(`/engagements/${engagementId}/runs`);

export const queueStep = (engagementId: number, stepId: string,
                          params?: Record<string, unknown>) =>
  post<StepRun>("/steps/run", {
    engagement_id: engagementId,
    step_id: stepId,
    params: params ?? {},
  });
