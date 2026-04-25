import { del, get, post, put } from "./client";
import type {
  ToolPolicyInventory,
  ToolPolicyRow,
  ToolPolicySnapshot,
} from "./types";

export const getPolicy = (engagementId: number) =>
  get<ToolPolicySnapshot>(`/engagements/${engagementId}/tool-policy`);

export const getPolicyInventory = (engagementId: number) =>
  get<ToolPolicyInventory>(
    `/engagements/${engagementId}/tool-policy/inventory`,
  );

export const toggleStep = (
  engagementId: number,
  stepId: string,
  allowed: boolean,
  note?: string,
) =>
  put<ToolPolicyRow>(
    `/engagements/${engagementId}/tool-policy/step/${encodeURIComponent(stepId)}`,
    { allowed, note },
  );

export const toggleCapability = (
  engagementId: number,
  capability: string,
  allowed: boolean,
  note?: string,
) =>
  put<ToolPolicyRow>(
    `/engagements/${engagementId}/tool-policy/capability/${encodeURIComponent(capability)}`,
    { allowed, note },
  );

export interface PresetApplyResponse {
  preset: string;
  cleared: number;
  capability_blocks: string[];
  step_blocks: string[];
}

export const applyPreset = (engagementId: number, preset: string) =>
  post<PresetApplyResponse>(
    `/engagements/${engagementId}/tool-policy/preset/${preset}`,
  );

export const clearPolicy = (engagementId: number) =>
  del<void>(`/engagements/${engagementId}/tool-policy`);
