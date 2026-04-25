import { get, post } from "./client";
import type { Finding } from "./types";

export const listFindings = (engagementId: number) =>
  get<Finding[]>(`/engagements/${engagementId}/findings`);

export const finalizeFinding = (engagementId: number, findingId: number) =>
  post<{
    success: boolean;
    finding_id: number;
    archived_paths: string[];
    skipped: string[];
    error: string | null;
  }>(`/engagements/${engagementId}/findings/${findingId}/finalize`);

export const archiveStatus = (engagementId: number) =>
  get<{
    configured: boolean;
    archive_root: string | null;
    reports_dir: string | null;
    evidence_dir: string | null;
  }>(`/engagements/${engagementId}/archive-status`);
