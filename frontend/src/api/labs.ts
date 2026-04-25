import { get, post } from "./client";
import type { Lab, LabActionResponse } from "./types";

export const listLabs = () => get<Lab[]>("/labs");

export const labMeta = () => get<{ docker_available: boolean }>("/labs/_meta");

export const labUp = (id: string, port?: number, wait_seconds = 0) =>
  post<LabActionResponse>(`/labs/${id}/up`, { port, wait_seconds });

export const labDown = (id: string) =>
  post<LabActionResponse>(`/labs/${id}/down`);

export const labLogs = (id: string, tail = 100) =>
  get<{ success: boolean; available: boolean; output: string; error: string | null }>(
    `/labs/${id}/logs`,
    { tail },
  );
