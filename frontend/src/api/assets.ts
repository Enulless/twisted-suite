import { get } from "./client";
import type { AssetDetail } from "./types";

export const listAssetDetail = (engagementId: number) =>
  get<AssetDetail[]>(`/engagements/${engagementId}/assets/detail`);
