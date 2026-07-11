import {
  DraftQualityRecordSchema,
  type DraftQualityOutcome,
  type DraftQualityRecord,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";

const QUALITY_STORE = "draft_quality";

/**
 * Record a draft quality outcome. MEASUREMENT ONLY — Block 6 deliberately does
 * not optimize or learn from these records.
 */
export async function recordDraftQuality(record: DraftQualityRecord): Promise<DraftQualityRecord> {
  const parsed = DraftQualityRecordSchema.parse(record);
  const scope: TenantScope = {
    tenantId: parsed.tenantId,
    workspaceId: parsed.workspaceId,
  };
  await applicationStoreFromEnv().logs.append(QUALITY_STORE, scope, parsed);
  return parsed;
}

export async function listDraftQuality(scope: TenantScope): Promise<DraftQualityRecord[]> {
  const rows = await applicationStoreFromEnv().logs.list(QUALITY_STORE, scope);
  return rows.map((r) => DraftQualityRecordSchema.parse(r));
}

export type DraftQualitySummary = {
  total: number;
  byOutcome: Record<DraftQualityOutcome, number>;
  averageEditDistance: number | null;
};

export async function summarizeDraftQuality(scope: TenantScope): Promise<DraftQualitySummary> {
  const records = await listDraftQuality(scope);
  const byOutcome: Record<DraftQualityOutcome, number> = {
    approved: 0,
    edited: 0,
    rejected: 0,
    sent: 0,
    failed: 0,
  };
  let editSum = 0;
  let editCount = 0;

  for (const r of records) {
    byOutcome[r.outcome] += 1;
    if (typeof r.editDistance === "number") {
      editSum += r.editDistance;
      editCount += 1;
    }
  }

  return {
    total: records.length,
    byOutcome,
    averageEditDistance: editCount > 0 ? editSum / editCount : null,
  };
}
