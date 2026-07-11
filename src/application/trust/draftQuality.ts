import fs from "node:fs";
import path from "node:path";

import {
  DraftQualityRecordSchema,
  type DraftQualityOutcome,
  type DraftQualityRecord,
} from "@aaliyah/contracts/v1";

import {
  scopedJsonlPath,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

const QUALITY_FILE = "draft-quality.jsonl";

/**
 * Record a draft quality outcome. MEASUREMENT ONLY — Block 6 deliberately does
 * not optimize or learn from these records.
 */
export function recordDraftQuality(record: DraftQualityRecord): DraftQualityRecord {
  const parsed = DraftQualityRecordSchema.parse(record);
  const scope: TenantScope = {
    tenantId: parsed.tenantId,
    workspaceId: parsed.workspaceId,
  };
  const fp = scopedJsonlPath(QUALITY_FILE, scope);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.appendFileSync(fp, `${JSON.stringify(parsed)}\n`, "utf8");
  return parsed;
}

export function listDraftQuality(scope: TenantScope): DraftQualityRecord[] {
  const fp = scopedJsonlPath(QUALITY_FILE, scope);
  if (!fs.existsSync(fp)) return [];
  return fs
    .readFileSync(fp, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => DraftQualityRecordSchema.parse(JSON.parse(l)));
}

export type DraftQualitySummary = {
  total: number;
  byOutcome: Record<DraftQualityOutcome, number>;
  averageEditDistance: number | null;
};

export function summarizeDraftQuality(scope: TenantScope): DraftQualitySummary {
  const records = listDraftQuality(scope);
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
