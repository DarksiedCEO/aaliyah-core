import type { ConfidenceLabel } from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { readDecisionTraces } from "./decisionTrace";
import {
  summarizeDraftQuality,
  type DraftQualitySummary,
} from "./draftQuality";

export type TrustMetrics = {
  traceCount: number;
  quality: DraftQualitySummary;
  confidence: Record<ConfidenceLabel, number>;
};

/**
 * Read-only trust metrics for a (tenant, workspace). This is the monitoring
 * integration point — it READS scoped trust data and never alters the frozen
 * monitoring gate math. `confidence` is supplied by the caller (drafts in
 * flight); traces and quality are read from their scoped stores.
 */
export function trustMetricsSummary(
  scope: TenantScope,
  confidence: Record<ConfidenceLabel, number> = { high: 0, medium: 0, low: 0 },
): TrustMetrics {
  return {
    traceCount: readDecisionTraces(scope).length,
    quality: summarizeDraftQuality(scope),
    confidence,
  };
}
