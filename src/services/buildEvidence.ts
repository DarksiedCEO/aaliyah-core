import type {
  EvidenceBundle,
  EvidenceRankingPolicy,
  RetrievalRequest,
} from "@aaliyah/contracts/v1";

import type { TaskScope } from "./scopeTask";
import { retrieveEvidence } from "./retrieveEvidence";

export async function buildEvidence(scope: TaskScope): Promise<EvidenceBundle> {
  const request: RetrievalRequest = {
    tenantId: scope.tenantId,
    userId: scope.userId,
    query: scope.requestedOutcome,
    connectors: ["gmail", "calendar", "workflow_state"],
    limit: 10,
  };

  return retrieveEvidence(request);
}

export function defaultEvidenceRankingPolicy(): EvidenceRankingPolicy {
  return {
    minimumTrustLevel: "medium",
    requireFreshnessForWritePaths: true,
    maxSources: 10,
    weightRelevance: 0.45,
    weightAuthority: 0.35,
    weightRecency: 0.2,
  };
}

export function assertEvidenceQuality(
  evidence: EvidenceBundle,
  riskTier: TaskScope["riskTier"],
): void {
  if (riskTier === "A0_READ") {
    return;
  }

  if (evidence.sourceCount === 0) {
    throw new Error("No evidence sources available");
  }

  if (evidence.evidenceQualityScore < 70) {
    throw new Error("Evidence quality below threshold for write-capable task");
  }

  if (evidence.contradictionCount > 0) {
    throw new Error("Evidence contradictions unresolved");
  }
}
