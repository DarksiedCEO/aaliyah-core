import type {
  EvidenceBundle,
  RetrievalRequest,
} from "@aaliyah/contracts/v1";
import { EvidenceBundleSchema } from "@aaliyah/contracts/v1";

import { retrievalBroker } from "../connectors/retrievalBroker";
import { detectContradictions } from "./detectContradictions";

export async function retrieveEvidence(
  request: RetrievalRequest,
): Promise<EvidenceBundle> {
  const rawSources = await retrievalBroker(request);
  const sources = detectContradictions(rawSources);

  const contradictionCount = sources.reduce(
    (sum, source) => sum + source.contradictionFlags.length,
    0,
  );

  const quality =
    sources.length === 0
      ? 0
      : Math.min(
          100,
          Math.round(
            sources.reduce(
              (sum, source) =>
                sum +
                source.relevanceScore * 0.4 +
                source.authorityScore * 0.35 +
                source.recencyScore * 0.25,
              0,
            ) / sources.length,
          ),
        );

  return EvidenceBundleSchema.parse({
    bundleId: `bundle:${request.tenantId}:${Date.now()}`,
    sourceCount: sources.length,
    contradictionCount,
    evidenceQualityScore: quality,
    sources,
  });
}
