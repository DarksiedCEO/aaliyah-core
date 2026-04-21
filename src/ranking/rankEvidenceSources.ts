import type {
  EvidenceBundle,
  EvidenceRankingPolicy,
  EvidenceSource,
  RankedEvidenceSource,
} from "@aaliyah/contracts/v1";

const TRUST_SCORE: Record<EvidenceSource["trustLevel"], number> = {
  low: 25,
  medium: 55,
  high: 80,
  authoritative: 95,
};

export function rankEvidenceSources(
  bundle: EvidenceBundle,
  policy: EvidenceRankingPolicy,
): RankedEvidenceSource[] {
  const minTrust = TRUST_SCORE[policy.minimumTrustLevel] ?? 0;

  return bundle.sources
    .filter((source: EvidenceSource) => (TRUST_SCORE[source.trustLevel] ?? 0) >= minTrust)
    .map((source) => {
      const contradictionPenalty = source.contradictionFlags.length * 10;
      const trustBoost = (TRUST_SCORE[source.trustLevel] ?? 0) * 0.15;

      const raw =
        source.relevanceScore * policy.weightRelevance +
        source.authorityScore * policy.weightAuthority +
        source.recencyScore * policy.weightRecency +
        trustBoost -
        contradictionPenalty;

      const finalScore = Math.max(0, Math.min(100, Math.round(raw)));

      return {
        source,
        finalScore,
      };
    })
    .sort((a, b) => b.finalScore - a.finalScore)
    .slice(0, policy.maxSources)
    .map((item, index) => ({
      ...item,
      rank: index + 1,
    }));
}
