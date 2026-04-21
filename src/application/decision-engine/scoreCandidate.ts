import type { Candidate } from "@aaliyah/contracts/v1";

export function scoreCandidate(candidate: Candidate): number {
  const raw =
    0.28 * candidate.goalFit +
    0.24 * candidate.evidenceQuality +
    0.18 * candidate.policyFit +
    0.12 * candidate.expectedValue +
    0.1 * candidate.reversibility -
    0.22 * candidate.downsideRisk -
    0.12 * candidate.ambiguity -
    4 * candidate.contradictions -
    (candidate.blockers.length > 0 ? 15 : 0);

  return Math.max(0, Math.min(100, Math.round(raw)));
}
