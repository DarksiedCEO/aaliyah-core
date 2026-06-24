import {
  ConfidenceSchema,
  type Confidence,
  type ConfidenceLabel,
} from "@aaliyah/contracts/v1";

const HIGH_THRESHOLD = 80;
const MEDIUM_THRESHOLD = 50;

export function labelForScore(score: number): ConfidenceLabel {
  if (score >= HIGH_THRESHOLD) return "high";
  if (score >= MEDIUM_THRESHOLD) return "medium";
  return "low";
}

/** Low confidence forces manual review (inbound already requires it regardless). */
export function forcesManualReview(label: ConfidenceLabel): boolean {
  return label === "low";
}

/**
 * Build confidence metadata from a numeric score and a reason. Deterministic —
 * no learning, no model dependency.
 */
export function buildConfidence(score: number, reason: string): Confidence {
  const clamped = Math.max(0, Math.min(100, score));
  const label = labelForScore(clamped);
  return ConfidenceSchema.parse({
    score: clamped,
    label,
    reason:
      reason ||
      (label === "low"
        ? "Low signal — manual review required"
        : `Confidence ${label} (score ${clamped})`),
  });
}
