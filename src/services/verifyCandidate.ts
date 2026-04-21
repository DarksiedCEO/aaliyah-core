import type {
  Candidate,
  EvidenceBundle,
  TaskEnvelope,
  VerificationResult,
} from "@aaliyah/contracts/v1";
import type { TaskScope } from "./scopeTask";

type VerifyCandidateInput = {
  task: TaskEnvelope;
  scope: TaskScope;
  evidence: EvidenceBundle;
  candidate: Candidate;
  score: number;
  margin: number;
};

export async function verifyCandidate(
  input: VerifyCandidateInput,
): Promise<VerificationResult> {
  const hardBlocks: string[] = [];
  const softBlocks: string[] = [];
  const verifierNotes: string[] = [];

  void input.scope;

  if (input.candidate.blockers.length > 0) {
    hardBlocks.push(...input.candidate.blockers);
  }

  if (input.evidence.evidenceQualityScore < 70 && input.task.riskTier !== "A0_READ") {
    hardBlocks.push("Insufficient evidence quality");
  }

  if (input.evidence.contradictionCount > 0) {
    hardBlocks.push("Evidence contradictions unresolved");
  }

  if (input.score < 75) {
    softBlocks.push("Candidate score below preferred threshold");
  }

  if (input.margin < 5) {
    softBlocks.push("Decision margin too narrow");
  }

  if (input.candidate.downsideRisk > 60 && input.task.riskTier !== "A0_READ") {
    hardBlocks.push("Downside risk too high for autonomous progression");
  }

  verifierNotes.push(`score=${input.score}`);
  verifierNotes.push(`margin=${input.margin}`);
  verifierNotes.push(`evidenceQuality=${input.evidence.evidenceQualityScore}`);

  return {
    pass: hardBlocks.length === 0,
    confidence: Math.max(0, Math.min(100, input.score - softBlocks.length * 5)),
    hardBlocks,
    softBlocks,
    verifierNotes,
  };
}
