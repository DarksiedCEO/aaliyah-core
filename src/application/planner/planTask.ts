import type {
  PlannerCandidate,
  PlannerRequest,
  PlannerResponse,
  RankedEvidenceSource,
  TaskEnvelope,
} from "@aaliyah/contracts/v1";

type PlanTaskInput = {
  request: PlannerRequest;
  rankedEvidence: RankedEvidenceSource[];
};

function buildPrimaryCandidate(
  task: TaskEnvelope,
  rankedEvidence: RankedEvidenceSource[],
): PlannerCandidate {
  const topRefs = rankedEvidence.slice(0, 3).map((item) => ({
    sourceId: item.source.sourceId,
    rationale: `Ranked #${item.rank} with finalScore=${item.finalScore}`,
  }));

  return {
    name: "primary_action",
    description: `Primary action for ${task.taskType}`,
    args: {
      requestedOutcome: task.requestedOutcome,
    },
    rationale: "Best available action based on ranked evidence and current task policy.",
    evidenceRefs: topRefs.length > 0
      ? topRefs
      : [
          {
            sourceId: "synthetic:none",
            rationale: "No evidence available; fail-safe placeholder",
          },
        ],
    goalFit: 90,
    evidenceQuality: rankedEvidence[0]?.finalScore ?? 40,
    policyFit: 92,
    expectedValue: 78,
    reversibility: task.riskTier === "A0_READ" ? 100 : 75,
    downsideRisk: task.riskTier === "A0_READ" ? 5 : 20,
    ambiguity: rankedEvidence.length >= 2 ? 15 : 35,
    contradictions: 0,
    blockers: [],
  };
}

function buildDissentCandidate(
  task: TaskEnvelope,
  rankedEvidence: RankedEvidenceSource[],
): PlannerCandidate {
  const topRef = rankedEvidence[0];

  return {
    name: "dissent_action",
    description: `Conservative alternative for ${task.taskType}`,
    args: {
      requestedOutcome: task.requestedOutcome,
      mode: "conservative",
    },
    rationale: "Alternative path designed to challenge the primary option and lower risk.",
    evidenceRefs: topRef
      ? [
          {
            sourceId: topRef.source.sourceId,
            rationale: `Using highest-ranked source ${topRef.source.title}`,
          },
        ]
      : [
          {
            sourceId: "synthetic:none",
            rationale: "No evidence available; fallback candidate",
          },
        ],
    goalFit: 76,
    evidenceQuality: topRef?.finalScore ?? 35,
    policyFit: 96,
    expectedValue: 60,
    reversibility: 90,
    downsideRisk: 10,
    ambiguity: 20,
    contradictions: 0,
    blockers: [],
  };
}

export async function planTask(
  input: PlanTaskInput,
): Promise<PlannerResponse> {
  const { request, rankedEvidence } = input;
  const { task, policy } = request;

  const candidates: PlannerCandidate[] = [
    buildPrimaryCandidate(task, rankedEvidence),
  ];

  if (policy.requireDissentCandidate && policy.maxCandidates > 1) {
    candidates.push(buildDissentCandidate(task, rankedEvidence));
  }

  return {
    plannerVersion: "v1",
    candidates: candidates.slice(0, policy.maxCandidates),
    rejectedAlternatives: [],
  };
}
