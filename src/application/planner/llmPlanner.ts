import type {
  PlannerRequest,
  PlannerResponse,
  RankedEvidenceSource,
} from "@aaliyah/contracts/v1";
import { PlannerResponseSchema } from "@aaliyah/contracts/v1";

import { logger } from "../../observability/logger";
import { planTask } from "./planTask";

// Replace this with your actual LLM client (OpenAI / etc.)
async function callLLM(prompt: string): Promise<string> {
  void prompt;

  // TODO: wire real client
  throw new Error("LLM client not implemented");
}

function buildPrompt(
  input: PlannerRequest,
  rankedEvidence: RankedEvidenceSource[],
): string {
  return `
You are Aaliyah Planner.

Task:
${input.task.requestedOutcome}

Constraints:
${input.task.constraints.join(", ")}

Ranked Evidence:
${rankedEvidence
    .map(
      (item) =>
        `- rank=${item.rank} sourceId=${item.source.sourceId} title=${item.source.title} finalScore=${item.finalScore}`,
    )
    .join("\n")}

Rules:
- Produce ${input.policy.maxCandidates} candidates
- Each candidate must include:
  name, description, args, rationale, evidenceRefs, scores
- One MUST be a dissenting / conservative option

Return ONLY valid JSON matching schema.
`;
}

export async function llmPlanner(
  request: PlannerRequest,
  rankedEvidence: RankedEvidenceSource[] = [],
): Promise<PlannerResponse> {
  const prompt = buildPrompt(request, rankedEvidence);

  try {
    const raw = await callLLM(prompt);

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error("LLM returned invalid JSON");
    }

    const result = PlannerResponseSchema.parse(parsed);

    logger.info(
      {
        candidateCount: result.candidates.length,
      },
      "planner.llm.completed",
    );

    return result;
  } catch (error) {
    logger.warn(
      {
        error: error instanceof Error ? error.message : String(error),
      },
      "planner.llm.fallback",
    );

    return planTask({
      request,
      rankedEvidence,
    });
  }
}
