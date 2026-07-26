import type {
  PlannerRequest,
  PlannerResponse,
  RankedEvidenceSource,
} from "@aaliyah/contracts/v1";

type PlanTaskInput = {
  request: PlannerRequest;
  rankedEvidence: RankedEvidenceSource[];
};

export async function planTask(
  _input: PlanTaskInput,
): Promise<PlannerResponse> {
  throw new Error("deterministic_planner_prohibited_in_production");
}
