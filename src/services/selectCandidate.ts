import type {
  PlannerCandidate,
  RankedCandidate,
} from "@aaliyah/contracts/v1";

import { scoreCandidate } from "../application/decision-engine/scoreCandidate";

export function selectCandidate(
  candidates: PlannerCandidate[],
): {
  ranked: RankedCandidate[];
  top: RankedCandidate;
  margin: number;
} {
  const ranked: RankedCandidate[] = candidates
    .map((candidate) => ({
      candidate,
      score: scoreCandidate(candidate),
    }))
    .sort((a, b) => b.score - a.score);

  if (ranked.length === 0) {
    throw new Error("No planner candidates available");
  }

  const top = ranked[0];
  if (!top) {
    throw new Error("No top-ranked planner candidate available");
  }

  const runnerUp = ranked[1];
  const margin = runnerUp ? top.score - runnerUp.score : top.score;

  return { ranked, top, margin };
}
