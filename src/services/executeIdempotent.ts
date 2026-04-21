import type { Candidate, ExecutionResult } from "@aaliyah/contracts/v1";

type ExecuteOptions = {
  taskId: string;
  idempotencyKey: string;
};

export async function executeIdempotent(
  candidate: Candidate,
  options: ExecuteOptions,
): Promise<ExecutionResult> {
  // TODO: replace with real tool execution layer
  return {
    success: true,
    taskId: options.taskId,
    idempotencyKey: options.idempotencyKey,
    approvalState: "not_required",
    externalRefs: [`simulated:${candidate.name}`],
    postconditionsMet: false,
    escalated: false,
    message: `Executed candidate: ${candidate.name}`,
  };
}
