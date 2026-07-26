import type { Candidate, ExecutionResult } from "@aaliyah/contracts/v1";

type ExecuteOptions = {
  taskId: string;
  idempotencyKey: string;
};

export type CandidateExecutor = (
  candidate: Candidate,
  options: ExecuteOptions,
) => Promise<unknown>;

export async function executeIdempotent(
  candidate: Candidate,
  options: ExecuteOptions,
  executor?: CandidateExecutor,
): Promise<ExecutionResult> {
  if (!executor) {
    throw new Error("execution_capability_unavailable");
  }

  const raw = await executor(candidate, options);
  if (!raw || typeof raw !== "object") {
    throw new Error("executor_result_ambiguous");
  }

  const result = raw as Partial<ExecutionResult>;
  if (
    result.success !== true ||
    result.taskId !== options.taskId ||
    result.idempotencyKey !== options.idempotencyKey ||
    !Array.isArray(result.externalRefs) ||
    result.externalRefs.length === 0 ||
    result.externalRefs.some((ref) => typeof ref !== "string" || ref.length === 0)
  ) {
    throw new Error("executor_result_ambiguous");
  }

  return {
    ...result,
    success: false,
    taskId: options.taskId,
    idempotencyKey: options.idempotencyKey,
    approvalState: result.approvalState ?? "not_required",
    externalRefs: result.externalRefs,
    postconditionsMet: false,
    escalated: result.escalated ?? false,
    message: "Execution reported; independent postcondition verification required",
  };
}
