import type {
  ExecutionResult,
  TaskEnvelope,
  VerificationResult,
} from "@aaliyah/contracts/v1";

export async function escalateForReview(
  task: TaskEnvelope,
  verification: VerificationResult,
): Promise<ExecutionResult> {
  return {
    success: false,
    taskId: task.taskId,
    idempotencyKey: task.taskId,
    approvalState: "pending",
    externalRefs: [],
    postconditionsMet: false,
    escalated: true,
    message: `Escalated for review: ${verification.hardBlocks.join("; ") || "manual review required"}`,
  };
}
