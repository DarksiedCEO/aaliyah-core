import type { ExecutionResult, TaskEnvelope } from "@aaliyah/contracts/v1";

export async function recoverOrEscalate(
  task: TaskEnvelope,
  priorResult: ExecutionResult,
): Promise<ExecutionResult> {
  return {
    ...priorResult,
    success: false,
    taskId: task.taskId,
    escalated: true,
    approvalState: "pending",
    postconditionsMet: false,
    message: "Postcondition verification failed; escalated for human review",
  };
}
