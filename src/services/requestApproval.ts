import type {
  Candidate,
  ExecutionResult,
  TaskEnvelope,
  VerificationResult,
} from "@aaliyah/contracts/v1";

export async function requestApproval(
  task: TaskEnvelope,
  candidate: Candidate,
  verification: VerificationResult,
): Promise<ExecutionResult> {
  return {
    success: false,
    taskId: task.taskId,
    idempotencyKey: task.taskId,
    approvalState: "pending",
    externalRefs: [],
    postconditionsMet: false,
    escalated: false,
    message: `Approval required for candidate "${candidate.name}". Confidence=${verification.confidence}`,
  };
}
