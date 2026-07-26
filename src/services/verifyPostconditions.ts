import {
  PostconditionVerificationReceiptV1Schema,
  assertPostconditionVerificationBindingV1,
  type ExecutionResult,
  type PostconditionVerificationReceiptV1,
  type TaskEnvelope,
} from "@aaliyah/contracts/v1";

export type PostconditionReceipt = PostconditionVerificationReceiptV1;

export type PostconditionVerifier = (
  task: TaskEnvelope,
  result: ExecutionResult,
) => Promise<unknown>;

export function validatePostconditionReceipt(
  taskId: string,
  result: ExecutionResult,
  receipt: PostconditionReceipt,
  options: {
    nowMs: number;
  },
): void {
  if (taskId !== result.taskId) {
    throw new Error("postcondition_verification_binding_invalid");
  }
  assertPostconditionVerificationBindingV1(result, receipt, options);
}

export async function verifyPostconditions(
  task: TaskEnvelope,
  result: ExecutionResult,
  options: { nowMs: number },
  verifier?: PostconditionVerifier,
): Promise<PostconditionReceipt> {
  if (!verifier) {
    throw new Error("postcondition_verifier_unavailable");
  }

  if (result.externalRefs.length === 0) {
    throw new Error("postcondition_claim_refs_missing");
  }

  const receipt = PostconditionVerificationReceiptV1Schema.parse(
    await verifier(task, result),
  );
  validatePostconditionReceipt(task.taskId, result, receipt, options);
  return receipt;
}
