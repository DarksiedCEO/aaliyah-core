import type { ExecutionResult, TaskEnvelope } from "@aaliyah/contracts/v1";

export type PostconditionReceipt = {
  verified: boolean;
  taskId: string;
  idempotencyKey: string;
  externalRefs: string[];
  verifier: string;
  verifiedAt: string;
  reason?: string;
};

export type PostconditionVerifier = (
  task: TaskEnvelope,
  result: ExecutionResult,
) => Promise<PostconditionReceipt>;

export function validatePostconditionReceipt(
  taskId: string,
  result: ExecutionResult,
  receipt: PostconditionReceipt,
  options: {
    enforceFreshness?: boolean;
    nowMs?: number;
  } = {},
): void {
  if (
    typeof receipt !== "object" ||
    receipt === null ||
    typeof receipt.verified !== "boolean" ||
    typeof receipt.taskId !== "string" ||
    typeof receipt.idempotencyKey !== "string" ||
    !Array.isArray(receipt.externalRefs) ||
    receipt.externalRefs.some((ref) => typeof ref !== "string" || ref.length === 0) ||
    typeof receipt.verifier !== "string" ||
    typeof receipt.verifiedAt !== "string"
  ) {
    throw new Error("postcondition_receipt_shape_invalid");
  }

  if (!receipt.verified) {
    throw new Error(`postcondition_not_verified:${receipt.reason ?? "unspecified"}`);
  }

  if (
    receipt.taskId !== taskId ||
    receipt.taskId !== result.taskId ||
    receipt.idempotencyKey !== result.idempotencyKey ||
    receipt.verifier.trim().length === 0
  ) {
    throw new Error("postcondition_receipt_binding_invalid");
  }

  const verifiedAt = Date.parse(receipt.verifiedAt);
  if (
    !Number.isFinite(verifiedAt) ||
    (
      options.enforceFreshness !== false &&
      Math.abs((options.nowMs ?? Date.now()) - verifiedAt) > 5 * 60 * 1000
    )
  ) {
    throw new Error("postcondition_receipt_stale");
  }

  const claimedRefs = [...new Set(result.externalRefs)].sort();
  const receiptRefs = [...new Set(receipt.externalRefs)].sort();
  if (
    claimedRefs.length === 0 ||
    claimedRefs.length !== result.externalRefs.length ||
    receiptRefs.length !== receipt.externalRefs.length ||
    claimedRefs.length !== receiptRefs.length ||
    claimedRefs.some((ref, index) => ref !== receiptRefs[index])
  ) {
    throw new Error("postcondition_receipt_ref_coverage_invalid");
  }
}

export async function verifyPostconditions(
  task: TaskEnvelope,
  result: ExecutionResult,
  verifier?: PostconditionVerifier,
): Promise<PostconditionReceipt> {
  if (!verifier) {
    throw new Error("postcondition_verifier_unavailable");
  }

  if (result.externalRefs.length === 0) {
    throw new Error("postcondition_claim_refs_missing");
  }

  const receipt = await verifier(task, result);
  validatePostconditionReceipt(task.taskId, result, receipt);
  return receipt;
}
