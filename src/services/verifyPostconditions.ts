import type { ExecutionResult, TaskEnvelope } from "@aaliyah/contracts/v1";

export async function verifyPostconditions(
  _task: TaskEnvelope,
  result: ExecutionResult,
): Promise<boolean> {
  // TODO: replace with real postcondition checks
  return result.success;
}
