import type { FollowupDecision, FollowupExecutionInput } from "@aaliyah/contracts/v1";

export async function logExecution(entry: {
  input: FollowupExecutionInput;
  decision: FollowupDecision;
  draftId?: string;
}): Promise<void> {
  console.log("AALIYAH_EXECUTION_LOG", JSON.stringify(entry));
}
