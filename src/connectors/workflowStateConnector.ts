import type { EvidenceSource } from "@aaliyah/contracts/v1";

export async function workflowStateConnector(
  _tenantId: string,
  _userId: string,
  _query: string,
): Promise<EvidenceSource[]> {
  // No production workflow-state backing store is configured. Empty evidence
  // is explicit and cannot acquire synthetic authority or fixed scores.
  return [];
}
