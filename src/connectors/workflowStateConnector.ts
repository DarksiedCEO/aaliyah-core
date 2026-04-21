import type { EvidenceSource } from "@aaliyah/contracts/v1";

export async function workflowStateConnector(
  tenantId: string,
  userId: string,
  query: string,
): Promise<EvidenceSource[]> {
  return [
    {
      sourceId: `workflow:${tenantId}:${userId}:1`,
      sourceType: "workflow_state",
      title: `Workflow state for ${query}`,
      excerpt: "Simulated workflow-state evidence",
      trustLevel: "authoritative",
      freshness: "current",
      relevanceScore: 86,
      authorityScore: 95,
      recencyScore: 88,
      contradictionFlags: [],
      tags: ["workflow_state"],
      retrievedAt: new Date().toISOString(),
    },
  ];
}
