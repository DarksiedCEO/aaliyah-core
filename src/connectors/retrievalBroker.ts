import type {
  ConnectorType,
  EvidenceSource,
  RetrievalRequest,
} from "@aaliyah/contracts/v1";

import { calendarConnector } from "./google/calendarConnector";
import { gmailConnector } from "./google/gmailConnector";
import { workflowStateConnector } from "./workflowStateConnector";

function googleConnectorConfigured(): boolean {
  return Boolean(
    process.env.GOOGLE_CLIENT_ID &&
      process.env.GOOGLE_CLIENT_SECRET &&
      process.env.GOOGLE_REDIRECT_URI,
  );
}

export async function retrievalBroker(
  request: RetrievalRequest,
): Promise<EvidenceSource[]> {
  const results: EvidenceSource[] = [];

  for (const connector of request.connectors) {
    let sources: EvidenceSource[] = [];

    switch (connector as ConnectorType) {
      case "gmail":
        if (!googleConnectorConfigured()) {
          sources = [];
          break;
        }

        sources = await gmailConnector({
          tenantId: request.tenantId,
          userId: request.userId,
          query: request.query,
        });
        break;
      case "calendar":
        if (!googleConnectorConfigured()) {
          sources = [];
          break;
        }

        sources = await calendarConnector({
          tenantId: request.tenantId,
          userId: request.userId,
          query: request.query,
        });
        break;
      case "workflow_state":
        sources = await workflowStateConnector(
          request.tenantId,
          request.userId,
          request.query,
        );
        break;
      case "crm":
        sources = [];
        break;
      default:
        sources = [];
    }

    results.push(...sources);
  }

  return results.slice(0, request.limit);
}
