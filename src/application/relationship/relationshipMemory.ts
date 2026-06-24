import {
  RelationshipContextSchema,
  type CommunicationStyle,
  type RelationshipContext,
  type RelationshipRecord,
} from "@aaliyah/contracts/v1";

import { requireTenantContext } from "../../governance/requireTenantContext";
import type { TenantScope } from "../../persistence/tenantScopedStore";
import { getRelationship, saveRelationship } from "./relationshipStore";

const MAX_SUMMARIES = 20;

/**
 * Record an interaction with a contact, upserting the relationship record.
 * Advisory memory only — recording never triggers any action or send.
 */
export function recordInteraction(input: {
  tenantId: string;
  userId: string;
  workspaceId?: string;
  contactEmail: string;
  contactName?: string;
  summary: string;
  communicationStylePreference?: CommunicationStyle;
  relationshipNotes?: string;
  now?: () => string;
}): RelationshipRecord {
  const tenant = requireTenantContext({
    tenantId: input.tenantId,
    userId: input.userId,
    workspaceId: input.workspaceId,
  });
  const scope: TenantScope = {
    tenantId: tenant.tenantId,
    workspaceId: tenant.workspaceId,
  };
  const now = input.now ?? (() => new Date().toISOString());
  const at = now();

  const existing = getRelationship(scope, tenant.userId, input.contactEmail);
  const summaries = [
    ...(existing?.interactionSummaries ?? []),
    { at, summary: input.summary },
  ].slice(-MAX_SUMMARIES);

  return saveRelationship({
    tenantId: tenant.tenantId,
    workspaceId: tenant.workspaceId,
    userId: tenant.userId,
    contactEmail: input.contactEmail,
    contactName: input.contactName ?? existing?.contactName,
    communicationStylePreference:
      input.communicationStylePreference ?? existing?.communicationStylePreference,
    relationshipNotes: input.relationshipNotes ?? existing?.relationshipNotes,
    responsePattern: existing?.responsePattern,
    interactionSummaries: summaries,
    lastInteractionAt: at,
    updatedAt: at,
  });
}

/**
 * Retrieve advisory relationship context for a contact, scoped to
 * (tenant, workspace, user). Returns undefined when nothing is remembered —
 * the drafting path treats memory as optional.
 */
export function getRelationshipContext(
  scope: TenantScope,
  userId: string,
  contactEmail: string,
): RelationshipContext | undefined {
  const record = getRelationship(scope, userId, contactEmail);
  if (!record) return undefined;

  return RelationshipContextSchema.parse({
    contactName: record.contactName,
    communicationStylePreference: record.communicationStylePreference,
    relationshipNotes: record.relationshipNotes,
    recentInteractions: record.interactionSummaries
      .slice(-3)
      .map((s) => s.summary),
  });
}

/** Advisory directive appended to the drafting prompt — context, not authority. */
export function relationshipDirectives(context: RelationshipContext): string {
  const lines: string[] = [];
  if (context.contactName) {
    lines.push(`You are writing to ${context.contactName}.`);
  }
  if (context.relationshipNotes) {
    lines.push(`Relationship notes: ${context.relationshipNotes}`);
  }
  if (context.recentInteractions.length > 0) {
    lines.push(`Recent context: ${context.recentInteractions.join(" | ")}`);
  }
  return lines.join(" ");
}
