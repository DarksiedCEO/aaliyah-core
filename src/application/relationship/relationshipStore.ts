import {
  RelationshipRecordSchema,
  type RelationshipRecord,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";

// Durable copy is a single per-user document holding contactEmail -> record,
// preserving the previous one-file-per-user map semantics.
const RELATIONSHIP_STORE = "relationships";

async function load(
  scope: TenantScope,
  userId: string,
): Promise<Map<string, RelationshipRecord>> {
  const map = new Map<string, RelationshipRecord>();
  const raw = await applicationStoreFromEnv().documents.get(RELATIONSHIP_STORE, scope, userId);
  if (raw && typeof raw === "object") {
    for (const [email, rec] of Object.entries(raw as Record<string, unknown>)) {
      map.set(email, RelationshipRecordSchema.parse(rec));
    }
  }
  return map;
}

export async function saveRelationship(record: RelationshipRecord): Promise<RelationshipRecord> {
  const parsed = RelationshipRecordSchema.parse(record);
  const scope: TenantScope = { tenantId: parsed.tenantId, workspaceId: parsed.workspaceId };
  const map = await load(scope, parsed.userId);
  map.set(parsed.contactEmail, parsed);
  await applicationStoreFromEnv().documents.put(
    RELATIONSHIP_STORE, scope, parsed.userId, Object.fromEntries(map),
  );
  return parsed;
}

export async function getRelationship(
  scope: TenantScope,
  userId: string,
  contactEmail: string,
): Promise<RelationshipRecord | undefined> {
  return (await load(scope, userId)).get(contactEmail);
}

export async function clearRelationshipCache(): Promise<void> {
  await applicationStoreFromEnv().documents.reset(RELATIONSHIP_STORE);
}
