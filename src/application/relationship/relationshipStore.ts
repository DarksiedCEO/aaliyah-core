import fs from "node:fs";
import path from "node:path";

import {
  RelationshipRecordSchema,
  type RelationshipRecord,
} from "@aaliyah/contracts/v1";

import {
  scopedJsonlPath,
  scopeBucketKey,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

// Per-(scope, user) cache of contactEmail -> record. Durable copy is a JSON map
// file namespaced under the tenant/workspace data directory.
const cache = new Map<string, Map<string, RelationshipRecord>>();

function cacheKey(scope: TenantScope, userId: string): string {
  return `${scopeBucketKey(scope)}:${userId}`;
}

function filePath(scope: TenantScope, userId: string): string {
  return scopedJsonlPath(`relationships-${userId}.json`, scope);
}

function load(scope: TenantScope, userId: string): Map<string, RelationshipRecord> {
  const ck = cacheKey(scope, userId);
  const cached = cache.get(ck);
  if (cached) return cached;

  const map = new Map<string, RelationshipRecord>();
  const fp = filePath(scope, userId);
  if (fs.existsSync(fp)) {
    const raw = JSON.parse(fs.readFileSync(fp, "utf8")) as Record<string, unknown>;
    for (const [email, rec] of Object.entries(raw)) {
      map.set(email, RelationshipRecordSchema.parse(rec));
    }
  }
  cache.set(ck, map);
  return map;
}

function persist(scope: TenantScope, userId: string, map: Map<string, RelationshipRecord>): void {
  const fp = filePath(scope, userId);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify(Object.fromEntries(map)), "utf8");
}

export function saveRelationship(record: RelationshipRecord): RelationshipRecord {
  const parsed = RelationshipRecordSchema.parse(record);
  const scope: TenantScope = { tenantId: parsed.tenantId, workspaceId: parsed.workspaceId };
  const map = load(scope, parsed.userId);
  map.set(parsed.contactEmail, parsed);
  persist(scope, parsed.userId, map);
  return parsed;
}

export function getRelationship(
  scope: TenantScope,
  userId: string,
  contactEmail: string,
): RelationshipRecord | undefined {
  return load(scope, userId).get(contactEmail);
}

export function clearRelationshipCache(): void {
  cache.clear();
}
