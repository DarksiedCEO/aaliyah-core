import fs from "node:fs";
import path from "node:path";

import {
  WorkspacePreferencesSchema,
  type WorkspacePreferences,
} from "@aaliyah/contracts/v1";

import {
  scopedJsonlPath,
  scopeBucketKey,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

// Process-local cache keyed by (tenant, workspace, user). Durable copy is a
// per-user JSON file under the tenant/workspace-namespaced data directory.
const cache = new Map<string, WorkspacePreferences>();

function key(scope: TenantScope, userId: string): string {
  return `${scopeBucketKey(scope)}:${userId}`;
}

function filePath(scope: TenantScope, userId: string): string {
  return scopedJsonlPath(`onboarding-preferences-${userId}.json`, scope);
}

export function savePreferences(prefs: WorkspacePreferences): WorkspacePreferences {
  const parsed = WorkspacePreferencesSchema.parse(prefs);
  const scope = { tenantId: parsed.tenantId, workspaceId: parsed.workspaceId };
  cache.set(key(scope, parsed.userId), parsed);

  const fp = filePath(scope, parsed.userId);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify(parsed), "utf8");
  return parsed;
}

export function loadPreferences(
  scope: TenantScope,
  userId: string,
): WorkspacePreferences | undefined {
  const cached = cache.get(key(scope, userId));
  if (cached) {
    return cached;
  }

  const fp = filePath(scope, userId);
  if (!fs.existsSync(fp)) {
    return undefined;
  }

  const parsed = WorkspacePreferencesSchema.parse(
    JSON.parse(fs.readFileSync(fp, "utf8")),
  );
  cache.set(key(scope, userId), parsed);
  return parsed;
}

export function clearPreferencesCache(): void {
  cache.clear();
}
