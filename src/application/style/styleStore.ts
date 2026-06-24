import fs from "node:fs";
import path from "node:path";

import { StyleProfileSchema, type StyleProfile } from "@aaliyah/contracts/v1";

import {
  scopedJsonlPath,
  scopeBucketKey,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

const cache = new Map<string, StyleProfile>();

function key(scope: TenantScope, userId: string): string {
  return `${scopeBucketKey(scope)}:${userId}`;
}

function filePath(scope: TenantScope, userId: string): string {
  return scopedJsonlPath(`style-profile-${userId}.json`, scope);
}

export function saveStyleProfile(profile: StyleProfile): StyleProfile {
  const parsed = StyleProfileSchema.parse(profile);
  const scope = { tenantId: parsed.tenantId, workspaceId: parsed.workspaceId };
  cache.set(key(scope, parsed.userId), parsed);

  const fp = filePath(scope, parsed.userId);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify(parsed), "utf8");
  return parsed;
}

export function loadStyleProfile(
  scope: TenantScope,
  userId: string,
): StyleProfile | undefined {
  const cached = cache.get(key(scope, userId));
  if (cached) {
    return cached;
  }

  const fp = filePath(scope, userId);
  if (!fs.existsSync(fp)) {
    return undefined;
  }

  const parsed = StyleProfileSchema.parse(JSON.parse(fs.readFileSync(fp, "utf8")));
  cache.set(key(scope, userId), parsed);
  return parsed;
}

export function clearStyleCache(): void {
  cache.clear();
}
