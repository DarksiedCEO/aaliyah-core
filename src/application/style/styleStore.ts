import { StyleProfileSchema, type StyleProfile } from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";

const STYLE_STORE = "style_profiles";

export async function saveStyleProfile(profile: StyleProfile): Promise<StyleProfile> {
  const parsed = StyleProfileSchema.parse(profile);
  const scope = { tenantId: parsed.tenantId, workspaceId: parsed.workspaceId };
  await applicationStoreFromEnv().documents.put(STYLE_STORE, scope, parsed.userId, parsed);
  return parsed;
}

export async function loadStyleProfile(
  scope: TenantScope,
  userId: string,
): Promise<StyleProfile | undefined> {
  const raw = await applicationStoreFromEnv().documents.get(STYLE_STORE, scope, userId);
  return raw ? StyleProfileSchema.parse(raw) : undefined;
}

export async function clearStyleCache(): Promise<void> {
  await applicationStoreFromEnv().documents.reset(STYLE_STORE);
}
