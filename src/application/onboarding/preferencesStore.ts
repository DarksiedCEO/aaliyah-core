import {
  WorkspacePreferencesSchema,
  type WorkspacePreferences,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";

const PREFERENCES_STORE = "onboarding_preferences";

export async function savePreferences(prefs: WorkspacePreferences): Promise<WorkspacePreferences> {
  const parsed = WorkspacePreferencesSchema.parse(prefs);
  const scope = { tenantId: parsed.tenantId, workspaceId: parsed.workspaceId };
  await applicationStoreFromEnv().documents.put(PREFERENCES_STORE, scope, parsed.userId, parsed);
  return parsed;
}

export async function loadPreferences(
  scope: TenantScope,
  userId: string,
): Promise<WorkspacePreferences | undefined> {
  const raw = await applicationStoreFromEnv().documents.get(PREFERENCES_STORE, scope, userId);
  return raw ? WorkspacePreferencesSchema.parse(raw) : undefined;
}

export async function clearPreferencesCache(): Promise<void> {
  await applicationStoreFromEnv().documents.reset(PREFERENCES_STORE);
}
