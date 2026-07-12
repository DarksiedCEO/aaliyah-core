import {
  StyleProfileSchema,
  type CommunicationStyle,
  type StyleProfile,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import {
  SAFE_DEFAULT_STYLE,
  defaultStyleFields,
} from "./defaultStyleProfiles";
import { loadStyleProfile } from "./styleStore";

/**
 * Resolve the style profile for a (tenant, workspace, user). Resolution order:
 *   1. A stored profile, if present.
 *   2. A profile built from built-in defaults for the requested `styleId`.
 *   3. Deterministic fallback to the safe `professional` defaults.
 *
 * Always returns a valid profile — the drafting path never fails for a missing
 * or partial style configuration.
 */
export async function resolveStyleProfile(
  scope: TenantScope,
  userId: string,
  styleId?: CommunicationStyle,
): Promise<StyleProfile> {
  const stored = await loadStyleProfile(scope, userId);
  if (stored) {
    return stored;
  }

  // `custom` has no usable defaults without stored notes — fall back to safe.
  const effectiveId: CommunicationStyle =
    styleId && styleId !== "custom" ? styleId : SAFE_DEFAULT_STYLE;

  return StyleProfileSchema.parse({
    tenantId: scope.tenantId,
    workspaceId: scope.workspaceId,
    userId,
    styleId: effectiveId,
    ...defaultStyleFields(effectiveId),
  });
}
