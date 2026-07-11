import type { TenantContext } from "@aaliyah/contracts/v1";
import { resolveTenantContext } from "@aaliyah/contracts/v1";

/**
 * Execution-boundary guard. Every tenant-scoped operation must derive its
 * isolation key from a concrete TenantContext. During the migration window an
 * absent `workspaceId` is backfilled to the tenant's default workspace rather
 * than rejected, so phase-1 envelopes keep flowing while still landing in a
 * concrete, isolated workspace.
 *
 * This guard does NOT touch decision logic — it only ensures a usable
 * isolation key exists before any storage boundary is reached.
 */
export function requireTenantContext(input: {
  tenantId?: string | undefined;
  userId?: string | undefined;
  workspaceId?: string | undefined;
}): TenantContext {
  if (!input.tenantId || !input.userId) {
    throw new Error("Missing tenant context: tenantId and userId are required");
  }

  return resolveTenantContext({
    tenantId: input.tenantId,
    userId: input.userId,
    workspaceId: input.workspaceId,
  });
}
