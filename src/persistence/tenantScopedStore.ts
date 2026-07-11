import os from "node:os";
import path from "node:path";

/**
 * The isolation key for every tenant-scoped storage boundary. `userId` is
 * intentionally excluded — isolation is at the workspace level; users within a
 * workspace share its data.
 */
export type TenantScope = {
  tenantId: string;
  workspaceId: string;
};

export const LEGACY_BUCKET = "__legacy__";

/**
 * Bucket key for partitioning process-local (in-memory) stores by scope, so a
 * read for one workspace never surfaces another's rows within the same process.
 * Scope-free callers share the legacy bucket, preserving pre-migration behaviour.
 */
export function scopeBucketKey(scope?: TenantScope): string {
  return scope ? `${scope.tenantId}:${scope.workspaceId}` : LEGACY_BUCKET;
}

function assertSegment(value: string, label: string): void {
  if (!value || value.includes("/") || value.includes("..")) {
    throw new Error(`Invalid ${label} for tenant-scoped storage`);
  }
}

/**
 * Derive a per-(tenant, workspace) namespaced key. Used to scope flat key
 * spaces (e.g. idempotency keys) so two tenants can never collide and a read
 * for one scope can never surface another's record.
 *
 * When `scope` is undefined the raw key is returned unchanged — this preserves
 * legacy behaviour during the migration window for callers not yet threading a
 * scope.
 */
export function scopedKey(key: string, scope?: TenantScope): string {
  if (!scope) {
    return key;
  }

  assertSegment(scope.tenantId, "tenantId");
  assertSegment(scope.workspaceId, "workspaceId");
  return `${scope.tenantId}:${scope.workspaceId}:${key}`;
}

/**
 * Root directory for durable file-backed stores (dev / no-DATABASE_URL path).
 */
export function dataRoot(): string {
  return process.env.AALIYAH_DATA_DIR ?? path.join(os.homedir(), ".aaliyah");
}

/**
 * Namespace a JSONL filename under `<dataRoot>/<tenantId>/<workspaceId>/`.
 * Without a scope it falls back to the legacy flat path so existing readers
 * keep working until they are migrated.
 */
export function scopedJsonlPath(filename: string, scope?: TenantScope): string {
  if (!scope) {
    return path.join(dataRoot(), filename);
  }

  assertSegment(scope.tenantId, "tenantId");
  assertSegment(scope.workspaceId, "workspaceId");
  return path.join(dataRoot(), scope.tenantId, scope.workspaceId, filename);
}
