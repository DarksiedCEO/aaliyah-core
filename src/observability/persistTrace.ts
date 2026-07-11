import { logger } from "./logger";
import type { TenantScope } from "../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../persistence/applicationState";

const TRACE_STORE = "observability_traces";

function scopeFromTrace(trace: Record<string, unknown>): TenantScope | undefined {
  const tenantId = trace.tenantId;
  const workspaceId = trace.workspaceId;

  if (typeof tenantId === "string" && typeof workspaceId === "string") {
    return { tenantId, workspaceId };
  }

  return undefined;
}

export async function persistTrace(trace: Record<string, unknown>): Promise<void> {
  const enriched = {
    timestamp: new Date().toISOString(),
    auditVersion: "v2",
    ...trace,
  };

  logger.info(enriched, "aaliyah.trace");

  // Durable, tenant-isolated trace storage. Traces carrying a concrete
  // (tenantId, workspaceId) are namespaced per workspace so a forensic read for
  // one tenant can never surface another's decision traces. Traces without a
  // resolvable scope are not written to the shared boundary (fail-closed) —
  // they remain in the structured log only.
  const scope = scopeFromTrace(enriched);
  if (!scope) {
    return;
  }

  await applicationStoreFromEnv().logs.append(TRACE_STORE, scope, enriched);
}

/**
 * Read back persisted traces for a single (tenant, workspace). Used by audit
 * tooling and isolation tests — never returns another scope's traces.
 */
export async function readPersistedTraces(scope: TenantScope): Promise<Record<string, unknown>[]> {
  const rows = await applicationStoreFromEnv().logs.list(TRACE_STORE, scope);
  return rows as Record<string, unknown>[];
}
