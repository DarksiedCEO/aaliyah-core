import fs from "node:fs";
import path from "node:path";

import { logger } from "./logger";
import { scopedJsonlPath, type TenantScope } from "../persistence/tenantScopedStore";

const TRACE_FILENAME = "aaliyah-traces.jsonl";

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

  const filePath = scopedJsonlPath(TRACE_FILENAME, scope);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(enriched)}\n`, "utf8");
}

/**
 * Read back persisted traces for a single (tenant, workspace). Used by audit
 * tooling and isolation tests — never returns another scope's traces.
 */
export function readPersistedTraces(scope: TenantScope): Record<string, unknown>[] {
  const filePath = scopedJsonlPath(TRACE_FILENAME, scope);

  if (!fs.existsSync(filePath)) {
    return [];
  }

  return fs
    .readFileSync(filePath, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
