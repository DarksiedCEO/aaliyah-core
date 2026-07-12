import crypto from "node:crypto";

import {
  DecisionTraceSchema,
  DOCTRINE_VERSION,
  type DecisionTrace,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";

const TRACE_STORE = "decision_traces";

export type DecisionTraceInput = {
  tenantId: string;
  workspaceId: string;
  userId: string;
  inputSummary?: string;
  decision: string;
  evidenceUsed?: string[];
  reason: string;
  provider?: string;
  now?: () => string;
};

/**
 * Record a tenant/workspace-scoped decision trace. Audit only — never alters a
 * decision. Doctrine version is stamped automatically.
 */
export async function recordDecisionTrace(input: DecisionTraceInput): Promise<DecisionTrace> {
  const now = input.now ?? (() => new Date().toISOString());
  const trace = DecisionTraceSchema.parse({
    traceId: crypto.randomUUID(),
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    timestamp: now(),
    inputSummary: input.inputSummary ?? "",
    decision: input.decision,
    evidenceUsed: input.evidenceUsed ?? [],
    reason: input.reason,
    doctrineVersion: DOCTRINE_VERSION,
    ...(input.provider ? { provider: input.provider } : {}),
  });

  const scope: TenantScope = {
    tenantId: trace.tenantId,
    workspaceId: trace.workspaceId,
  };
  await applicationStoreFromEnv().logs.append(TRACE_STORE, scope, trace);
  return trace;
}

export async function readDecisionTraces(scope: TenantScope): Promise<DecisionTrace[]> {
  const rows = await applicationStoreFromEnv().logs.list(TRACE_STORE, scope);
  return rows.map((r) => DecisionTraceSchema.parse(r));
}
