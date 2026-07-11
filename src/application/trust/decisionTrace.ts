import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  DecisionTraceSchema,
  DOCTRINE_VERSION,
  type DecisionTrace,
} from "@aaliyah/contracts/v1";

import {
  scopedJsonlPath,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

const TRACE_FILE = "decision-traces.jsonl";

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
export function recordDecisionTrace(input: DecisionTraceInput): DecisionTrace {
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
  const fp = scopedJsonlPath(TRACE_FILE, scope);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.appendFileSync(fp, `${JSON.stringify(trace)}\n`, "utf8");
  return trace;
}

export function readDecisionTraces(scope: TenantScope): DecisionTrace[] {
  const fp = scopedJsonlPath(TRACE_FILE, scope);
  if (!fs.existsSync(fp)) return [];
  return fs
    .readFileSync(fp, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => DecisionTraceSchema.parse(JSON.parse(l)));
}
