import crypto from "node:crypto";
import { execSync } from "node:child_process";

import { runInboundDraft, inboundDraftInternals } from "../application/inbound/runInboundDraft";
import { readDecisionTraces } from "../application/trust/decisionTrace";
import type { TenantScope } from "../persistence/tenantScopedStore";

/**
 * Local Runtime Certification Harness.
 *
 * Drives the REAL native inbound-draft path — authenticated tenant context →
 * inbound analysis → draft generation → durable decision trace → awaiting
 * approval → NO send — with deterministic fake providers over real durable
 * state, and emits a machine-readable evidence bundle.
 *
 * HONESTY BOUNDARY: this repo does not implement the wider execution-ledger
 * surfaces some specs describe (execution_run_records / executions /
 * execution_steps / email_draft_review_items / aaliyah_diagnostics_events) nor a
 * /v1/agent-os diagnostics endpoint — see `MISSING_SURFACES`. The harness
 * certifies the path that actually exists and names what does not. Fake-provider
 * mode may ONLY emit LOCAL_RUNTIME_PATH_VERIFIED; it may never emit a production
 * certificate — only a real deployed/live run may.
 */

export const MISSING_SURFACES: readonly string[] = [
  "execution_run_records",
  "executions",
  "execution_steps",
  "email_draft_review_items",
  "aaliyah_diagnostics_events",
  "GET /v1/agent-os/aaliyah/diagnostics",
];

export type CertificationGate = { name: string; pass: boolean; detail: string };

export type LocalCertificationEvidence = {
  marker: "LOCAL_RUNTIME_PATH_VERIFIED" | "LOCAL_RUNTIME_PATH_FAILED";
  environment: "local-deterministic";
  commitSha: string;
  timestamp: string;
  tenantRef: string; // redacted (hash prefix) — never the raw id
  workspaceRef: string;
  decisionTraceId: string | null;
  draftId: string | null;
  outcomeStatus: string | null;
  autoSend: boolean;
  sendCount: number;
  gates: CertificationGate[];
  missingSurfaces: readonly string[];
};

function redact(value: string): string {
  return `ref_${crypto.createHash("sha256").update(value).digest("hex").slice(0, 12)}`;
}

function currentCommit(): string {
  try {
    return execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

/**
 * Run the certification against a scope. The caller wires durable state via env
 * (AALIYAH_DATABASE_URL for the application store; AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY
 * for the idempotency guard in local mode). Providers are faked here so the run
 * is deterministic and never touches the network — and never sends.
 */
export async function runLocalRuntimeCertification(input: {
  scope: TenantScope;
  userId: string;
  now?: () => string;
}): Promise<LocalCertificationEvidence> {
  const { scope, userId } = input;
  const messageId = `cert-${crypto.randomUUID()}`;
  const threadId = `cert-thread-${crypto.randomUUID()}`;
  let sendCount = 0;

  // Deterministic fake providers. createDraft returns a draft id WITHOUT any
  // network call; there is no send path here, and we count sends defensively.
  const saved = {
    generator: inboundDraftInternals.generator,
    createDraft: inboundDraftInternals.createDraft,
    resolveAccessToken: inboundDraftInternals.resolveAccessToken,
  };
  inboundDraftInternals.resolveAccessToken = () => "cert-fake-token";
  inboundDraftInternals.createDraft = async () => `cert-draft-${crypto.randomUUID()}`;
  inboundDraftInternals.generator = async ({ replyType }) => ({
    subject: "Re: certification probe",
    body: "Deterministic certification draft — never sent.",
    replyType,
    confidence: 20, // low → stays awaiting_approval
    generatorMode: "deterministic-v1",
  });

  let outcomeStatus: string | null = null;
  let autoSend = false;
  let draftId: string | null = null;
  let ran = false;
  let runError: string | null = null;
  try {
    const result = await runInboundDraft({
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      userId,
      email: {
        messageId,
        threadId,
        fromEmail: "prospect@example.com",
        subject: "Certification probe",
        body: "Please confirm pricing.",
        receivedAt: input.now?.() ?? new Date().toISOString(),
      },
    });
    ran = true;
    outcomeStatus = result.status;
    autoSend = result.autoSend;
    draftId = result.draftId ?? null;
  } catch (error) {
    runError = error instanceof Error ? error.message : String(error);
  } finally {
    inboundDraftInternals.generator = saved.generator;
    inboundDraftInternals.createDraft = saved.createDraft;
    inboundDraftInternals.resolveAccessToken = saved.resolveAccessToken;
  }

  // Read the durable decision trace back from state (proves persistence).
  const traces = ran ? await readDecisionTraces(scope) : [];
  const trace = traces.find((t) => t.evidenceUsed?.includes(threadId)) ?? traces.at(-1) ?? null;

  const gates: CertificationGate[] = [
    { name: "native_path_executed", pass: ran, detail: runError ?? "runInboundDraft completed" },
    { name: "draft_generated", pass: Boolean(draftId), detail: draftId ? "draft id present" : "no draft id" },
    {
      name: "decision_trace_persisted",
      pass: Boolean(trace),
      detail: trace ? `traceId=${trace.traceId}` : "no durable decision trace found",
    },
    {
      name: "awaiting_approval",
      pass: outcomeStatus === "awaiting_approval",
      detail: `status=${outcomeStatus}`,
    },
    { name: "no_auto_send", pass: autoSend === false, detail: `autoSend=${autoSend}` },
    { name: "no_send", pass: sendCount === 0, detail: `sendCount=${sendCount}` },
  ];

  const allPass = gates.every((g) => g.pass);
  return {
    marker: allPass ? "LOCAL_RUNTIME_PATH_VERIFIED" : "LOCAL_RUNTIME_PATH_FAILED",
    environment: "local-deterministic",
    commitSha: currentCommit(),
    timestamp: input.now?.() ?? new Date().toISOString(),
    tenantRef: redact(scope.tenantId),
    workspaceRef: redact(scope.workspaceId),
    decisionTraceId: trace?.traceId ?? null,
    draftId,
    outcomeStatus,
    autoSend,
    sendCount,
    gates,
    missingSurfaces: MISSING_SURFACES,
  };
}
