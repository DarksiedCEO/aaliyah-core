import assert from "node:assert/strict";
import crypto from "node:crypto";
import test, { afterEach, mock } from "node:test";

import {
  ensureIdempotentExecution,
  idempotencyStoreInternals,
  parseVerifiedExecutionRecord,
  recordIdempotentFailure,
  recordIdempotentResult,
  recordVerifiedExecutionResult,
} from "../src/persistence/idempotencyStore";
import * as idempotencyStoreExports from "../src/persistence/idempotencyStore";
import { runAaliyahTask } from "../src/application/decision-engine/runAaliyahTask";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

afterEach(() => {
  idempotencyStoreInternals.resetInMemory();
});

test("idempotency v2 replays stored generic result for the same request", async () => {
  const first = await ensureIdempotentExecution<{ cached: boolean }>(
    "idem-1",
    { action: "send" },
    "write",
  );

  assert.equal(first.replay, false);

  await recordIdempotentResult("idem-1", { cached: true });

  const replay = await ensureIdempotentExecution<{ cached: boolean }>(
    "idem-1",
    { action: "send" },
    "write",
  );

  assert.equal(replay.replay, true);
  assert.deepEqual(replay.result, { cached: true });
});

test("generic completion cannot masquerade as verified execution", async () => {
  await ensureIdempotentExecution("idem-exec", { action: "execute" }, "write");

  await assert.rejects(
    () => recordIdempotentResult("idem-exec", { success: true }),
    /successful_execution_requires_verified_completion/,
  );

  const validReceipt = {
    contractVersion: "aaliyah.postcondition-verification/v1" as const,
    verified: true as const,
    tenantId: "tenant_123",
    workspaceId: "tenant_123:default",
    taskId: "550e8400-e29b-41d4-a716-446655440030",
    idempotencyKey: "idem-exec",
    executionReceiptId: "provider-execution-30",
    executorId: "provider-executor-v1",
    externalRefs: ["provider:1"],
    verifierId: "readback",
    verificationMethod: "independent_readback" as const,
    verifiedAt: new Date().toISOString(),
  };
  const result = {
    success: true,
    tenantId: validReceipt.tenantId,
    workspaceId: validReceipt.workspaceId,
    taskId: validReceipt.taskId,
    idempotencyKey: validReceipt.idempotencyKey,
    executionReceiptId: validReceipt.executionReceiptId,
    executorId: validReceipt.executorId,
    verificationReceipt: validReceipt,
    approvalState: "not_required" as const,
    externalRefs: ["provider:1"],
    postconditionsMet: true,
    escalated: false,
    message: "verified",
  };
  await assert.rejects(
    () => recordVerifiedExecutionResult("idem-exec", result, {
      ...validReceipt,
      verified: false,
    } as never, { nowMs: Date.now() }),
    /Invalid input/,
  );
});

test("raw completion writer is not exported", () => {
  assert.equal("markCompleted" in idempotencyStoreExports, false);
});

test("persistence independently rejects invalid verification receipts", async () => {
  const validReceipt = {
    contractVersion: "aaliyah.postcondition-verification/v1" as const,
    verified: true as const,
    tenantId: "tenant_123",
    workspaceId: "tenant_123:default",
    taskId: "550e8400-e29b-41d4-a716-446655440031",
    idempotencyKey: "550e8400-e29b-41d4-a716-446655440031",
    executionReceiptId: "provider-execution-31",
    executorId: "provider-executor-v1",
    externalRefs: ["provider:1", "provider:2"],
    verifierId: "provider-readback-v1",
    verificationMethod: "independent_readback" as const,
    verifiedAt: new Date().toISOString(),
  };
  const result = {
    success: true,
    tenantId: validReceipt.tenantId,
    workspaceId: validReceipt.workspaceId,
    taskId: validReceipt.taskId,
    idempotencyKey: validReceipt.idempotencyKey,
    executionReceiptId: validReceipt.executionReceiptId,
    executorId: validReceipt.executorId,
    verificationReceipt: validReceipt,
    approvalState: "not_required" as const,
    externalRefs: ["provider:1", "provider:2"],
    postconditionsMet: true,
    escalated: false,
    message: "verified",
  };
  const invalidReceipts = [
    { ...validReceipt, verifiedAt: "2020-01-01T00:00:00.000Z" },
    { ...validReceipt, externalRefs: ["provider:1"] },
    { ...validReceipt, externalRefs: ["provider:1", "provider:1"] },
    { ...validReceipt, verifierId: "" },
    { ...validReceipt, executionReceiptId: "provider-execution-other" },
    {
      ...validReceipt,
      taskId: "550e8400-e29b-41d4-a716-446655440999",
    },
  ];
  for (const receipt of invalidReceipts) {
    await assert.rejects(() =>
      recordVerifiedExecutionResult(
        result.idempotencyKey,
        result,
        receipt as never,
        { nowMs: Date.now() },
      ),
    );
  }
});

test("verified execution persists a stable envelope and run replay unwraps result", async () => {
  const task = {
    taskId: "550e8400-e29b-41d4-a716-446655440032",
    tenantId: "tenant_123",
    userId: "user_123",
    taskType: "decision" as const,
    riskTier: "A1_DRAFT" as const,
    requestedOutcome: "Replay verified execution",
    inputs: {},
    constraints: [],
    requiredSources: [],
    createdAt: "2026-04-18T12:00:00.000Z",
  };
  const scope = {
    tenantId: task.tenantId,
    workspaceId: `${task.tenantId}:default`,
  };
  await ensureIdempotentExecution(task.taskId, task, task.taskType, scope);

  const receipt = {
    contractVersion: "aaliyah.postcondition-verification/v1" as const,
    verified: true as const,
    tenantId: task.tenantId,
    workspaceId: scope.workspaceId,
    taskId: task.taskId,
    idempotencyKey: task.taskId,
    executionReceiptId: "provider-execution-32",
    executorId: "provider-executor-v1",
    externalRefs: ["provider:verified-32"],
    verifierId: "provider-readback-v1",
    verificationMethod: "independent_readback" as const,
    verifiedAt: new Date().toISOString(),
  };
  const result = {
    success: true,
    tenantId: task.tenantId,
    workspaceId: scope.workspaceId,
    taskId: task.taskId,
    idempotencyKey: task.taskId,
    executionReceiptId: receipt.executionReceiptId,
    executorId: receipt.executorId,
    verificationReceipt: receipt,
    approvalState: "not_required" as const,
    externalRefs: ["provider:verified-32"],
    postconditionsMet: true,
    escalated: false,
    message: "verified execution",
  };
  await recordVerifiedExecutionResult(
    task.taskId,
    result,
    receipt,
    { nowMs: Date.now() },
    scope,
  );

  const stored = await ensureIdempotentExecution<{
    kind: string;
    version: number;
    result: typeof result;
  }>(task.taskId, task, task.taskType, scope);
  assert.equal(stored.replay, true);
  assert.equal(stored.result?.kind, "verified_execution");
  assert.equal(stored.result?.version, 1);

  assert.deepEqual(await runAaliyahTask(task), result);
});

test("historical verified envelope is rejected after freshness window", async () => {
  const task = {
    taskId: "550e8400-e29b-41d4-a716-446655440033",
    tenantId: "tenant_123",
    userId: "user_123",
    taskType: "decision" as const,
    riskTier: "A1_DRAFT" as const,
    requestedOutcome: "Replay historical verified execution",
    inputs: {},
    constraints: [],
    requiredSources: [],
    createdAt: "2026-04-18T12:00:00.000Z",
  };
  const scope = {
    tenantId: task.tenantId,
    workspaceId: `${task.tenantId}:default`,
  };
  const verifiedAt = "2026-04-18T12:01:00.000Z";
  const receipt = {
    contractVersion: "aaliyah.postcondition-verification/v1" as const,
    verified: true as const,
    tenantId: task.tenantId,
    workspaceId: scope.workspaceId,
    taskId: task.taskId,
    idempotencyKey: task.taskId,
    executionReceiptId: "provider-execution-33",
    executorId: "provider-executor-v1",
    externalRefs: ["provider:verified-33"],
    verifierId: "provider-readback-v1",
    verificationMethod: "independent_readback" as const,
    verifiedAt,
  };
  const result = {
    success: true,
    tenantId: task.tenantId,
    workspaceId: scope.workspaceId,
    taskId: task.taskId,
    idempotencyKey: task.taskId,
    executionReceiptId: receipt.executionReceiptId,
    executorId: receipt.executorId,
    verificationReceipt: receipt,
    approvalState: "not_required" as const,
    externalRefs: ["provider:verified-33"],
    postconditionsMet: true,
    escalated: false,
    message: "historically verified execution",
  };

  await ensureIdempotentExecution(task.taskId, task, task.taskType, scope);
  const nowMock = mock.method(Date, "now", () => Date.parse(verifiedAt));
  await recordVerifiedExecutionResult(
    task.taskId,
    result,
    receipt,
    { nowMs: Date.parse(verifiedAt) },
    scope,
  );
  nowMock.mock.restore();

  await assert.rejects(
    () => runAaliyahTask(task),
    /verified_execution_record_invalid/,
  );
});

test("durable replay still rejects structurally invalid verification envelopes", () => {
  const receipt = {
    contractVersion: "aaliyah.postcondition-verification/v1" as const,
    verified: true as const,
    tenantId: "tenant_123",
    workspaceId: "tenant_123:default",
    taskId: "550e8400-e29b-41d4-a716-446655440034",
    idempotencyKey: "550e8400-e29b-41d4-a716-446655440034",
    executionReceiptId: "provider-execution-34",
    executorId: "provider-executor-v1",
    externalRefs: ["provider:1", "provider:2"],
    verifierId: "provider-readback-v1",
    verificationMethod: "independent_readback" as const,
    verifiedAt: "2026-04-18T12:01:00.000Z",
  };
  const result = {
    success: true,
    tenantId: receipt.tenantId,
    workspaceId: receipt.workspaceId,
    taskId: receipt.taskId,
    idempotencyKey: receipt.idempotencyKey,
    executionReceiptId: receipt.executionReceiptId,
    executorId: receipt.executorId,
    verificationReceipt: receipt,
    approvalState: "not_required" as const,
    externalRefs: ["provider:1", "provider:2"],
    postconditionsMet: true,
    escalated: false,
    message: "verified execution",
  };
  const envelope = {
    kind: "verified_execution" as const,
    version: 1 as const,
    result,
    receipt,
  };

  const invalidEnvelopes = [
    { ...envelope, kind: "generic_completion" },
    { ...envelope, receipt: { ...receipt, verified: false } },
    { ...envelope, receipt: { ...receipt, externalRefs: ["provider:1"] } },
    {
      ...envelope,
      receipt: {
        ...receipt,
        externalRefs: ["provider:1", "provider:1"],
      },
    },
    { ...envelope, receipt: { ...receipt, verifierId: "" } },
    { ...envelope, receipt: { ...receipt, taskId: crypto.randomUUID() } },
    { ...envelope, receipt: { ...receipt, verifiedAt: "not-a-timestamp" } },
  ];

  for (const invalid of invalidEnvelopes) {
    assert.throws(() =>
      parseVerifiedExecutionRecord(invalid, {
        nowMs: Date.parse(receipt.verifiedAt),
      }),
    );
  }
});

test("idempotency v2 rejects reused keys with different payloads", async () => {
  await ensureIdempotentExecution("idem-2", { action: "send" }, "write");

  await assert.rejects(
    () => ensureIdempotentExecution("idem-2", { action: "delete" }, "write"),
    /Idempotency key reuse with different payload/,
  );
});

test("idempotency v3 allows retry after recorded failure", async () => {
  await ensureIdempotentExecution("idem-3", { action: "send" }, "write");
  await recordIdempotentFailure("idem-3", "connector timeout");

  const retry = await ensureIdempotentExecution("idem-3", { action: "send" }, "write");

  assert.equal(retry.replay, false);
});
