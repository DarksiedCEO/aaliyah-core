import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { afterEach, before } from "node:test";

import {
  ensureIdempotentExecution,
  idempotencyStoreInternals,
  recordIdempotentResult,
} from "../src/persistence/idempotencyStore";
import { scopedKey, scopedJsonlPath } from "../src/persistence/tenantScopedStore";
import { enforceTenantBoundary } from "../src/governance/enforceTenantBoundary";
import { requireTenantContext } from "../src/governance/requireTenantContext";
import {
  registerCredential,
  getCredential,
  clearCredentials,
} from "../src/governance/credentialProvider";
import { persistTrace, readPersistedTraces } from "../src/observability/persistTrace";
import {
  recordApprovalReview,
  listApprovalReviews,
  clearApprovalReviews,
} from "../src/services/followup/recordApprovalReview";
import {
  recordReplyOutcome,
  listReplyOutcomes,
  clearReplyOutcomes,
} from "../src/services/followup/recordReplyOutcome";
import {
  trackFollowupOutcome,
  getTrackedFollowupOutcome,
  listTrackedFollowupOutcomes,
  clearTrackedFollowupOutcomes,
} from "../src/services/followup/trackFollowupOutcome";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

const TENANT_A = { tenantId: "tenant_a", workspaceId: "ws_a" };
const TENANT_B = { tenantId: "tenant_b", workspaceId: "ws_b" };

let dataDir: string;

before(() => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "aaliyah-isolation-"));
  process.env.AALIYAH_DATA_DIR = dataDir;
});

afterEach(() => {
  idempotencyStoreInternals.resetInMemory();
  clearCredentials();
});

test("idempotency: same key under two scopes stays isolated (no cross-tenant replay)", async () => {
  const first = await ensureIdempotentExecution<{ owner: string }>(
    "shared-key",
    { action: "send" },
    "write",
    TENANT_A,
  );
  assert.equal(first.replay, false);
  await recordIdempotentResult("shared-key", { owner: "tenant_a" }, TENANT_A);

  // Same idempotency key, different tenant/workspace -> must NOT replay A's result.
  const crossTenant = await ensureIdempotentExecution<{ owner: string }>(
    "shared-key",
    { action: "send" },
    "write",
    TENANT_B,
  );
  assert.equal(crossTenant.replay, false);
  assert.equal(crossTenant.result, undefined);

  // A still replays its own result independently.
  const replayA = await ensureIdempotentExecution<{ owner: string }>(
    "shared-key",
    { action: "send" },
    "write",
    TENANT_A,
  );
  assert.equal(replayA.replay, true);
  assert.deepEqual(replayA.result, { owner: "tenant_a" });
});

test("enforceTenantBoundary rejects foreign tenant and foreign workspace", () => {
  const rows = [
    { tenantId: "tenant_a", workspaceId: "ws_a", value: 1 },
    { tenantId: "tenant_a", workspaceId: "ws_a", value: 2 },
  ];

  // Matching scope passes through untouched.
  assert.deepEqual(enforceTenantBoundary("tenant_a", rows, "ws_a"), rows);

  // Foreign tenant throws.
  assert.throws(
    () => enforceTenantBoundary("tenant_b", rows, "ws_a"),
    /Tenant boundary violation/,
  );

  // Same tenant, foreign workspace throws.
  assert.throws(
    () => enforceTenantBoundary("tenant_a", rows, "ws_other"),
    /Tenant boundary violation/,
  );
});

test("credentials isolate by workspace and fail closed across boundaries", () => {
  registerCredential({
    tenantId: "tenant_a",
    workspaceId: "ws_a",
    userId: "user_1",
    provider: "google",
    accessToken: "token_a",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  // Correct scope resolves.
  assert.equal(
    getCredential("tenant_a", "user_1", "google", "ws_a").accessToken,
    "token_a",
  );

  // Foreign workspace cannot read it (fails closed).
  assert.throws(
    () => getCredential("tenant_a", "user_1", "google", "ws_other"),
    /Missing credential/,
  );

  // Legacy tenant:user scope (no workspace) is a different key and also closed.
  assert.throws(
    () => getCredential("tenant_a", "user_1", "google"),
    /Missing credential/,
  );
});

test("requireTenantContext backfills workspace and rejects missing identity", () => {
  const resolved = requireTenantContext({ tenantId: "tenant_a", userId: "user_1" });
  assert.equal(resolved.workspaceId, "tenant_a:default");

  assert.throws(
    () => requireTenantContext({ userId: "user_1" }),
    /Missing tenant context/,
  );
});

test("traces persist per workspace and reads never cross scopes", async () => {
  await persistTrace({ ...TENANT_A, taskId: "task_a", decisionPath: "a" });
  await persistTrace({ ...TENANT_B, taskId: "task_b", decisionPath: "b" });

  const aTraces = await readPersistedTraces(TENANT_A);
  const bTraces = await readPersistedTraces(TENANT_B);

  assert.equal(aTraces.length, 1);
  assert.equal(aTraces[0]!.taskId, "task_a");
  assert.equal(bTraces.length, 1);
  assert.equal(bTraces[0]!.taskId, "task_b");
});

test("approval reviews never leak across tenants (the live JSONL gap)", async () => {
  await clearApprovalReviews(TENANT_A);
  await clearApprovalReviews(TENANT_B);

  const base = {
    threadId: "thread_1",
    approved: true,
    edited: false,
    editDistance: 0,
    reviewerId: "reviewer_1",
    reviewedAt: "2026-06-23T12:00:00.000Z",
    draftConfidence: 80,
  };

  await recordApprovalReview({ ...base, taskId: "task_a" }, TENANT_A);
  await recordApprovalReview({ ...base, taskId: "task_b1" }, TENANT_B);
  await recordApprovalReview({ ...base, taskId: "task_b2" }, TENANT_B);

  const a = await listApprovalReviews(TENANT_A);
  const b = await listApprovalReviews(TENANT_B);

  assert.deepEqual(a.map((r) => r.taskId), ["task_a"]);
  assert.deepEqual(b.map((r) => r.taskId).sort(), ["task_b1", "task_b2"]);
});

test("reply outcomes isolate by scope", async () => {
  clearReplyOutcomes(TENANT_A);
  clearReplyOutcomes(TENANT_B);

  await recordReplyOutcome(
    { taskId: "t_a", threadId: "th", replyReceived: true, createdAt: "2026-06-23T12:00:00.000Z" },
    TENANT_A,
  );
  await recordReplyOutcome(
    { taskId: "t_b", threadId: "th", replyReceived: false, createdAt: "2026-06-23T12:00:00.000Z" },
    TENANT_B,
  );

  assert.deepEqual((await listReplyOutcomes(TENANT_A)).map((r) => r.taskId), ["t_a"]);
  assert.deepEqual((await listReplyOutcomes(TENANT_B)).map((r) => r.taskId), ["t_b"]);
});

test("followup outcome transition state is independent per scope", async () => {
  await clearTrackedFollowupOutcomes(TENANT_A);
  await clearTrackedFollowupOutcomes(TENANT_B);

  // Identical taskId/threadId in two scopes must not collide on transition state.
  await trackFollowupOutcome(
    { taskId: "task", threadId: "thread", status: "detected", outcomeNotes: [], shadowMode: false },
    TENANT_A,
  );
  await trackFollowupOutcome(
    { taskId: "task", threadId: "thread", status: "detected", outcomeNotes: [], shadowMode: false },
    TENANT_B,
  );

  // Advancing A does not affect B's independent state machine.
  await trackFollowupOutcome(
    { taskId: "task", threadId: "thread", status: "drafted", outcomeNotes: [], shadowMode: false },
    TENANT_A,
  );

  // Current state per scope is independent.
  assert.equal(getTrackedFollowupOutcome("task", "thread", TENANT_A)!.status, "drafted");
  assert.equal(getTrackedFollowupOutcome("task", "thread", TENANT_B)!.status, "detected");

  // And B's history never contains A's advanced state.
  assert.ok(
    !(await listTrackedFollowupOutcomes(TENANT_B)).some((o) => o.status === "drafted"),
  );
});

test("scoped key/path namespacing and traversal guards", () => {
  assert.equal(scopedKey("k", TENANT_A), "tenant_a:ws_a:k");
  assert.equal(scopedKey("k"), "k"); // legacy passthrough

  const p = scopedJsonlPath("file.jsonl", TENANT_A);
  assert.ok(p.includes(path.join("tenant_a", "ws_a")));

  assert.throws(
    () => scopedKey("k", { tenantId: "../etc", workspaceId: "ws" }),
    /Invalid tenantId/,
  );
});
