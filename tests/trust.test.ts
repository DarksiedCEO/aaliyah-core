import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before, beforeEach, afterEach } from "node:test";

import {
  buildConfidence,
  labelForScore,
  forcesManualReview,
} from "../src/application/trust/confidenceEngine";
import {
  recordDecisionTrace,
  readDecisionTraces,
} from "../src/application/trust/decisionTrace";
import {
  recordDraftQuality,
  summarizeDraftQuality,
} from "../src/application/trust/draftQuality";
import { trustMetricsSummary } from "../src/application/trust/trustMetrics";
import {
  runInboundDraft,
  inboundDraftInternals,
} from "../src/application/inbound/runInboundDraft";
import { idempotencyStoreInternals } from "../src/persistence/idempotencyStore";
import { resetApplicationStoreForTests } from "../src/persistence/applicationState";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(
    path.join(os.tmpdir(), "aaliyah-trust-"),
  );
  // Fresh in-memory application store per file (mirrors the prior per-file data
  // dir); data still accumulates across tests within this file.
  resetApplicationStoreForTests();
});

const A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };

test("confidence labels follow the thresholds and low forces manual review", () => {
  assert.equal(labelForScore(90), "high");
  assert.equal(labelForScore(60), "medium");
  assert.equal(labelForScore(30), "low");
  assert.equal(forcesManualReview("low"), true);
  assert.equal(forcesManualReview("high"), false);

  const c = buildConfidence(150, "x"); // clamps to 100
  assert.equal(c.score, 100);
  assert.equal(c.label, "high");
});

test("decision traces persist per scope and never cross tenants", async () => {
  await recordDecisionTrace({
    ...A, userId: "u1", decision: "draft_reply_awaiting_approval",
    reason: "ok", evidenceUsed: ["t1"],
  });
  await recordDecisionTrace({
    ...B, userId: "u2", decision: "draft_reply_awaiting_approval", reason: "ok",
  });

  const aTraces = await readDecisionTraces(A);
  assert.equal(aTraces.length, 1);
  assert.equal(aTraces[0]!.doctrineVersion, "v1");
  assert.equal((await readDecisionTraces(B)).length, 1);
  // No cross-tenant bleed.
  assert.ok(aTraces.every((t) => t.tenantId === "tenant_a"));
});

test("draft quality records and summarizes (measurement only), scoped", async () => {
  const base = { ...A, threadId: "t", createdAt: "2026-06-23T12:00:00.000Z" };
  await recordDraftQuality({ ...base, taskId: "k1", outcome: "approved" });
  await recordDraftQuality({ ...base, taskId: "k2", outcome: "edited", editDistance: 12 });
  await recordDraftQuality({ ...base, taskId: "k3", outcome: "rejected", rejectionReason: "tone_off" });

  const summary = await summarizeDraftQuality(A);
  assert.equal(summary.total, 3);
  assert.equal(summary.byOutcome.approved, 1);
  assert.equal(summary.byOutcome.edited, 1);
  assert.equal(summary.byOutcome.rejected, 1);
  assert.equal(summary.averageEditDistance, 12);

  // Scoped — tenant_b sees none of tenant_a's quality data.
  assert.equal((await summarizeDraftQuality(B)).total, 0);
});

test("trust metrics summary reads scoped traces + quality (read-only)", async () => {
  const metrics = await trustMetricsSummary(A, { high: 2, medium: 1, low: 0 });
  assert.ok(metrics.traceCount >= 1);
  assert.equal(metrics.confidence.high, 2);
  assert.ok(metrics.quality.total >= 3);
});

test("every inbound draft carries confidence + a decision trace; low still awaits approval", async () => {
  const realCreate = inboundDraftInternals.createDraft;
  const realToken = inboundDraftInternals.resolveAccessToken;
  const realGen = inboundDraftInternals.generator;
  inboundDraftInternals.createDraft = async () => "draft_t1";
  inboundDraftInternals.resolveAccessToken = () => "token";
  // Force a LOW confidence draft.
  inboundDraftInternals.generator = async ({ replyType }) => ({
    subject: "Re: hi", body: "draft", replyType, confidence: 20,
    generatorMode: "deterministic-v1",
  });

  try {
    const tracesBefore = (await readDecisionTraces({ tenantId: "tenant_c", workspaceId: "tenant_c:default" })).length;
    const result = await runInboundDraft({
      tenantId: "tenant_c", workspaceId: "tenant_c:default", userId: "u",
      email: {
        messageId: "mc1", threadId: "tc1", fromEmail: "c@example.com",
        subject: "hi", body: "question?", receivedAt: "2026-06-23T12:00:00.000Z",
      },
    });

    assert.equal(result.status, "awaiting_approval"); // low confidence still gated
    assert.equal(result.autoSend, false);
    assert.ok(result.confidence);
    assert.equal(result.confidence!.label, "low");

    const tracesAfter = (await readDecisionTraces({ tenantId: "tenant_c", workspaceId: "tenant_c:default" })).length;
    assert.equal(tracesAfter, tracesBefore + 1);
  } finally {
    inboundDraftInternals.createDraft = realCreate;
    inboundDraftInternals.resolveAccessToken = realToken;
    inboundDraftInternals.generator = realGen;
    idempotencyStoreInternals.resetInMemory();
  }
});
