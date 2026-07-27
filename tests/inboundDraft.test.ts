import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";

import {
  clearInboundDraftRuntime,
  configureInboundDraftRuntime,
  runInboundDraft,
} from "../src/application/inbound/runInboundDraft";
import { analyzeInbound } from "../src/application/inbound/analyzeInbound";
import { idempotencyStoreInternals } from "../src/persistence/idempotencyStore";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

let createdDrafts: { rawMessage: string; accessToken: string }[];

beforeEach(() => {
  createdDrafts = [];
  configureInboundDraftRuntime({
    authorize: async () => ({
      allowed: true,
      risk: "green",
      confidence: 0.9,
      reason: "test authorization",
    }),
    generator: async ({ email, replyType }) => ({
      subject: /^\s*re:/i.test(email.subject) ? email.subject : `Re: ${email.subject}`,
      body: "Model-generated test body.",
      replyType,
      generatorMode: "router:test",
    }),
  });
});

afterEach(() => {
  clearInboundDraftRuntime();
  idempotencyStoreInternals.resetInMemory();
});

function request(overrides: Record<string, unknown> = {}) {
  return {
    tenantId: "tenant_a",
    workspaceId: "ws_a",
    userId: "user_1",
    email: {
      messageId: "msg_1",
      threadId: "thread_1",
      fromEmail: "client@example.com",
      toEmail: "me@example.com",
      subject: "Pricing question",
      body: "Could you send pricing details?",
      receivedAt: "2026-06-23T12:00:00.000Z",
    },
    ...overrides,
  };
}

test("legacy inbound entry point fails closed without a trusted principal", async () => {
  const result = await runInboundDraft(request());

  assert.equal(result.status, "failed");
  assert.equal(result.mode, "inbound_draft");
  assert.equal(result.autoSend, false);
  assert.equal(result.reason, "trusted_executive_runtime_required");
  assert.equal(result.draftId, undefined);
  assert.equal(createdDrafts.length, 0);
});

test("non-replyable senders are skipped without creating a draft", async () => {
  const result = await runInboundDraft(
    request({
      email: {
        messageId: "msg_2",
        threadId: "thread_2",
        fromEmail: "no-reply@example.com",
        subject: "Receipt",
        body: "Your receipt",
        receivedAt: "2026-06-23T12:00:00.000Z",
      },
    }),
  );

  assert.equal(result.status, "no_action");
  assert.equal(result.mode, "inbound_draft");
  assert.equal(result.autoSend, false);
  assert.equal(createdDrafts.length, 0);
});

test("re: subjects are classified as existing conversation", () => {
  const analysis = analyzeInbound({
    messageId: "m",
    threadId: "t",
    fromEmail: "client@example.com",
    subject: "Re: Proposal",
    body: "Following up",
    receivedAt: "2026-06-23T12:00:00.000Z",
  });
  assert.equal(analysis.shouldDraft, true);
  assert.equal(analysis.replyType, "existing_conversation");
});

test("legacy fail-closed outcome is idempotent and never creates a draft", async () => {
  const first = await runInboundDraft(request());
  const second = await runInboundDraft(request());

  assert.deepEqual(first, second);
  assert.equal(createdDrafts.length, 0);
});

test("legacy generator configuration cannot bypass the trusted runtime boundary", async () => {
  configureInboundDraftRuntime({
    authorize: async () => ({
      allowed: true,
      risk: "green",
      confidence: 0.9,
      reason: "test authorization",
    }),
    generator: async ({ replyType }) => ({
      subject: "Custom subject",
      body: "Router-generated body",
      replyType,
      generatorMode: "router:test",
    }),
  });

  const result = await runInboundDraft(request());
  assert.equal(result.status, "failed");
  assert.equal(result.generatorMode, undefined);
  assert.equal(createdDrafts.length, 0);
});
