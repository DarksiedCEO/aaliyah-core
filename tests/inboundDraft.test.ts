import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";

import {
  runInboundDraft,
  inboundDraftInternals,
} from "../src/application/inbound/runInboundDraft";
import { analyzeInbound } from "../src/application/inbound/analyzeInbound";
import { idempotencyStoreInternals } from "../src/persistence/idempotencyStore";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

const realCreateDraft = inboundDraftInternals.createDraft;
const realResolveToken = inboundDraftInternals.resolveAccessToken;
const realGenerator = inboundDraftInternals.generator;

let createdDrafts: { rawMessage: string; accessToken: string }[];

beforeEach(() => {
  createdDrafts = [];
  // Stub Gmail + credentials so no network/credential store is touched.
  inboundDraftInternals.createDraft = async (rawMessage, accessToken) => {
    createdDrafts.push({ rawMessage, accessToken });
    return `draft_${createdDrafts.length}`;
  };
  inboundDraftInternals.resolveAccessToken = () => "test_access_token";
});

afterEach(() => {
  inboundDraftInternals.createDraft = realCreateDraft;
  inboundDraftInternals.resolveAccessToken = realResolveToken;
  inboundDraftInternals.generator = realGenerator;
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

test("inbound draft is saved as a Gmail draft, pending approval, never sent", async () => {
  const result = await runInboundDraft(request());

  assert.equal(result.status, "draft_saved");
  assert.equal(result.approvalState, "pending");
  assert.equal(result.autoSend, false);
  assert.equal(result.draftId, "draft_1");
  assert.equal(result.replyType, "first_touch");

  // Exactly one DRAFT created, no send path exists.
  assert.equal(createdDrafts.length, 1);
  assert.match(createdDrafts[0]!.rawMessage, /^To: client@example.com/m);
  assert.match(createdDrafts[0]!.rawMessage, /^Subject: Re: Pricing question/m);
  assert.match(createdDrafts[0]!.rawMessage, /In-Reply-To: msg_1/);
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

  assert.equal(result.status, "skipped");
  assert.equal(result.approvalState, "pending");
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

test("inbound drafting is idempotent on messageId (no duplicate drafts)", async () => {
  const first = await runInboundDraft(request());
  const second = await runInboundDraft(request());

  assert.equal(first.draftId, second.draftId);
  // Replay returns the stored result without creating a second draft.
  assert.equal(createdDrafts.length, 1);
});

test("the generator is a pluggable seam (Block 3 router injection point)", async () => {
  inboundDraftInternals.generator = async ({ replyType }) => ({
    subject: "Custom subject",
    body: "Router-generated body",
    replyType,
    confidence: 90,
    generatorMode: "router:test",
  });

  const result = await runInboundDraft(request());
  assert.equal(result.generatorMode, "router:test");
  assert.match(createdDrafts[0]!.rawMessage, /^Subject: Custom subject/m);
});
