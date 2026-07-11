import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";

import {
  runInboundDraft,
  inboundDraftInternals,
} from "../src/application/inbound/runInboundDraft";
import { routerDraftGenerator } from "../src/application/inbound/routerDraftGenerator";
import { AaliyahModelRouter } from "../src/model-router/AaliyahModelRouter";
import { idempotencyStoreInternals } from "../src/persistence/idempotencyStore";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

const realCreateDraft = inboundDraftInternals.createDraft;
const realResolveToken = inboundDraftInternals.resolveAccessToken;
const realGenerator = inboundDraftInternals.generator;

let createdDrafts: { rawMessage: string; accessToken: string }[];

beforeEach(() => {
  createdDrafts = [];
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

test("Block 3: the AaliyahModelRouter plugs into the inbound seam end-to-end", async () => {
  // Real router with a fake provider adapter — no network, no keys.
  const router = new AaliyahModelRouter([
    {
      provider: "anthropic" as const,
      generate: async () => ({
        text: "Happy to help — here are the pricing details you asked for.",
        provider: "anthropic" as const,
        model: "claude-opus-4-8",
        latencyMs: 1,
      }),
    },
  ]);
  inboundDraftInternals.generator = routerDraftGenerator(router);

  const result = await runInboundDraft({
    tenantId: "tenant_a",
    workspaceId: "ws_a",
    userId: "user_1",
    email: {
      messageId: "msg_router_1",
      threadId: "thread_router_1",
      fromEmail: "client@example.com",
      toEmail: "me@example.com",
      subject: "Pricing question",
      body: "Could you send pricing details?",
      receivedAt: "2026-06-23T12:00:00.000Z",
    },
  });

  assert.equal(result.status, "awaiting_approval");
  assert.equal(result.autoSend, false);
  assert.equal(result.generatorMode, "router:anthropic");
  assert.match(createdDrafts[0]!.rawMessage, /pricing details you asked for/);
});
