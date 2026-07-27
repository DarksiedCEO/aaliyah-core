import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";

import {
  clearInboundDraftRuntime,
  configureInboundDraftRuntime,
  runInboundDraft,
} from "../src/application/inbound/runInboundDraft";
import { routerDraftGenerator } from "../src/application/inbound/routerDraftGenerator";
import { AaliyahModelRouter } from "../src/model-router/AaliyahModelRouter";
import { idempotencyStoreInternals } from "../src/persistence/idempotencyStore";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

let createdDrafts: { rawMessage: string; accessToken: string }[];

beforeEach(() => {
  createdDrafts = [];
});

afterEach(() => {
  clearInboundDraftRuntime();
  idempotencyStoreInternals.resetInMemory();
});

test("legacy router seam is quarantined before model or provider access", async () => {
  // Real router with a fake provider adapter — no network, no keys.
  let modelCalls = 0;
  const router = new AaliyahModelRouter([
    {
      provider: "anthropic" as const,
      generate: async () => {
        modelCalls += 1;
        return {
          text: "Happy to help — here are the pricing details you asked for.",
          provider: "anthropic" as const,
          model: "claude-opus-4-8",
          latencyMs: 1,
        };
      },
    },
  ]);
  configureInboundDraftRuntime({
    authorize: async () => ({
      allowed: true,
      risk: "green",
      confidence: 0.9,
      reason: "test authorization",
    }),
    generator: routerDraftGenerator(router),
  });

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

  assert.equal(result.status, "failed");
  assert.equal(result.autoSend, false);
  assert.equal(result.generatorMode, undefined);
  assert.equal(modelCalls, 0);
  assert.equal(createdDrafts.length, 0);
});
