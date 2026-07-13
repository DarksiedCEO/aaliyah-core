import assert from "node:assert/strict";
import test from "node:test";
import { classifyInbound } from "../../src/application/executive/triage";
import { AllProvidersFailedError } from "../../src/model-router/types";

const email = { messageId: "m", threadId: "t", fromEmail: "jane@acme.com", subject: "check my website", body: "Can you look at acme.com?", receivedAt: "2026-07-12T00:00:00.000Z" };
const routerReturning = (text: string) => ({ generate: async () => ({ text, provider: "anthropic" as const, model: "haiku", latencyMs: 1 }) });

test("valid JSON is parsed into a TriageResult", async () => {
  const r = await classifyInbound(
    routerReturning('{"category":"real_lead","risk":"green","reason":"asks for website help","confidence":0.9}'),
    email,
  );
  assert.equal(r.category, "real_lead");
  assert.equal(r.risk, "green");
  assert.equal(r.confidence, 0.9);
});

test("malformed JSON -> degraded review-only marker", async () => {
  const r = await classifyInbound(routerReturning("not json at all"), email);
  assert.equal(r.category, "unknown");
  assert.match(r.reason, /degraded/i);
  assert.equal(r.confidence, 0);
});

test("schema-invalid category -> degraded", async () => {
  const r = await classifyInbound(routerReturning('{"category":"nonsense","risk":"green","reason":"x","confidence":0.9}'), email);
  assert.equal(r.category, "unknown");
  assert.match(r.reason, /degraded/i);
});

test("all providers failed -> degraded", async () => {
  const router = { generate: async () => { throw new AllProvidersFailedError([]); } };
  const r = await classifyInbound(router, email);
  assert.equal(r.category, "unknown");
  assert.match(r.reason, /degraded/i);
  assert.equal(r.confidence, 0);
  assert.equal(r.degraded, true);
});
