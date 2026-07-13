import assert from "node:assert/strict";
import test from "node:test";
import { runEaPipeline } from "../../src/application/executive/eaPipeline";
import { CeoProfileSchema } from "../../src/application/executive/ceoProfile";
import { AllProvidersFailedError } from "../../src/model-router/types";

const profile = CeoProfileSchema.parse({ schemaVersion: 1, name: "Andre Love", title: "CEO", companies: ["Z Best Media"], priorities: ["leads"], tone: "direct", greeting: "Hi", signoff: "Best", neverPromise: ["pricing"], confidentialTopics: [] });
const email = (over = {}) => ({ messageId: "m", threadId: "t", fromEmail: "jane@acme.com", subject: "check my website", body: "look at acme.com", receivedAt: "2026-07-12T00:00:00.000Z", ...over });
const noSignals = { listUnsubscribe: false, precedenceBulk: false };
const router = (text: string) => ({ generate: async () => ({ text, provider: "anthropic" as const, model: "m", latencyMs: 1 }) });
const classify = (o: object) => router(JSON.stringify(o));

test("Stage 0 notification never calls models and yields no_action", async () => {
  let called = 0;
  const spy = { generate: async () => { called++; return { text: "{}", provider: "anthropic" as const, model: "m", latencyMs: 1 }; } };
  const out = await runEaPipeline({ triageRouter: spy, draftRouter: spy, profile }, { email: email({ fromEmail: "no-reply@x.com" }), signals: noSignals });
  assert.equal(out.action, "no_action");
  assert.equal(out.category, "notification_system");
  assert.equal(called, 0);
});

test("real_lead green -> draft attached", async () => {
  const out = await runEaPipeline(
    { triageRouter: classify({ category: "real_lead", risk: "green", reason: "asks for help", confidence: 0.9 }), draftRouter: router("Hi Jane, send the URL."), profile },
    { email: email(), signals: noSignals },
  );
  assert.equal(out.action, "draft");
  assert.ok(out.draft?.body.includes("URL"));
});

test("real_lead red -> escalate, no draft", async () => {
  const out = await runEaPipeline(
    { triageRouter: classify({ category: "real_lead", risk: "red", reason: "legal threat", confidence: 0.95 }), draftRouter: router("should not be used"), profile },
    { email: email(), signals: noSignals },
  );
  assert.equal(out.action, "escalate");
  assert.equal(out.draft, undefined);
});

test("triage degraded -> review_only", async () => {
  const bad = { generate: async () => { throw new AllProvidersFailedError([]); } };
  const out = await runEaPipeline({ triageRouter: bad, draftRouter: router("x"), profile }, { email: email(), signals: noSignals });
  assert.equal(out.action, "review_only");
  assert.equal(out.degraded, true);
});

test("drafting degraded -> review_only (no draft), even though triage said draft", async () => {
  const bad = { generate: async () => { throw new AllProvidersFailedError([]); } };
  const out = await runEaPipeline(
    { triageRouter: classify({ category: "real_lead", risk: "green", reason: "lead", confidence: 0.9 }), draftRouter: bad, profile },
    { email: email(), signals: noSignals },
  );
  assert.equal(out.action, "review_only");
  assert.equal(out.degraded, true);
  assert.equal(out.draft, undefined);
});
