import assert from "node:assert/strict";
import test from "node:test";
import { generateExecutiveDraft, DraftDegradedError } from "../../src/application/executive/executiveDraft";
import { CeoProfileSchema } from "../../src/application/executive/ceoProfile";
import { AllProvidersFailedError } from "../../src/model-router/types";

const profile = CeoProfileSchema.parse({
  schemaVersion: 1, name: "Andre Love", title: "CEO", companies: ["Z Best Media"],
  priorities: ["leads"], tone: "direct, warm, concise", greeting: "Hi", signoff: "Best,\nAndre",
  neverPromise: ["pricing"], confidentialTopics: [],
});
const email = { messageId: "m", threadId: "t", fromEmail: "jane@acme.com", subject: "check my website", body: "Can you look at acme.com?", receivedAt: "2026-07-12T00:00:00.000Z" };

test("produces a draft body from the router", async () => {
  const router = { generate: async () => ({ text: "Hi Jane, happy to take a look — send the URL.", provider: "anthropic" as const, model: "sonnet", latencyMs: 1 }) };
  const d = await generateExecutiveDraft(router, profile, "real_lead", email);
  assert.match(d.body, /take a look/);
  assert.match(d.subject, /^Re: /);
  assert.equal(d.generatorMode, "executive:anthropic");
});

test("AllProvidersFailedError -> DraftDegradedError (no canned draft)", async () => {
  const router = { generate: async () => { throw new AllProvidersFailedError([]); } };
  await assert.rejects(() => generateExecutiveDraft(router, profile, "real_lead", email), DraftDegradedError);
});

test("empty model output -> DraftDegradedError", async () => {
  const router = { generate: async () => ({ text: "   ", provider: "anthropic" as const, model: "sonnet", latencyMs: 1 }) };
  await assert.rejects(() => generateExecutiveDraft(router, profile, "real_lead", email), DraftDegradedError);
});
