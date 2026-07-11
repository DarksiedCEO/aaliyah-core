import assert from "node:assert/strict";
import test from "node:test";

import type {
  ModelProvider,
  ModelRouterRequest,
  NormalizedModelResponse,
} from "@aaliyah/contracts/v1";

import { AaliyahModelRouter } from "../src/model-router/AaliyahModelRouter";
import { AllProvidersFailedError, type ProviderAdapter } from "../src/model-router/types";
import { ProviderHealthTracker } from "../src/model-router/providerHealth";

function fakeAdapter(
  provider: ModelProvider,
  impl: (req: ModelRouterRequest) => Promise<NormalizedModelResponse>,
): ProviderAdapter {
  return { provider, generate: impl };
}

function ok(provider: ModelProvider, text: string): ProviderAdapter {
  return fakeAdapter(provider, async () => ({
    text,
    provider,
    model: `${provider}-model`,
    latencyMs: 1,
  }));
}

function fail(provider: ModelProvider, message: string): ProviderAdapter {
  return fakeAdapter(provider, async () => {
    throw new Error(message);
  });
}

const REQ: ModelRouterRequest = { prompt: "hello" };

test("router returns the first healthy provider's response", async () => {
  const router = new AaliyahModelRouter([ok("openai", "from openai"), ok("anthropic", "from anthropic")]);
  const res = await router.generate(REQ);
  assert.equal(res.provider, "openai");
  assert.equal(res.text, "from openai");
});

test("router falls back to the next provider on failure", async () => {
  const router = new AaliyahModelRouter([
    fail("openai", "boom"),
    ok("anthropic", "rescued"),
  ]);
  const res = await router.generate(REQ);
  assert.equal(res.provider, "anthropic");
  assert.equal(res.text, "rescued");
});

test("router throws AllProvidersFailedError when every provider fails", async () => {
  const router = new AaliyahModelRouter([
    fail("openai", "a"),
    fail("anthropic", "b"),
    fail("gemini", "c"),
  ]);
  await assert.rejects(() => router.generate(REQ), (err: unknown) => {
    assert.ok(err instanceof AllProvidersFailedError);
    assert.equal(err.failures.length, 3);
    return true;
  });
});

test("a provider swap requires no caller change (same interface)", async () => {
  // Same request, different provider ordering — caller code is identical.
  const a = new AaliyahModelRouter([ok("anthropic", "A")]);
  const g = new AaliyahModelRouter([ok("gemini", "G")]);
  assert.equal((await a.generate(REQ)).provider, "anthropic");
  assert.equal((await g.generate(REQ)).provider, "gemini");
});

test("unhealthy provider is skipped until cooldown elapses", async () => {
  let clock = 0;
  const health = new ProviderHealthTracker({
    failureThreshold: 1,
    cooldownMs: 1000,
    now: () => clock,
  });
  let openaiCalls = 0;
  const flakyOpenai = fakeAdapter("openai", async () => {
    openaiCalls += 1;
    throw new Error("down");
  });
  const router = new AaliyahModelRouter([flakyOpenai, ok("anthropic", "backup")], {
    health,
    now: () => clock,
  });

  // First call: openai fails (now marked unhealthy), anthropic serves.
  assert.equal((await router.generate(REQ)).provider, "anthropic");
  assert.equal(openaiCalls, 1);

  // Within cooldown: openai is skipped entirely, not retried.
  assert.equal((await router.generate(REQ)).provider, "anthropic");
  assert.equal(openaiCalls, 1);

  // After cooldown: openai is retried (and fails again).
  clock = 2000;
  assert.equal((await router.generate(REQ)).provider, "anthropic");
  assert.equal(openaiCalls, 2);
});

test("a hung provider times out and falls back", async () => {
  const hung = fakeAdapter("openai", () => new Promise<NormalizedModelResponse>(() => {}));
  const router = new AaliyahModelRouter([hung, ok("anthropic", "fast")], {
    timeoutMs: 20,
  });
  const res = await router.generate(REQ);
  assert.equal(res.provider, "anthropic");
});

test("router requires at least one provider", () => {
  assert.throws(() => new AaliyahModelRouter([]), /at least one provider/);
});
