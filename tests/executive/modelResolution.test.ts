import assert from "node:assert/strict";
import test from "node:test";
import { resolveConfiguredModels, verifyModels } from "../../src/application/executive/modelResolution";

test("defaults when env not set", () => {
  const t = resolveConfiguredModels({} as NodeJS.ProcessEnv);
  assert.equal(t.triage, "claude-haiku-4-5-20251001");
  assert.equal(t.draft, "claude-sonnet-5");
});

test("env overrides win", () => {
  const t = resolveConfiguredModels({ AALIYAH_TRIAGE_MODEL: "x", AALIYAH_DRAFT_MODEL: "y" } as NodeJS.ProcessEnv);
  assert.deepEqual(t, { triage: "x", draft: "y" });
});

test("verifyModels ok when both present in account list", async () => {
  const res = await verifyModels(
    { triage: "a", draft: "b" },
    async () => ["a", "b", "c"],
  );
  assert.equal(res.ok, true);
  assert.deepEqual(res.missing, []);
});

test("verifyModels reports missing without substituting", async () => {
  const res = await verifyModels(
    { triage: "a", draft: "missing" },
    async () => ["a", "c"],
  );
  assert.equal(res.ok, false);
  assert.deepEqual(res.missing, ["missing"]);
  assert.equal(res.tiers.draft, "missing"); // unchanged — never silently swapped
});
