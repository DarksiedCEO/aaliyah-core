import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before, afterEach } from "node:test";

import { StyleProfileSchema } from "@aaliyah/contracts/v1";

import {
  saveStyleProfile,
  loadStyleProfile,
  clearStyleCache,
} from "../src/application/style/styleStore";
import { resolveStyleProfile } from "../src/application/style/resolveStyleProfile";
import {
  defaultStyleFields,
  SAFE_DEFAULT_STYLE,
} from "../src/application/style/defaultStyleProfiles";
import {
  styleDirectives,
  enforceForbiddenPhrases,
} from "../src/application/style/styleDirectives";
import { routerDraftGenerator } from "../src/application/inbound/routerDraftGenerator";
import { AaliyahModelRouter } from "../src/model-router/AaliyahModelRouter";

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(
    path.join(os.tmpdir(), "aaliyah-style-"),
  );
});

afterEach(() => clearStyleCache());

const SCOPE = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };

test("the default style is safe and professional", () => {
  assert.equal(SAFE_DEFAULT_STYLE, "professional");
  const fields = defaultStyleFields("professional");
  assert.equal(fields.formality, "formal");
  assert.equal(fields.tone.length > 0, true);
});

test("style profiles store and retrieve by tenant/workspace/user", () => {
  const profile = saveStyleProfile({
    tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "user_1",
    styleId: "friendly", tone: "warm", lengthPreference: "short",
    formality: "casual", ctaBehavior: "soft", greeting: "Hey", signoff: "Cheers",
    forbiddenPhrases: [],
  });
  assert.equal(profile.styleId, "friendly");
  assert.equal(loadStyleProfile(SCOPE, "user_1")!.styleId, "friendly");
  // Isolated per user.
  assert.equal(loadStyleProfile(SCOPE, "user_other"), undefined);
});

test("resolve returns stored profile, else default for id, else safe fallback", () => {
  // No stored profile, explicit id -> default for that id.
  const direct = resolveStyleProfile(SCOPE, "user_2", "direct");
  assert.equal(direct.styleId, "direct");
  assert.equal(direct.lengthPreference, "short");

  // No stored profile, no id -> deterministic professional fallback.
  const fallback = resolveStyleProfile(SCOPE, "user_3");
  assert.equal(fallback.styleId, "professional");

  // custom with no stored notes -> safe fallback (custom is unusable without notes).
  const customFallback = resolveStyleProfile(SCOPE, "user_4", "custom");
  assert.equal(customFallback.styleId, "professional");

  // Stored profile wins.
  saveStyleProfile({
    tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "user_5",
    styleId: "executive", tone: "executive", lengthPreference: "short",
    formality: "formal", ctaBehavior: "direct", greeting: "Hi", signoff: "Best",
    forbiddenPhrases: [],
  });
  assert.equal(resolveStyleProfile(SCOPE, "user_5", "friendly").styleId, "executive");
});

test("custom style profile requires customNotes (validation)", () => {
  const invalid = StyleProfileSchema.safeParse({
    tenantId: "t", workspaceId: "w", userId: "u", styleId: "custom",
    tone: "x", lengthPreference: "short", formality: "neutral", ctaBehavior: "none",
  });
  assert.equal(invalid.success, false);

  const valid = StyleProfileSchema.safeParse({
    tenantId: "t", workspaceId: "w", userId: "u", styleId: "custom",
    tone: "x", lengthPreference: "short", formality: "neutral", ctaBehavior: "none",
    customNotes: "Always reference our SLA.",
  });
  assert.equal(valid.success, true);
});

test("forbidden phrases are deterministically stripped from output", () => {
  const profile = StyleProfileSchema.parse({
    tenantId: "t", workspaceId: "w", userId: "u", styleId: "professional",
    tone: "x", lengthPreference: "short", formality: "formal", ctaBehavior: "soft",
    forbiddenPhrases: ["as per my last email"],
  });
  const cleaned = enforceForbiddenPhrases("Hello, as per my last email, here it is.", profile);
  assert.ok(!cleaned.includes("as per my last email"));
});

test("selected style shapes the draft (directives reach the generator)", async () => {
  let capturedSystem = "";
  const router = new AaliyahModelRouter([
    {
      provider: "openai" as const,
      generate: async (req) => {
        capturedSystem = req.system ?? "";
        return { text: "Cheers, here you go.", provider: "openai" as const, model: "m", latencyMs: 1 };
      },
    },
  ]);
  const style = resolveStyleProfile(SCOPE, "user_6", "friendly");
  const generate = routerDraftGenerator(router, { style });

  const draft = await generate({
    email: {
      messageId: "m", threadId: "t", fromEmail: "c@example.com",
      subject: "Hi", body: "Question?", receivedAt: "2026-06-23T12:00:00.000Z",
    },
    replyType: "first_touch",
  });

  // The friendly style's directives were injected into the system prompt.
  assert.match(capturedSystem, /warm and approachable/);
  assert.match(styleDirectives(style), /Cheers/);
  assert.equal(draft.generatorMode, "router:openai");
});
