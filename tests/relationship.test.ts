import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before, afterEach } from "node:test";

import {
  recordInteraction,
  getRelationshipContext,
  relationshipDirectives,
} from "../src/application/relationship/relationshipMemory";
import { clearRelationshipCache } from "../src/application/relationship/relationshipStore";
import { routerDraftGenerator } from "../src/application/inbound/routerDraftGenerator";
import { AaliyahModelRouter } from "../src/model-router/AaliyahModelRouter";
import { resetApplicationStoreForTests } from "../src/persistence/applicationState";

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(
    path.join(os.tmpdir(), "aaliyah-relationship-"),
  );
  resetApplicationStoreForTests();
});

afterEach(() => clearRelationshipCache());

const A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };
const NOW = () => "2026-06-23T12:00:00.000Z";

test("interactions accumulate into a retrievable relationship record", async () => {
  await recordInteraction({
    tenantId: "tenant_a", userId: "u1", contactEmail: "client@example.com",
    contactName: "Dana", summary: "Discussed pricing", relationshipNotes: "Prefers brevity",
    communicationStylePreference: "concise", now: NOW,
  });
  await recordInteraction({
    tenantId: "tenant_a", userId: "u1", contactEmail: "client@example.com",
    summary: "Sent proposal", now: NOW,
  });

  const ctx = await getRelationshipContext(A, "u1", "client@example.com");
  assert.ok(ctx);
  assert.equal(ctx!.contactName, "Dana");
  assert.equal(ctx!.communicationStylePreference, "concise");
  assert.equal(ctx!.relationshipNotes, "Prefers brevity");
  assert.deepEqual(ctx!.recentInteractions, ["Discussed pricing", "Sent proposal"]);
});

test("relationship memory never crosses tenant boundaries", async () => {
  await recordInteraction({
    tenantId: "tenant_a", userId: "u1", contactEmail: "shared@example.com",
    summary: "tenant A note", now: NOW,
  });
  // Same contact email, same userId, different tenant — must not be visible.
  assert.equal(await getRelationshipContext(B, "u1", "shared@example.com"), undefined);
  // And it is isolated per user within the tenant.
  assert.equal(await getRelationshipContext(A, "u_other", "shared@example.com"), undefined);
});

test("missing relationship context is undefined (advisory, optional)", async () => {
  assert.equal(await getRelationshipContext(A, "u1", "stranger@example.com"), undefined);
});

test("relationship context is supplied to the drafting system as advisory directives", async () => {
  await recordInteraction({
    tenantId: "tenant_a", userId: "u2", contactEmail: "lead@example.com",
    contactName: "Sam", summary: "Asked about enterprise tier", relationshipNotes: "Decision maker",
    now: NOW,
  });
  const ctx = (await getRelationshipContext(A, "u2", "lead@example.com"))!;
  assert.match(relationshipDirectives(ctx), /Sam/);
  assert.match(relationshipDirectives(ctx), /Decision maker/);

  let capturedSystem = "";
  const router = new AaliyahModelRouter([
    {
      provider: "openai" as const,
      generate: async (req) => {
        capturedSystem = req.system ?? "";
        return { text: "Hi Sam, ...", provider: "openai" as const, model: "m", latencyMs: 1 };
      },
    },
  ]);
  const generate = routerDraftGenerator(router, { relationship: ctx });
  await generate({
    email: {
      messageId: "m", threadId: "t", fromEmail: "lead@example.com",
      subject: "Q", body: "?", receivedAt: "2026-06-23T12:00:00.000Z",
    },
    replyType: "first_touch",
  });

  // The relationship context reached the generator (advisory, drafting only).
  assert.match(capturedSystem, /writing to Sam/);
});
