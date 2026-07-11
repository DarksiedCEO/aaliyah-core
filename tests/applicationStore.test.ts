import assert from "node:assert/strict";
import test from "node:test";

import {
  createInMemoryApplicationStore,
  applicationStoreFromEnv,
  resetApplicationStoreForTests,
} from "../src/persistence/applicationState";

const A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };

test("documents: latest-wins upsert, scoped get, cross-tenant isolation", async () => {
  const store = createInMemoryApplicationStore();
  await store.documents.put("style", A, "u1", { v: 1 });
  await store.documents.put("style", A, "u1", { v: 2 }); // latest wins
  assert.deepEqual(await store.documents.get("style", A, "u1"), { v: 2 });

  // Same store + key, different tenant → isolated (and absent).
  assert.equal(await store.documents.get("style", B, "u1"), null);
  // Same tenant, different store namespace → isolated.
  assert.equal(await store.documents.get("prefs", A, "u1"), null);

  await store.documents.put("style", B, "u1", { v: 99 });
  assert.deepEqual(await store.documents.get("style", A, "u1"), { v: 2 });
  assert.deepEqual(await store.documents.get("style", B, "u1"), { v: 99 });
});

test("documents.reset drops only the named store's rows", async () => {
  const store = createInMemoryApplicationStore();
  await store.documents.put("style", A, "u1", { v: 1 });
  await store.documents.put("prefs", A, "u1", { v: 1 });
  await store.documents.reset("style");
  assert.equal(await store.documents.get("style", A, "u1"), null);
  assert.deepEqual(await store.documents.get("prefs", A, "u1"), { v: 1 });
});

test("logs: append preserves order, list/clear are scoped and isolated", async () => {
  const store = createInMemoryApplicationStore();
  await store.logs.append("traces", A, { n: 1 });
  await store.logs.append("traces", A, { n: 2 });
  await store.logs.append("traces", B, { n: 100 });

  assert.deepEqual(await store.logs.list("traces", A), [{ n: 1 }, { n: 2 }]);
  assert.deepEqual(await store.logs.list("traces", B), [{ n: 100 }]);

  await store.logs.clear("traces", A);
  assert.deepEqual(await store.logs.list("traces", A), []);
  // Clearing one scope never touches another's rows.
  assert.deepEqual(await store.logs.list("traces", B), [{ n: 100 }]);
});

test("approvals: scoped list/clear; unscoped list returns all", async () => {
  const store = createInMemoryApplicationStore();
  const base = {
    taskId: "t", threadId: "th", approved: true, edited: false,
    editDistance: 0, reviewerId: "r", draftConfidence: 80,
    reviewedAt: "2026-07-11T00:00:00.000Z",
  };
  await store.approvals.insert({ ...base, taskId: "a" }, A);
  await store.approvals.insert({ ...base, taskId: "b" }, B);

  assert.deepEqual((await store.approvals.list(A)).map((r) => r.taskId), ["a"]);
  assert.deepEqual((await store.approvals.list(B)).map((r) => r.taskId), ["b"]);
  assert.equal((await store.approvals.list()).length, 2); // unscoped sees all

  await store.approvals.clear(A);
  assert.equal((await store.approvals.list(A)).length, 0);
  assert.equal((await store.approvals.list(B)).length, 1);
});

test("applicationStoreFromEnv fails closed in production without a database URL", () => {
  resetApplicationStoreForTests();
  const savedNodeEnv = process.env.NODE_ENV;
  const savedDbUrl = process.env.AALIYAH_DATABASE_URL;
  try {
    delete process.env.AALIYAH_DATABASE_URL;
    process.env.NODE_ENV = "production";
    assert.throws(
      () => applicationStoreFromEnv(),
      /durable application state is required in production/,
    );
  } finally {
    if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedNodeEnv;
    if (savedDbUrl !== undefined) process.env.AALIYAH_DATABASE_URL = savedDbUrl;
    resetApplicationStoreForTests();
  }
});
