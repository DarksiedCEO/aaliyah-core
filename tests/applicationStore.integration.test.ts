import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";

import { Pool } from "pg";

import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import {
  createPostgresApplicationStore,
  type ApplicationStore,
} from "../src/persistence/postgres/applicationStore";

// Real Postgres or nothing — proves the durable application store against an
// actual database (the same dockerized/CI instance the mail-state tests use).
const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };

let pool: Pool;
let store: ApplicationStore;

before(async () => {
  pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  await runMailMigrations(pool);
  await runMailMigrations(pool); // idempotent — second run is a no-op
  store = createPostgresApplicationStore(pool);
});

after(async () => {
  await pool.end();
});

beforeEach(async () => {
  await pool.query("TRUNCATE aaliyah_documents, aaliyah_append_logs, aaliyah_followup_approvals");
});

test("documents: durable upsert + scoped read; cross-tenant reads nothing", async () => {
  await store.documents.put("style", A, "u1", { v: 1 });
  await store.documents.put("style", A, "u1", { v: 2 }); // latest wins
  assert.deepEqual(await store.documents.get("style", A, "u1"), { v: 2 });
  assert.equal(await store.documents.get("style", B, "u1"), null);
});

test("append logs: insertion order preserved, scoped, clearable", async () => {
  await store.logs.append("traces", A, { n: 1 });
  await store.logs.append("traces", A, { n: 2 });
  await store.logs.append("traces", B, { n: 100 });

  assert.deepEqual(await store.logs.list("traces", A), [{ n: 1 }, { n: 2 }]);
  assert.deepEqual(await store.logs.list("traces", B), [{ n: 100 }]);

  await store.logs.clear("traces", A);
  assert.deepEqual(await store.logs.list("traces", A), []);
  assert.deepEqual(await store.logs.list("traces", B), [{ n: 100 }]);
});

test("approval reviews: scoped persistence + isolation, optional fields survive", async () => {
  const base = {
    taskId: "t", threadId: "th", approved: true, edited: true, editDistance: 7,
    reviewerId: "r", draftConfidence: 82, reviewedAt: "2026-07-11T00:00:00.000Z",
  };
  await store.approvals.insert({ ...base, taskId: "a", rejectionReason: "tone", category: "sales" }, A);
  await store.approvals.insert({ ...base, taskId: "b" }, B);

  const aRows = await store.approvals.list(A);
  assert.deepEqual(aRows.map((r) => r.taskId), ["a"]);
  assert.equal(aRows[0]!.rejectionReason, "tone");
  assert.equal(aRows[0]!.category, "sales");
  assert.equal(aRows[0]!.editDistance, 7);

  assert.deepEqual((await store.approvals.list(B)).map((r) => r.taskId), ["b"]);
  assert.equal((await store.approvals.list()).length, 2); // unscoped sees all
});
