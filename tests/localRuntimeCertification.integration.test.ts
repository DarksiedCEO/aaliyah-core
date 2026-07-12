import assert from "node:assert/strict";
import test, { after, before } from "node:test";

import { Pool } from "pg";

import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { resetApplicationStoreForTests } from "../src/persistence/applicationState";
import { runLocalRuntimeCertification, MISSING_SURFACES } from "../src/certification/localRuntimeCertification";

// Local deterministic certification over REAL Postgres: fake providers, real
// durable state. Proves the native inbound-draft path writes its ledger surface
// and never sends.
const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE = { tenantId: "cert_tenant", workspaceId: "cert_tenant:default" };

let pool: Pool;
let savedDbUrl: string | undefined;
let savedIdem: string | undefined;

before(async () => {
  savedDbUrl = process.env.AALIYAH_DATABASE_URL;
  savedIdem = process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY;
  process.env.AALIYAH_DATABASE_URL = DB_URL; // route the application store to real pg
  process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true"; // local-mode idempotency
  resetApplicationStoreForTests();
  pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  await runMailMigrations(pool);
});

after(async () => {
  await pool.end();
  if (savedDbUrl === undefined) delete process.env.AALIYAH_DATABASE_URL;
  else process.env.AALIYAH_DATABASE_URL = savedDbUrl;
  if (savedIdem === undefined) delete process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY;
  else process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = savedIdem;
  resetApplicationStoreForTests();
});

test("local runtime certification: native path verified, durable trace, zero sends", async () => {
  const evidence = await runLocalRuntimeCertification({ scope: SCOPE, userId: "cert_user" });

  // Every gate passed and the honest marker was emitted.
  assert.equal(evidence.marker, "LOCAL_RUNTIME_PATH_VERIFIED", JSON.stringify(evidence.gates));
  assert.ok(evidence.gates.every((g) => g.pass));

  // The certified invariants.
  assert.equal(evidence.outcomeStatus, "awaiting_approval");
  assert.equal(evidence.autoSend, false);
  assert.equal(evidence.sendCount, 0);
  assert.ok(evidence.draftId);
  assert.ok(evidence.decisionTraceId, "decision trace must be durably persisted");

  // Evidence bundle hygiene: redacted tenant/workspace, real commit, honest note.
  assert.match(evidence.tenantRef, /^ref_[0-9a-f]{12}$/);
  assert.ok(!evidence.tenantRef.includes("cert_tenant"));
  assert.notEqual(evidence.commitSha, "unknown");
  assert.equal(evidence.environment, "local-deterministic");
  assert.deepEqual(evidence.missingSurfaces, MISSING_SURFACES);
});

test("fake-provider mode never emits a production certificate", async () => {
  const evidence = await runLocalRuntimeCertification({ scope: SCOPE, userId: "cert_user2" });
  // The marker is strictly the local one — never a production/platform cert.
  assert.equal(evidence.marker, "LOCAL_RUNTIME_PATH_VERIFIED");
  assert.ok(!String(evidence.marker).includes("CERTIFIED"));
});
