import assert from "node:assert/strict";
import crypto from "node:crypto";
import test, { after, before, beforeEach } from "node:test";

import { Pool } from "pg";

import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresMailState, type PostgresMailState } from "../src/persistence/postgres/mailStateStore";
import { envelopeSeal, envelopeOpen, localMasterKms } from "../src/crypto/envelopeEncryption";

// Real database or nothing: these tests prove the durable layer against an
// actual Postgres (dockerized locally / CI service). They fail loudly when the
// database is unreachable rather than green-lighting untested SQL.
const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const KMS = localMasterKms({ keyId: "test-master-v1", masterKey: Buffer.alloc(32, 4) });
const T_A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const T_B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };
const NOW = "2026-07-10T12:00:00.000Z";
const LATER = "2026-07-10T12:10:00.000Z";

let pool: Pool;
let state: PostgresMailState;

before(async () => {
  pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  await runMailMigrations(pool);
  await runMailMigrations(pool); // idempotent — second run must be a no-op
  state = createPostgresMailState(pool);
});

after(async () => {
  await pool.end();
});

beforeEach(async () => {
  await pool.query(
    "TRUNCATE mail_oauth_states, mail_connections, mail_credentials, mail_connection_health, mail_send_approvals, mail_reconciliation, mail_job_markers, mail_audit_events",
  );
});

test("pool creation fails closed without a database url", () => {
  assert.throws(() => createMailDbPool({} as NodeJS.ProcessEnv), /AALIYAH_DATABASE_URL/);
});

// ---- OAuth states ----

function oauthState(over: Record<string, unknown> = {}) {
  const sealed = envelopeSeal("verifier-secret", KMS);
  return {
    stateHash: crypto.randomBytes(16).toString("hex"),
    provider: "google" as const,
    ...T_A,
    userId: "u1",
    sessionId: "sess_1",
    redirectUri: "https://app.example/cb",
    codeVerifierEncrypted: JSON.stringify(sealed),
    codeVerifierKeyVersion: sealed.keyId,
    createdAt: NOW,
    expiresAt: LATER,
    consumedAt: null,
    ...over,
  };
}

test("oauth state: one-time, session-bound, expiring consume", async () => {
  const s = oauthState();
  await state.oauthStates.put(s);

  // Wrong session refused, state untouched.
  await assert.rejects(
    () =>
      state.oauthStates.consume(s.stateHash, {
        redirectUri: s.redirectUri,
        sessionId: "sess_hijack",
        now: () => new Date(NOW).getTime(),
      }),
    /session/,
  );

  // Wrong redirect refused.
  await assert.rejects(
    () =>
      state.oauthStates.consume(s.stateHash, {
        redirectUri: "https://evil.example/cb",
        sessionId: s.sessionId,
        now: () => new Date(NOW).getTime(),
      }),
    /redirect/,
  );

  // Correct consume returns the bound scope.
  const consumed = await state.oauthStates.consume(s.stateHash, {
    redirectUri: s.redirectUri,
    sessionId: s.sessionId,
    now: () => new Date(NOW).getTime(),
  });
  assert.equal(consumed.tenantId, T_A.tenantId);
  assert.equal(consumed.workspaceId, T_A.workspaceId);
  assert.equal(consumed.userId, "u1");
  assert.equal(envelopeOpen(JSON.parse(consumed.codeVerifierEncrypted), KMS), "verifier-secret");

  // Replay is dead.
  await assert.rejects(
    () =>
      state.oauthStates.consume(s.stateHash, {
        redirectUri: s.redirectUri,
        sessionId: s.sessionId,
        now: () => new Date(NOW).getTime(),
      }),
    /already used/,
  );

  // Expired state refused.
  const s2 = oauthState();
  await state.oauthStates.put(s2);
  await assert.rejects(
    () =>
      state.oauthStates.consume(s2.stateHash, {
        redirectUri: s2.redirectUri,
        sessionId: s2.sessionId,
        now: () => new Date(LATER).getTime() + 1,
      }),
    /expired/,
  );
});

test("oauth state: concurrent consumes — exactly one wins", async () => {
  const s = oauthState();
  await state.oauthStates.put(s);
  const attempt = () =>
    state.oauthStates
      .consume(s.stateHash, {
        redirectUri: s.redirectUri,
        sessionId: s.sessionId,
        now: () => new Date(NOW).getTime(),
      })
      .then(() => "won")
      .catch(() => "lost");
  const results = await Promise.all([attempt(), attempt(), attempt(), attempt()]);
  assert.equal(results.filter((r) => r === "won").length, 1);
});

// ---- Connections ----

function connection(id: string, scope = T_A) {
  return {
    connectionId: id,
    ...scope,
    userId: "u1",
    provider: "google" as const,
    emailAddress: "sales@pussycatalley.com",
    authKind: "oauth" as const,
    status: "connected" as const,
    connectedAt: NOW,
  };
}

test("connections: tenant-scoped save/get/delete; cross-tenant reads nothing", async () => {
  await state.connections.save(connection("conn_1"));
  const got = await state.connections.get("conn_1", T_A);
  assert.equal(got?.emailAddress, "sales@pussycatalley.com");

  assert.equal(await state.connections.get("conn_1", T_B), null);

  await state.connections.delete("conn_1");
  assert.equal(await state.connections.get("conn_1", T_A), null);
});

// ---- Credentials (envelope-encrypted at rest) ----

test("credentials: envelope at rest, revocation blocks retrieval of the secret", async () => {
  const envelope = envelopeSeal("rt-REFRESH-SECRET", KMS);
  await state.credentials.save({
    connectionId: "conn_1",
    ...T_A,
    userId: "u1",
    provider: "google",
    envelope,
    grantedScopes: ["email"],
    connectedEmail: "sales@pussycatalley.com",
    accessTokenExpiresAt: LATER,
    revokedAt: null,
  });

  const stored = await state.credentials.get("conn_1", T_A);
  assert.ok(stored);
  assert.equal(envelopeOpen(stored!.envelope, KMS), "rt-REFRESH-SECRET");
  // Nothing plaintext at rest.
  const raw = await pool.query("SELECT * FROM mail_credentials");
  assert.ok(!JSON.stringify(raw.rows).includes("rt-REFRESH-SECRET"));

  await state.credentials.revoke("conn_1", T_A, () => NOW);
  const revoked = await state.credentials.get("conn_1", T_A);
  assert.equal(revoked?.revokedAt !== null, true);

  assert.equal(await state.credentials.get("conn_1", T_B), null);
});

// ---- Connection health ----

test("connection health: upsert + scoped read", async () => {
  await state.health.upsert({ connectionId: "conn_1", ...T_A, healthy: true, detail: "ok", checkedAt: NOW });
  await state.health.upsert({ connectionId: "conn_1", ...T_A, healthy: false, detail: "token_expired", checkedAt: LATER });
  const h = await state.health.get("conn_1", T_A);
  assert.equal(h?.healthy, false);
  assert.equal(h?.detail, "token_expired");
  assert.equal(await state.health.get("conn_1", T_B), null);
});

// ---- Send approvals: delivery state machine, atomic claim ----

function approval(id: string) {
  return {
    approvalId: id,
    ...T_A,
    connectionId: "conn_1",
    recipientHash: "rh",
    bodyHash: "bh",
    approvedByUserId: "u1",
    approvedAt: NOW,
    expiresAt: LATER,
    status: "issued" as const,
    operationId: null,
    providerMessageId: null,
    updatedAt: NOW,
  };
}

test("send approvals: claim is atomic — concurrent claims yield one sending", async () => {
  await state.sendApprovals.insert(approval("ap_1"));
  const claim = () =>
    state.sendApprovals
      .claim("ap_1", { operationId: crypto.randomUUID(), now: () => NOW })
      .then((a) => (a ? "won" : "lost"));
  const results = await Promise.all([claim(), claim(), claim()]);
  assert.equal(results.filter((r) => r === "won").length, 1);

  const row = await state.sendApprovals.get("ap_1");
  assert.equal(row?.status, "sending");
  assert.ok(row?.operationId);
});

test("send approvals: settle sent / retryable; ambiguous stays sending for reconciliation", async () => {
  await state.sendApprovals.insert(approval("ap_1"));
  await state.sendApprovals.claim("ap_1", { operationId: "op_1", now: () => NOW });
  await state.sendApprovals.settle("ap_1", { sent: true, providerMessageId: "pm_1" }, () => LATER);
  assert.equal((await state.sendApprovals.get("ap_1"))?.status, "sent");

  await state.sendApprovals.insert(approval("ap_2"));
  await state.sendApprovals.claim("ap_2", { operationId: "op_2", now: () => NOW });
  // Never settled → surfaces for reconciliation once stale.
  const needing = await state.sendApprovals.needingReconciliation(new Date(LATER).getTime());
  assert.deepEqual(needing.map((a) => a.approvalId), ["ap_2"]);
});

test("send approvals: invalidateForConnection terminates pending approvals", async () => {
  await state.sendApprovals.insert(approval("ap_1"));
  await state.sendApprovals.insert({ ...approval("ap_2"), connectionId: "conn_other" });
  await state.sendApprovals.invalidateForConnection("conn_1", () => LATER);
  assert.equal((await state.sendApprovals.get("ap_1"))?.status, "failed_terminal");
  assert.equal((await state.sendApprovals.get("ap_2"))?.status, "issued");
});

// ---- Reconciliation records ----

test("reconciliation: attempts are recorded and listable per approval", async () => {
  await state.reconciliation.record({ approvalId: "ap_1", operationId: "op_1", checkedAt: NOW, outcome: "provider_no_record", detail: null });
  await state.reconciliation.record({ approvalId: "ap_1", operationId: "op_1", checkedAt: LATER, outcome: "confirmed_sent", detail: "pm_9" });
  const rows = await state.reconciliation.listForApproval("ap_1");
  assert.equal(rows.length, 2);
  assert.equal(rows[1]!.outcome, "confirmed_sent");
});

// ---- Job shutdown markers ----

test("job markers: disconnect marker stops background work", async () => {
  assert.equal(await state.jobMarkers.isStopped("conn_1"), false);
  await state.jobMarkers.setStopped({ connectionId: "conn_1", ...T_A, stoppedAt: NOW });
  assert.equal(await state.jobMarkers.isStopped("conn_1"), true);
});

// ---- Audit events ----

test("audit: append + tenant-scoped read, actor distinction survives storage", async () => {
  await state.audit.append({
    auditId: crypto.randomUUID(),
    ...T_A,
    connectionId: "conn_1",
    actorType: "user",
    actorUserId: "u1",
    action: "mail.connection.disconnect_requested",
    detail: "allowed",
    at: NOW,
  });
  await state.audit.append({
    auditId: crypto.randomUUID(),
    ...T_A,
    actorType: "service",
    actorServiceId: "mail.reader",
    action: "mail.connection.read",
    at: NOW,
  });

  const events = await state.audit.read(T_A);
  assert.equal(events.length, 2);
  assert.ok(events.some((e) => e.actorType === "user" && e.actorUserId === "u1"));
  assert.ok(events.some((e) => e.actorType === "service" && e.actorServiceId === "mail.reader"));

  assert.deepEqual(await state.audit.read(T_B), []);
});
