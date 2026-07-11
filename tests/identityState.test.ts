import assert from "node:assert/strict";
import crypto from "node:crypto";
import test, { after, before } from "node:test";

import { Pool } from "pg";

import { createMailDbPool } from "../src/persistence/postgres/pool";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresIdentityState } from "../src/persistence/postgres/identityStateStore";
import { createInMemoryIdentityState, type IdentityBackend } from "../src/auth/identityState";

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const NOW = "2026-07-10T12:00:00.000Z";
const LATER = "2026-07-10T13:00:00.000Z";

let pool: Pool;

before(async () => {
  pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  await runMailMigrations(pool);
});

after(async () => {
  await pool.end();
});

function user(id: string, over: object = {}) {
  return {
    id,
    tenantId: "tenant_a",
    externalProvider: "google" as const,
    externalSubject: `sub-${id}`,
    email: `${id}@pussycatalley.com`,
    emailVerified: true,
    status: "active" as const,
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

function session(id: string, userId: string, over: object = {}) {
  return {
    id,
    userId,
    tenantId: "tenant_a",
    sessionTokenHash: crypto.createHash("sha256").update(`token-${id}`).digest("hex"),
    authStrength: "sso" as const,
    createdAt: NOW,
    expiresAt: LATER,
    lastSeenAt: NOW,
    revokedAt: null,
    ...over,
  };
}

/** The same behavioral contract must hold for Postgres and the in-memory twin. */
function conformance(name: string, makeBackend: () => Promise<IdentityBackend> | IdentityBackend) {
  test(`${name}: users are anchored to external subject and status-controlled`, async () => {
    const ids = await makeBackend();
    const u = user(`u_${crypto.randomUUID().slice(0, 8)}`);
    await ids.users.create(u);

    const found = await ids.users.findByExternalSubject("google", u.externalSubject);
    assert.equal(found?.id, u.id);
    // Email alone anchors nothing.
    assert.equal(await ids.users.findByExternalSubject("google", u.email), null);

    await ids.users.setStatus(u.id, "disabled", () => LATER);
    assert.equal((await ids.users.get(u.id))?.status, "disabled");
  });

  test(`${name}: memberships grant, suspend, and revoke workspace access`, async () => {
    const ids = await makeBackend();
    const u = user(`u_${crypto.randomUUID().slice(0, 8)}`);
    await ids.users.create(u);

    await ids.memberships.grant({
      userId: u.id, tenantId: "tenant_a", workspaceId: "tenant_a:default",
      roleIds: ["workspace_admin"], status: "active", createdAt: NOW, revokedAt: null,
    });
    await ids.memberships.grant({
      userId: u.id, tenantId: "tenant_a", workspaceId: "tenant_a:ops",
      roleIds: ["workspace_member"], status: "active", createdAt: NOW, revokedAt: null,
    });

    let active = await ids.memberships.listActiveForUser(u.id, "tenant_a");
    assert.equal(active.length, 2);

    await ids.memberships.setStatus(u.id, "tenant_a", "tenant_a:ops", "suspended");
    active = await ids.memberships.listActiveForUser(u.id, "tenant_a");
    assert.deepEqual(active.map((m) => m.workspaceId), ["tenant_a:default"]);

    await ids.memberships.setStatus(u.id, "tenant_a", "tenant_a:default", "revoked", () => LATER);
    active = await ids.memberships.listActiveForUser(u.id, "tenant_a");
    assert.equal(active.length, 0);
  });

  test(`${name}: sessions are hash-addressed, touchable, revocable`, async () => {
    const ids = await makeBackend();
    const u = user(`u_${crypto.randomUUID().slice(0, 8)}`);
    await ids.users.create(u);
    const s = session(`sess_${crypto.randomUUID().slice(0, 8)}`, u.id);
    await ids.sessions.insert(s);

    const found = await ids.sessions.getByTokenHash(s.sessionTokenHash);
    assert.equal(found?.id, s.id);
    assert.equal(await ids.sessions.getByTokenHash("forged-hash"), null);

    await ids.sessions.touch(s.id, LATER);
    assert.equal((await ids.sessions.getByTokenHash(s.sessionTokenHash))?.lastSeenAt, LATER);

    await ids.sessions.revoke(s.id, LATER);
    assert.equal((await ids.sessions.getByTokenHash(s.sessionTokenHash))?.revokedAt, LATER);
  });

  test(`${name}: revokeAllForUser kills every session for the user`, async () => {
    const ids = await makeBackend();
    const u = user(`u_${crypto.randomUUID().slice(0, 8)}`);
    await ids.users.create(u);
    const s1 = session(`sess_${crypto.randomUUID().slice(0, 8)}`, u.id);
    const s2 = session(`sess_${crypto.randomUUID().slice(0, 8)}`, u.id);
    await ids.sessions.insert(s1);
    await ids.sessions.insert(s2);

    await ids.sessions.revokeAllForUser(u.id, LATER);
    assert.ok((await ids.sessions.getByTokenHash(s1.sessionTokenHash))?.revokedAt);
    assert.ok((await ids.sessions.getByTokenHash(s2.sessionTokenHash))?.revokedAt);
  });

  test(`${name}: service identities are hash-addressed and rotatable`, async () => {
    const ids = await makeBackend();
    const oldHash = crypto.createHash("sha256").update("old-credential").digest("hex");
    const svcId = `svc_${crypto.randomUUID().slice(0, 8)}`;
    await ids.serviceIdentities.register({
      id: svcId, tenantId: "tenant_a", name: "mail.reader",
      permissionIds: ["mail.connection.read"], credentialHash: oldHash,
      status: "active", createdAt: NOW, rotatedAt: NOW,
    });

    assert.equal((await ids.serviceIdentities.findActiveByCredentialHash(oldHash))?.id, svcId);

    // Rotation: new hash works, old hash is dead.
    const newHash = crypto.createHash("sha256").update("new-credential").digest("hex");
    await ids.serviceIdentities.rotate(svcId, newHash, LATER);
    assert.equal(await ids.serviceIdentities.findActiveByCredentialHash(oldHash), null);
    assert.equal((await ids.serviceIdentities.findActiveByCredentialHash(newHash))?.rotatedAt, LATER);

    // Disabled identities do not authenticate.
    await ids.serviceIdentities.setStatus(svcId, "disabled");
    assert.equal(await ids.serviceIdentities.findActiveByCredentialHash(newHash), null);
  });
}

conformance("postgres", () => createPostgresIdentityState(pool));
conformance("in-memory", () => createInMemoryIdentityState());

test("postgres: session revocation is visible across instances immediately", async () => {
  const ids = createPostgresIdentityState(pool);
  const u = user(`u_${crypto.randomUUID().slice(0, 8)}`);
  await ids.users.create(u);
  const s = session(`sess_${crypto.randomUUID().slice(0, 8)}`, u.id);
  await ids.sessions.insert(s);

  const pool2 = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  const instance2 = createPostgresIdentityState(pool2);
  try {
    await instance2.sessions.revoke(s.id, LATER); // revoked on instance 2…
    const seen = await ids.sessions.getByTokenHash(s.sessionTokenHash); // …instance 1 sees it
    assert.ok(seen?.revokedAt);
  } finally {
    await pool2.end();
  }
});
