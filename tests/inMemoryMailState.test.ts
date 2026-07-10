import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createInMemoryMailState } from "../src/mail/mailState";
import { envelopeSeal, envelopeOpen, localMasterKms } from "../src/crypto/envelopeEncryption";

// The in-memory backend must honor the SAME semantics the Postgres layer
// proves in postgresMailState.integration.test.ts — it is the dev/test
// stand-in, not a different behavior.

const KMS = localMasterKms({ keyId: "mem-master-v1", masterKey: Buffer.alloc(32, 6) });
const T_A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const T_B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };
const NOW = "2026-07-10T12:00:00.000Z";
const LATER = "2026-07-10T12:10:00.000Z";

function oauthState(over: Record<string, never> | object = {}) {
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

test("in-memory oauth states: one-time, session-bound, expiring; raw values never stored", async () => {
  const state = createInMemoryMailState();
  const s = oauthState();
  await state.oauthStates.put(s);

  await assert.rejects(
    () =>
      state.oauthStates.consume(s.stateHash, {
        redirectUri: s.redirectUri,
        sessionId: "sess_x",
        now: () => new Date(NOW).getTime(),
      }),
    /session/,
  );
  const consumed = await state.oauthStates.consume(s.stateHash, {
    redirectUri: s.redirectUri,
    sessionId: s.sessionId,
    now: () => new Date(NOW).getTime(),
  });
  assert.equal(consumed.tenantId, T_A.tenantId);
  assert.equal(envelopeOpen(JSON.parse(consumed.codeVerifierEncrypted), KMS), "verifier-secret");
  await assert.rejects(
    () =>
      state.oauthStates.consume(s.stateHash, {
        redirectUri: s.redirectUri,
        sessionId: s.sessionId,
        now: () => new Date(NOW).getTime(),
      }),
    /already used/,
  );

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

  // No plaintext verifier anywhere in the backend's stored state.
  assert.ok(!JSON.stringify(state.dump()).includes("verifier-secret"));
});

test("in-memory connections + credentials: tenant scoping and revocation parity", async () => {
  const state = createInMemoryMailState();
  await state.connections.save({
    connectionId: "conn_1", ...T_A, userId: "u1", provider: "google",
    emailAddress: "sales@pussycatalley.com", authKind: "oauth",
    status: "connected", connectedAt: NOW,
  });
  assert.ok(await state.connections.get("conn_1", T_A));
  assert.equal(await state.connections.get("conn_1", T_B), null);

  const envelope = envelopeSeal("rt-SECRET", KMS);
  await state.credentials.save({
    connectionId: "conn_1", ...T_A, userId: "u1", provider: "google",
    envelope, grantedScopes: ["email"], connectedEmail: "sales@pussycatalley.com",
    accessTokenExpiresAt: null, revokedAt: null,
  });
  const cred = await state.credentials.get("conn_1", T_A);
  assert.equal(envelopeOpen(cred!.envelope, KMS), "rt-SECRET");
  assert.equal(await state.credentials.get("conn_1", T_B), null);

  await state.credentials.revoke("conn_1", T_A, () => NOW);
  const revoked = await state.credentials.get("conn_1", T_A);
  assert.ok(revoked!.revokedAt);
  // Ciphertext destroyed — even with the right KMS it cannot decrypt.
  assert.throws(() => envelopeOpen(revoked!.envelope, KMS));
});

test("in-memory approval claim: exactly one concurrent winner; ambiguous stays sending", async () => {
  const state = createInMemoryMailState();
  await state.sendApprovals.insert({
    approvalId: "ap_1", ...T_A, connectionId: "conn_1",
    recipientHash: "rh", bodyHash: "bh", approvedByUserId: "u1",
    approvedAt: NOW, expiresAt: LATER, status: "issued",
    operationId: null, providerMessageId: null, updatedAt: NOW,
  });
  const claim = () =>
    state.sendApprovals
      .claim("ap_1", { operationId: crypto.randomUUID(), now: () => NOW })
      .then((a) => (a ? "won" : "lost"));
  const results = await Promise.all([claim(), claim(), claim()]);
  assert.equal(results.filter((r) => r === "won").length, 1);

  const needing = await state.sendApprovals.needingReconciliation(new Date(LATER).getTime());
  assert.deepEqual(needing.map((a) => a.approvalId), ["ap_1"]);
});

test("in-memory job markers and audit: durable-parity semantics", async () => {
  const state = createInMemoryMailState();
  assert.equal(await state.jobMarkers.isStopped("conn_1"), false);
  await state.jobMarkers.setStopped({ connectionId: "conn_1", ...T_A, stoppedAt: NOW });
  assert.equal(await state.jobMarkers.isStopped("conn_1"), true);

  await state.audit.append({
    auditId: crypto.randomUUID(), ...T_A, actorType: "service",
    actorServiceId: "mail.reader", action: "mail.connection.read", at: NOW,
  });
  assert.equal((await state.audit.read(T_A)).length, 1);
  assert.deepEqual(await state.audit.read(T_B), []);
});
