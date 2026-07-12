import assert from "node:assert/strict";
import test from "node:test";

import { localMasterKms, type KmsKeyWrapper } from "../src/crypto/envelopeEncryption";
import { createInMemoryMailState } from "../src/mail/mailState";
import { saveMailCredential, openRefreshToken } from "../src/mail/security/credentialVault";
import { connectionIdFor } from "../src/mail/adapters/helpers";
import { GoogleMailAdapter } from "../src/mail/adapters/googleMailAdapter";

// Focused failure-path certification for the gaps not already covered by the
// credential-lifecycle, model-router, idempotency, envelope, and send-approval
// suites. Every case must FAIL CLOSED: no token, no send, no swallowed error.

const GOOD_KMS = localMasterKms({ keyId: "v1", masterKey: Buffer.alloc(32, 5) });
const SCOPE = { tenantId: "t", workspaceId: "t:default" };
const EMAIL = "sales@pussycatalley.com";
const CONN = connectionIdFor({ ...SCOPE, userId: "u", provider: "google", emailAddress: EMAIL });

async function seed(kms: KmsKeyWrapper = GOOD_KMS) {
  const state = createInMemoryMailState();
  await saveMailCredential(
    {
      connectionId: CONN, tenantId: SCOPE.tenantId, workspaceId: SCOPE.workspaceId,
      userId: "u", refreshToken: "rt-SECRET", grantedScopes: ["gmail"],
      connectedEmail: EMAIL, accessTokenExpiresAt: null,
    },
    { store: state.credentials, kms },
  );
  return state;
}

test("KMS unwrap failure -> openRefreshToken fails closed (no token)", async () => {
  const state = await seed(GOOD_KMS); // sealed under a working KMS
  // At read time the KMS is unavailable / permission denied.
  const failingKms: KmsKeyWrapper = {
    keyId: "v1",
    wrapDataKey: async () => { throw new Error("KMS unavailable"); },
    unwrapDataKey: async () => { throw new Error("KMS permission denied"); },
  };
  await assert.rejects(
    () => openRefreshToken(CONN, SCOPE, { store: state.credentials, kms: failingKms }),
    /KMS permission denied/,
  );
});

test("KMS key rotation mismatch -> envelope refuses to open (no token)", async () => {
  const state = await seed(GOOD_KMS); // sealed under keyId v1
  const otherKey: KmsKeyWrapper = localMasterKms({ keyId: "v2", masterKey: Buffer.alloc(32, 9) });
  await assert.rejects(
    () => openRefreshToken(CONN, SCOPE, { store: state.credentials, kms: otherKey }),
    /key id mismatch/,
  );
});

function jsonRes(status: number, body: unknown): Response {
  return { ok: status < 400, status, json: async () => body } as Response;
}

test("Gmail health classification: 401/403 -> reauth_required, 429/5xx -> unreachable, 200 -> active", async () => {
  const cases: Array<[number, "reauth_required" | "unreachable" | "active"]> = [
    [200, "active"],
    [401, "reauth_required"],
    [403, "reauth_required"],
    [404, "unreachable"],
    [429, "unreachable"],
    [500, "unreachable"],
  ];
  for (const [status, expected] of cases) {
    const adapter = new GoogleMailAdapter({
      resolveAccessToken: () => "token",
      fetchImpl: (async () => jsonRes(status, { emailAddress: EMAIL })) as unknown as typeof fetch,
    });
    const health = await adapter.verify(CONN);
    assert.equal(health.status, expected, `status ${status}`);
    assert.equal(health.healthy, status === 200, `healthy for ${status}`);
  }
});

test("Gmail read failure surfaces (never silently swallowed)", async () => {
  const adapter = new GoogleMailAdapter({
    resolveAccessToken: () => "token",
    fetchImpl: (async () => jsonRes(500, {})) as unknown as typeof fetch,
  });
  await assert.rejects(() => adapter.listThreads({ connectionId: CONN, limit: 1 }), /request failed \(500\)/);
});

test("default Gmail adapter refuses to send (no auto-send path exists)", async () => {
  const adapter = new GoogleMailAdapter({ resolveAccessToken: () => "token" });
  await assert.rejects(
    () =>
      adapter.sendMessage({
        connectionId: CONN,
        approvalId: "ap-x",
        to: [{ email: "x@example.com" }],
        subject: "s",
        body: "b",
      }),
  );
});
