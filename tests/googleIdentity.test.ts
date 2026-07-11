import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { verifyGoogleIdToken, type JwksProvider } from "../src/auth/googleIdentity";

const CLIENT_ID = "aaliyah-client-id.apps.googleusercontent.com";
const NOW_MS = new Date("2026-07-10T12:00:00.000Z").getTime();
const nowSec = Math.floor(NOW_MS / 1000);

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const { privateKey: rogueKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

const jwk = {
  ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
  kid: "kid-1",
  alg: "RS256",
  use: "sig",
};
const jwks: JwksProvider = async () => ({ keys: [jwk] });

function b64u(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function payload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "https://accounts.google.com",
    aud: CLIENT_ID,
    sub: "google-sub-1234567890",
    email: "andre@pussycatalley.com",
    email_verified: true,
    iat: nowSec,
    exp: nowSec + 3600,
    ...over,
  };
}

function sign(
  body: Record<string, unknown>,
  over: { kid?: string; alg?: string; key?: crypto.KeyObject } = {},
): string {
  const header = { alg: over.alg ?? "RS256", kid: over.kid ?? "kid-1", typ: "JWT" };
  const input = `${b64u(header)}.${b64u(body)}`;
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(input), over.key ?? privateKey)
    .toString("base64url");
  return `${input}.${signature}`;
}

const opts = { clientId: CLIENT_ID, jwks, now: () => NOW_MS };

test("a genuine Google id token verifies: issuer, audience, signature, expiry, subject", async () => {
  const verified = await verifyGoogleIdToken(sign(payload()), opts);
  assert.equal(verified.subject, "google-sub-1234567890");
  assert.equal(verified.email, "andre@pussycatalley.com");
  assert.equal(verified.emailVerified, true);
});

test("wrong issuer is rejected", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload({ iss: "https://evil.example" })), opts),
    /issuer/,
  );
});

test("wrong audience is rejected", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload({ aud: "some-other-client" })), opts),
    /audience/,
  );
});

test("a token signed by a different key is rejected", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload(), { key: rogueKey }), opts),
    /signature/,
  );
});

test("an expired token is rejected", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload({ exp: nowSec - 10 })), opts),
    /expired/,
  );
});

test("alg=none and non-RS256 algorithms are rejected outright", async () => {
  // alg none with empty signature.
  const header = { alg: "none", kid: "kid-1", typ: "JWT" };
  const noneToken = `${b64u(header)}.${b64u(payload())}.`;
  await assert.rejects(() => verifyGoogleIdToken(noneToken, opts), /algorithm/);

  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload(), { alg: "HS256" }), opts),
    /algorithm/,
  );
});

test("unknown key id is rejected (no key guessing)", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload(), { kid: "kid-unknown" }), opts),
    /key/,
  );
});

test("unverified email is rejected", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload({ email_verified: false })), opts),
    /email/,
  );
});

test("missing subject is rejected — email alone can never anchor identity", async () => {
  await assert.rejects(
    () => verifyGoogleIdToken(sign(payload({ sub: "" })), opts),
    /subject/,
  );
});

test("nonce is enforced when expected", async () => {
  await assert.rejects(
    () =>
      verifyGoogleIdToken(sign(payload({ nonce: "wrong" })), { ...opts, expectedNonce: "right" }),
    /nonce/,
  );
  const ok = await verifyGoogleIdToken(sign(payload({ nonce: "right" })), {
    ...opts,
    expectedNonce: "right",
  });
  assert.equal(ok.subject, "google-sub-1234567890");
});

test("verification errors never echo the token or its claims payload", async () => {
  const token = sign(payload({ aud: "some-other-client" }));
  try {
    await verifyGoogleIdToken(token, opts);
    assert.fail("expected rejection");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert.ok(!message.includes(token));
    assert.ok(!message.includes("andre@pussycatalley.com"));
  }
});
