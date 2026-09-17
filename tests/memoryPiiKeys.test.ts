import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  MemoryPiiEnvelopeInvalid,
  MemoryPiiKeyDestroyed,
  MemoryPiiKeyRetired,
  MemoryPiiKeyUnknown,
  MemoryPiiProviderUnavailable,
  MemoryPiiScopeMismatch,
  PII_BLIND_INDEX_FORM,
  createLocalTestPiiKeyProvider,
  piiFrame,
} from "../src/crypto/memoryPiiKeys";

/**
 * THE PII KEY PROVIDER, ATTACKED IN ISOLATION.
 *
 * Every property the alias vault's erasure guarantee rests on is exercised
 * here without a database, so a failure localizes to the key layer.
 */

const ROOT = Buffer.alloc(32, 7);
const ALIAS = "victim.person@example.com";
const INDEX_SCOPE = { tenantId: "tenant-pii", scopeKey: "workspace-pii" };
const DATA_SCOPE = { tenantId: "tenant-pii", workspaceId: "workspace-pii" };

function provider() {
  return createLocalTestPiiKeyProvider({ rootKey: ROOT, env: {} as NodeJS.ProcessEnv });
}

test("a blind index is NOT a raw hash: a dictionary of SHA-256 digests does not contain it", async () => {
  const index = await provider().blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS });
  assert.match(index, PII_BLIND_INDEX_FORM);
  const tag = index.split(".")[2]!;
  // Everything an attacker holding the database and a dictionary could try
  // without the key.
  const guesses = [
    crypto.createHash("sha256").update(ALIAS).digest("base64url"),
    crypto.createHash("sha256").update(ALIAS.toLowerCase()).digest("base64url"),
    crypto.createHash("sha256").update(piiFrame(["alias.normalized", ALIAS])).digest("base64url"),
    crypto
      .createHash("sha256")
      .update(piiFrame(["HMAC-SHA256/aaliyah-pii-blind-index-v1", "alias.normalized", "tenant-pii", "workspace-pii", ALIAS]))
      .digest("base64url"),
  ];
  assert.ok(!guesses.includes(tag));
});

test("an attacker-chosen root key does not reproduce a blind index", async () => {
  const real = await provider().blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS });
  const attacker = createLocalTestPiiKeyProvider({ rootKey: Buffer.alloc(32, 8), env: {} as NodeJS.ProcessEnv });
  assert.notEqual(await attacker.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS }), real);
});

test("a blind index is deterministic for equality, and separated by tenant, scope key and purpose", async () => {
  const p = provider();
  const base = await p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS });
  assert.equal(await p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS }), base);
  const variants = await Promise.all([
    p.blindIndex({ scope: { ...INDEX_SCOPE, tenantId: "tenant-other" }, purpose: "alias.normalized", value: ALIAS }),
    p.blindIndex({ scope: { ...INDEX_SCOPE, scopeKey: "*" }, purpose: "alias.normalized", value: ALIAS }),
    p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.skeleton", value: ALIAS }),
    p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: `${ALIAS} ` }),
  ]);
  for (const variant of variants) assert.notEqual(variant, base);
  assert.equal(new Set(variants).size, variants.length);
});

test("rotation: new indexes use the new version, lookups still find the old one until it is retired", async () => {
  const p = provider();
  const v1 = await p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS });
  assert.match(v1, /^bi1\.1\./);
  assert.equal(p.rotateBlindIndexKey(INDEX_SCOPE, "alias.normalized"), 2);
  const v2 = await p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS });
  assert.match(v2, /^bi1\.2\./);
  assert.notEqual(v2, v1);
  assert.deepEqual(await p.blindIndexesForLookup({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS }), [v2, v1]);
  assert.throws(() => p.retireBlindIndexVersion(INDEX_SCOPE, "alias.normalized", 2), /current blind-index version cannot be retired/);
  p.retireBlindIndexVersion(INDEX_SCOPE, "alias.normalized", 1);
  assert.deepEqual(await p.blindIndexesForLookup({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS }), [v2]);
});

test("an envelope round-trips, and refuses the wrong tenant, the wrong workspace, and different associated data", async () => {
  const p = provider();
  const { keyRef } = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-1" });
  const envelope = await p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: ALIAS, associatedData: "aad-1" });
  assert.ok(!JSON.stringify(envelope).includes(ALIAS));
  assert.equal(await p.decrypt({ scope: DATA_SCOPE, envelope, associatedData: "aad-1" }), ALIAS);
  await assert.rejects(
    p.decrypt({ scope: { ...DATA_SCOPE, tenantId: "tenant-other" }, envelope, associatedData: "aad-1" }),
    MemoryPiiScopeMismatch,
  );
  await assert.rejects(
    p.decrypt({ scope: { ...DATA_SCOPE, workspaceId: "workspace-other" }, envelope, associatedData: "aad-1" }),
    MemoryPiiScopeMismatch,
  );
  await assert.rejects(p.decrypt({ scope: DATA_SCOPE, envelope, associatedData: "aad-2" }), MemoryPiiEnvelopeInvalid);
});

test("a tampered envelope, or one naming a different key version, is refused rather than decrypted", async () => {
  const p = provider();
  const { keyRef } = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-1" });
  const envelope = await p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: ALIAS, associatedData: "aad" });
  const flipped = Buffer.from(envelope.ciphertext, "base64url");
  flipped[0] = flipped[0]! ^ 1;
  await assert.rejects(
    p.decrypt({ scope: DATA_SCOPE, envelope: { ...envelope, ciphertext: flipped.toString("base64url") }, associatedData: "aad" }),
    MemoryPiiEnvelopeInvalid,
  );
  await assert.rejects(
    p.decrypt({ scope: DATA_SCOPE, envelope: { ...envelope, keyVersion: 2 }, associatedData: "aad" }),
    MemoryPiiEnvelopeInvalid,
  );
  await assert.rejects(
    p.decrypt({ scope: DATA_SCOPE, envelope: { ...envelope, keyRef: "pii-key:local-test/v1:never" }, associatedData: "aad" }),
    MemoryPiiKeyUnknown,
  );
});

test("a DESTROYED key decrypts nothing and encrypts nothing, destruction is idempotent, and the state says so", async () => {
  const p = provider();
  const { keyRef } = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-1" });
  const envelope = await p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: ALIAS, associatedData: "aad" });
  assert.equal(await p.dataKeyState({ scope: DATA_SCOPE, keyRef }), "active");
  const first = await p.destroyDataKey({ scope: DATA_SCOPE, keyRef });
  const second = await p.destroyDataKey({ scope: DATA_SCOPE, keyRef });
  assert.equal(first.state, "destroyed");
  assert.equal(second.destroyedAt, first.destroyedAt);
  assert.equal(await p.dataKeyState({ scope: DATA_SCOPE, keyRef }), "destroyed");
  await assert.rejects(p.decrypt({ scope: DATA_SCOPE, envelope, associatedData: "aad" }), MemoryPiiKeyDestroyed);
  await assert.rejects(
    p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: "again", associatedData: "aad" }),
    MemoryPiiKeyDestroyed,
  );
  // Destroying under another tenant's scope is refused, not silently accepted.
  await assert.rejects(p.destroyDataKey({ scope: { ...DATA_SCOPE, tenantId: "tenant-other" }, keyRef }), MemoryPiiScopeMismatch);
});

test("a destroyed data key cannot be RE-DERIVED: the same root key in a fresh provider does not know it", async () => {
  // Data keys are random, not derived. If they were derived from the root,
  // "destroying" one would destroy nothing.
  const p = provider();
  const { keyRef } = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-1" });
  const envelope = await p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: ALIAS, associatedData: "aad" });
  await p.destroyDataKey({ scope: DATA_SCOPE, keyRef });
  await assert.rejects(provider().decrypt({ scope: DATA_SCOPE, envelope, associatedData: "aad" }), MemoryPiiKeyUnknown);
});

test("a RETIRED data-key version cannot encrypt again, and still decrypts what it wrote", async () => {
  const p = provider();
  const { keyRef, keyVersion } = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-1" });
  assert.equal(keyVersion, 1);
  const envelope = await p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: ALIAS, associatedData: "aad" });
  assert.equal(p.rotateDataKeys(DATA_SCOPE), 2);
  await assert.rejects(p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: "new", associatedData: "aad" }), MemoryPiiKeyRetired);
  assert.equal(await p.decrypt({ scope: DATA_SCOPE, envelope, associatedData: "aad" }), ALIAS);
  const fresh = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-2" });
  assert.equal(fresh.keyVersion, 2);
});

test("an unavailable provider THROWS — it never answers an index, a plaintext, or a key state", async () => {
  const p = provider();
  const { keyRef } = await p.createDataKey({ scope: DATA_SCOPE, subjectRef: "alias-1" });
  const envelope = await p.encrypt({ scope: DATA_SCOPE, keyRef, plaintext: ALIAS, associatedData: "aad" });
  p.setAvailable(false);
  await assert.rejects(p.blindIndex({ scope: INDEX_SCOPE, purpose: "alias.normalized", value: ALIAS }), MemoryPiiProviderUnavailable);
  await assert.rejects(p.decrypt({ scope: DATA_SCOPE, envelope, associatedData: "aad" }), MemoryPiiProviderUnavailable);
  await assert.rejects(p.destroyDataKey({ scope: DATA_SCOPE, keyRef }), MemoryPiiProviderUnavailable);
  await assert.rejects(p.dataKeyState({ scope: DATA_SCOPE, keyRef }), MemoryPiiProviderUnavailable);
});

test("the LOCAL TEST provider refuses production, refuses a short root key, and never claims production eligibility", () => {
  assert.throws(
    () => createLocalTestPiiKeyProvider({ rootKey: ROOT, env: { NODE_ENV: "production" } as NodeJS.ProcessEnv }),
    /refuses to run with NODE_ENV=production/,
  );
  assert.throws(
    () => createLocalTestPiiKeyProvider({ rootKey: Buffer.alloc(16), env: {} as NodeJS.ProcessEnv }),
    /must be 32 bytes/,
  );
  assert.equal(provider().productionEligible, false);
});

test("framing is length-prefixed: moving a boundary changes the bytes", () => {
  assert.notDeepEqual(piiFrame(["ab", "c"]), piiFrame(["a", "bc"]));
});
