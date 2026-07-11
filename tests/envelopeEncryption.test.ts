import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  envelopeSeal,
  envelopeOpen,
  localMasterKms,
  type KmsKeyWrapper,
} from "../src/crypto/envelopeEncryption";

function testKms(): KmsKeyWrapper {
  const master = Buffer.alloc(32, 3);
  return localMasterKms({ keyId: "local-master-v1", masterKey: master });
}

test("envelope round-trips a secret through a wrapped data key", async () => {
  const kms = testKms();
  const sealed = await envelopeSeal("rt-REFRESH-SECRET", kms);

  assert.equal(sealed.keyId, "local-master-v1");
  assert.notEqual(sealed.ciphertext, "rt-REFRESH-SECRET");
  assert.ok(sealed.wrappedDataKey.length > 0);
  // Ciphertext and wrapped key never contain the plaintext or the data key.
  assert.ok(!sealed.ciphertext.includes("rt-REFRESH-SECRET"));

  assert.equal(await envelopeOpen(sealed, kms), "rt-REFRESH-SECRET");
});

test("each seal uses a fresh data key — no key reuse across secrets", async () => {
  const kms = testKms();
  const a = await envelopeSeal("same-secret", kms);
  const b = await envelopeSeal("same-secret", kms);
  assert.notEqual(a.wrappedDataKey, b.wrappedDataKey);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test("tampered ciphertext or wrapped key fails closed", async () => {
  const kms = testKms();
  const sealed = await envelopeSeal("secret", kms);

  const flip = (s: string, at: number): string => {
    const buf = Buffer.from(s, "base64");
    buf[at] = buf[at]! ^ 1;
    return buf.toString("base64");
  };

  await assert.rejects(() => envelopeOpen({ ...sealed, ciphertext: flip(sealed.ciphertext, 20) }, kms));
  await assert.rejects(() =>
    envelopeOpen({ ...sealed, wrappedDataKey: flip(sealed.wrappedDataKey, 20) }, kms),
  );
});

test("a different master key cannot unwrap", async () => {
  const sealed = await envelopeSeal("secret", testKms());
  const wrongKms = localMasterKms({
    keyId: "local-master-v1",
    masterKey: crypto.randomBytes(32),
  });
  await assert.rejects(() => envelopeOpen(sealed, wrongKms));
});

test("keyId mismatch is refused before any crypto is attempted", async () => {
  const kms = testKms();
  const sealed = await envelopeSeal("secret", kms);
  await assert.rejects(
    () => envelopeOpen({ ...sealed, keyId: "some-other-key" }, kms),
    /key id/i,
  );
});

test("local master KMS requires a 32-byte key", () => {
  assert.throws(() => localMasterKms({ keyId: "k", masterKey: Buffer.alloc(16, 1) }), /32/);
});
