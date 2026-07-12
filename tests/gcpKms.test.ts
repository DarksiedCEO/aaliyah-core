import assert from "node:assert/strict";
import test from "node:test";

import {
  createGcpKmsKeyWrapper,
  gcpKeyResourceName,
  gcpKmsFromEnv,
  type GcpKmsClient,
} from "../src/crypto/gcpKms";
import { envelopeSeal, envelopeOpen } from "../src/crypto/envelopeEncryption";

const CONFIG = {
  projectId: "aaliyah-prod",
  location: "us-central1",
  keyRing: "mail-credentials",
  cryptoKey: "refresh-token-key",
};
const EXPECTED_NAME =
  "projects/aaliyah-prod/locations/us-central1/keyRings/mail-credentials/cryptoKeys/refresh-token-key";

/** A fake Cloud KMS client — no live GCP project exists to test against, so
 * this proves the adapter's request/response mapping and error handling.
 * NOT a substitute for a live-proof run against real Cloud KMS. */
function fakeKmsClient(overrides: Partial<GcpKmsClient> = {}): GcpKmsClient & {
  calls: { encrypt: unknown[]; decrypt: unknown[] };
} {
  const calls = { encrypt: [] as unknown[], decrypt: [] as unknown[] };
  // Simulate KMS by XOR "encryption" against a fixed pad — enough to prove
  // wrap(unwrap(x)) round-trips through the client boundary, not real crypto.
  const pad = Buffer.from("0123456789abcdef0123456789abcdef", "utf8").subarray(0, 32);
  const xor = (buf: Buffer): Buffer => Buffer.from(buf.map((b, i) => b ^ pad[i % pad.length]!));

  return {
    calls,
    encrypt: overrides.encrypt ?? (async (request) => {
      calls.encrypt.push(request);
      return [{ ciphertext: xor(request.plaintext) }];
    }),
    decrypt: overrides.decrypt ?? (async (request) => {
      calls.decrypt.push(request);
      return [{ plaintext: xor(Buffer.from(request.ciphertext)) }];
    }),
  };
}

test("resource name is built from project/location/keyRing/cryptoKey", () => {
  assert.equal(gcpKeyResourceName(CONFIG), EXPECTED_NAME);
});

test("keyId is the full KMS resource name — envelope key-mismatch protection works across keys", async () => {
  const wrapper = createGcpKmsKeyWrapper(CONFIG, fakeKmsClient());
  assert.equal(wrapper.keyId, EXPECTED_NAME);
});

test("wrap/unwrap round-trip through the client, with correct request shape", async () => {
  const client = fakeKmsClient();
  const wrapper = createGcpKmsKeyWrapper(CONFIG, client);

  const dataKey = Buffer.alloc(32, 7);
  const wrapped = await wrapper.wrapDataKey(dataKey);
  assert.notDeepEqual(wrapped, dataKey);
  assert.deepEqual(client.calls.encrypt, [{ name: EXPECTED_NAME, plaintext: dataKey }]);

  const unwrapped = await wrapper.unwrapDataKey(wrapped);
  assert.deepEqual(unwrapped, dataKey);
  assert.deepEqual(client.calls.decrypt, [{ name: EXPECTED_NAME, ciphertext: wrapped }]);
});

test("full envelope round-trip through the GCP wrapper", async () => {
  const wrapper = createGcpKmsKeyWrapper(CONFIG, fakeKmsClient());
  const sealed = await envelopeSeal("rt-REFRESH-SECRET", wrapper);
  assert.equal(sealed.keyId, EXPECTED_NAME);
  assert.equal(await envelopeOpen(sealed, wrapper), "rt-REFRESH-SECRET");
});

test("a ciphertext returned as a plain Uint8Array (not Buffer) is handled correctly", async () => {
  const client = fakeKmsClient({
    encrypt: async () => [{ ciphertext: new Uint8Array([1, 2, 3, 4]) }],
    decrypt: async () => [{ plaintext: new Uint8Array([9, 9, 9]) }],
  });
  const wrapper = createGcpKmsKeyWrapper(CONFIG, client);
  const wrapped = await wrapper.wrapDataKey(Buffer.alloc(32));
  assert.ok(Buffer.isBuffer(wrapped));
  assert.deepEqual(wrapped, Buffer.from([1, 2, 3, 4]));
  const unwrapped = await wrapper.unwrapDataKey(Buffer.alloc(4));
  assert.deepEqual(unwrapped, Buffer.from([9, 9, 9]));
});

test("missing ciphertext/plaintext in the KMS response fails closed, not silently", async () => {
  const emptyClient = fakeKmsClient({
    encrypt: async () => [{}],
    decrypt: async () => [{}],
  });
  const wrapper = createGcpKmsKeyWrapper(CONFIG, emptyClient);
  await assert.rejects(() => wrapper.wrapDataKey(Buffer.alloc(32)), /no ciphertext/);
  await assert.rejects(() => wrapper.unwrapDataKey(Buffer.alloc(32)), /no plaintext/);
});

test("a KMS client error (e.g. IAM denial, network failure) propagates — never silently swallowed", async () => {
  const failingClient = fakeKmsClient({
    encrypt: async () => {
      throw new Error("PERMISSION_DENIED: caller lacks cloudkms.cryptoKeyVersions.useToEncrypt");
    },
  });
  const wrapper = createGcpKmsKeyWrapper(CONFIG, failingClient);
  await assert.rejects(() => wrapper.wrapDataKey(Buffer.alloc(32)), /PERMISSION_DENIED/);
});

test("gcpKmsFromEnv fails closed when configuration is incomplete", () => {
  assert.throws(() => gcpKmsFromEnv({} as NodeJS.ProcessEnv), /GCP_KMS/);
  assert.throws(
    () =>
      gcpKmsFromEnv({
        GCP_KMS_PROJECT_ID: "p",
        GCP_KMS_LOCATION: "us-central1",
        // keyRing and cryptoKey missing
      } as NodeJS.ProcessEnv),
    /GCP_KMS/,
  );
});

test("gcpKmsFromEnv builds a real wrapper (client construction only — no network call) when fully configured", () => {
  const wrapper = gcpKmsFromEnv({
    GCP_KMS_PROJECT_ID: "aaliyah-prod",
    GCP_KMS_LOCATION: "us-central1",
    GCP_KMS_KEY_RING: "mail-credentials",
    GCP_KMS_CRYPTO_KEY: "refresh-token-key",
  } as unknown as NodeJS.ProcessEnv);
  assert.equal(wrapper.keyId, EXPECTED_NAME);
});
