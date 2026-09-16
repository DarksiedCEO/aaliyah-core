import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  MemoryIntegrityKeyUnavailable,
  localMemoryIntegrityProvider,
  memoryIntegrityMessage,
  type MemoryIntegrityTag,
} from "../src/crypto/memoryIntegrity";

/**
 * KEYED INTEGRITY, TESTED AS A PRIMITIVE.
 *
 * Every negative assertion here pins WHY it failed. A bare "it did not verify"
 * passes when the provider throws for an unrelated reason, which is how a
 * control looks tested while never having been exercised: the rotation tests
 * in particular would pass against a provider that simply refused everything.
 */

const KEY_A = Buffer.alloc(32, 0xa1);
const KEY_B = Buffer.alloc(32, 0xb2);

function provider(
  overrides: Parameters<typeof localMemoryIntegrityProvider>[0] | null = null,
) {
  return localMemoryIntegrityProvider(
    overrides ?? { keyId: "key.memory-integrity", versions: [{ version: 1, key: KEY_A }] },
  );
}

function message(
  overrides: Partial<Parameters<typeof memoryIntegrityMessage>[0]> = {},
): Buffer {
  return memoryIntegrityMessage({
    domain: "aaliyah.trusted-memory.record-content/v1",
    tenantId: "tenant-alpha",
    workspaceId: "workspace-1",
    principalId: "principal-1",
    userId: "user-1",
    subjectId: "record-memory-001",
    sequence: 1,
    payload: Buffer.from(JSON.stringify({ note: "original" }), "utf8"),
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// The primitive does what it says.
// ---------------------------------------------------------------------------

test("a tag produced over a message verifies against that message", async () => {
  const p = provider();
  const m = message();
  const tag = await p.sign(m);

  assert.equal(tag.algorithm, "HMAC-SHA256");
  assert.equal(tag.keyVersion, 1);
  // The local provider must never claim a stronger origin than it has.
  assert.equal(tag.provenance, "local_test");
  assert.equal(await p.verify(m, tag), true);
});

test("a tag does not verify against a message whose content changed by one byte", async () => {
  const p = provider();
  const tag = await p.sign(message());

  const altered = message({
    payload: Buffer.from(JSON.stringify({ note: "originaL" }), "utf8"),
  });
  assert.equal(await p.verify(altered, tag), false);
});

test("a tampered tag does not verify, and does not throw", async () => {
  const p = provider();
  const m = message();
  const tag = await p.sign(m);

  const bytes = Buffer.from(tag.tag, "base64");
  bytes.writeUInt8(bytes.readUInt8(0) ^ 0xff, 0);
  const forged: MemoryIntegrityTag = { ...tag, tag: bytes.toString("base64") };

  // False, not an exception: this IS a verdict, and it is "no".
  assert.equal(await p.verify(m, forged), false);
});

test("a truncated tag is refused rather than compared against a prefix", async () => {
  const p = provider();
  const m = message();
  const tag = await p.sign(m);
  const short = Buffer.from(tag.tag, "base64").subarray(0, 16);

  assert.equal(
    await p.verify(m, { ...tag, tag: short.toString("base64") }),
    false,
  );
});

// ---------------------------------------------------------------------------
// WHAT THE TAG IS BOUND TO. Each of these is a lift-and-replay attempt.
// ---------------------------------------------------------------------------

test("a tag cannot be lifted onto the same content in another TENANT", async () => {
  const p = provider();
  const tag = await p.sign(message());

  assert.equal(await p.verify(message({ tenantId: "tenant-beta" }), tag), false);
});

test("a tag cannot be lifted onto the same content in another WORKSPACE", async () => {
  const p = provider();
  const tag = await p.sign(message());

  assert.equal(
    await p.verify(message({ workspaceId: "workspace-2" }), tag),
    false,
  );
});

test("a tag cannot be lifted onto another PRINCIPAL's record", async () => {
  const p = provider();
  const tag = await p.sign(message());

  assert.equal(
    await p.verify(message({ principalId: "principal-2" }), tag),
    false,
  );
});

test("a tag cannot be lifted onto another USER's record", async () => {
  const p = provider();
  const tag = await p.sign(message());

  assert.equal(await p.verify(message({ userId: "user-2" }), tag), false);
});

test("a tag cannot be lifted onto a different record id", async () => {
  const p = provider();
  const tag = await p.sign(message());

  assert.equal(
    await p.verify(message({ subjectId: "record-memory-002" }), tag),
    false,
  );
});

test("a tag cannot be lifted onto a different version of the same record", async () => {
  const p = provider();
  const tag = await p.sign(message());

  // Without the sequence inside the message, a version-1 tag would authenticate
  // version 7 holding the same bytes, and a rollback would verify.
  assert.equal(await p.verify(message({ sequence: 7 }), tag), false);
});

test("DOMAIN SEPARATION: a record-content tag does not verify as an alias-binding tag", async () => {
  const p = provider();
  const tag = await p.sign(message());

  assert.equal(
    await p.verify(
      message({ domain: "aaliyah.trusted-memory.alias-binding/v1" }),
      tag,
    ),
    false,
  );
});

test("the framing is unambiguous: moving a separator between fields changes the message", async () => {
  // The reason the encoding is length-prefixed rather than delimiter-joined.
  // Under `join("|")` both of these are the identical string
  // "...|tenant|a|b|workspace|c|..." and one tag would authenticate both.
  const a = message({ tenantId: "a|b", workspaceId: "c" });
  const b = message({ tenantId: "a", workspaceId: "b|c" });

  assert.notEqual(a.toString("base64"), b.toString("base64"));

  const p = provider();
  const tag = await p.sign(a);
  assert.equal(await p.verify(b, tag), false);
});

test("an identical message under a DIFFERENT key does not verify", async () => {
  const m = message();
  const tag = await provider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: KEY_A }],
  }).sign(m);

  const other = provider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: KEY_B }],
  });
  assert.equal(await other.verify(m, tag), false);
});

// ---------------------------------------------------------------------------
// ROTATION, AND THE HISTORY THAT HAS TO KEEP VERIFYING.
// ---------------------------------------------------------------------------

test("after rotation, new tags use the new version and OLD tags still verify", async () => {
  const m = message();
  const before = provider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: KEY_A }],
  });
  const historical = await before.sign(m);
  assert.equal(historical.keyVersion, 1);

  const after = provider({
    keyId: "key.memory-integrity",
    versions: [
      { version: 1, key: KEY_A, retired: true },
      { version: 2, key: KEY_B },
    ],
  });

  // New writes go under v2 ...
  const current = await after.current();
  assert.equal(current.keyVersion, 2);
  assert.equal((await after.sign(m)).keyVersion, 2);

  // ... and last year's record is still checkable, which is the whole point.
  assert.equal(await after.verify(m, historical), true);
});

test("a retired version never SIGNS, even when it is the highest number", async () => {
  const p = provider({
    keyId: "key.memory-integrity",
    versions: [
      { version: 1, key: KEY_A },
      { version: 9, key: KEY_B, retired: true },
    ],
  });

  assert.equal((await p.current()).keyVersion, 1);
  assert.equal((await p.sign(message())).keyVersion, 1);
});

test("a provider with no active version refuses to be built rather than signing under a retired key", () => {
  assert.throws(
    () =>
      localMemoryIntegrityProvider({
        keyId: "key.memory-integrity",
        versions: [{ version: 1, key: KEY_A, retired: true }],
      }),
    /no active key version/,
  );
});

// ---------------------------------------------------------------------------
// FAIL-CLOSED. An outage is not a verdict.
// ---------------------------------------------------------------------------

test("an UNREACHABLE key throws rather than reporting the record as tampered", async () => {
  const p = provider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: KEY_A }],
    unavailable: () => true,
  });
  const good = await provider().sign(message());

  await assert.rejects(
    () => p.verify(message(), good),
    (error: unknown) => {
      // Pinned: a bare rejects() would pass on any thrown error at all,
      // including a programming mistake, and the distinction between "no
      // verdict" and "forged" is the entire control.
      assert.ok(error instanceof MemoryIntegrityKeyUnavailable);
      assert.equal(error.keyVersion, 1);
      return true;
    },
  );
});

test("an unreachable key throws on SIGN too, so nothing is written unauthenticated", async () => {
  const p = provider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: KEY_A }],
    unavailable: () => true,
  });

  await assert.rejects(
    () => p.sign(message()),
    (error: unknown) => error instanceof MemoryIntegrityKeyUnavailable,
  );
});

test("a tag naming an UNKNOWN key version throws instead of returning false", async () => {
  const p = provider();
  const tag = await p.sign(message());

  await assert.rejects(
    () => p.verify(message(), { ...tag, keyVersion: 42 }),
    (error: unknown) => {
      // A record written under a key this deployment was never given is not a
      // forgery, and calling it one is a false accusation about real data.
      assert.ok(error instanceof MemoryIntegrityKeyUnavailable);
      assert.equal(error.keyVersion, 42);
      return true;
    },
  );
});

test("a tag naming a different KEY ID throws rather than being judged here", async () => {
  const p = provider();
  const tag = await p.sign(message());

  await assert.rejects(
    () => p.verify(message(), { ...tag, keyId: "key.some-other-system" }),
    (error: unknown) => error instanceof MemoryIntegrityKeyUnavailable,
  );
});

// ---------------------------------------------------------------------------
// DOWNGRADE AND WEAK-KEY REFUSALS.
// ---------------------------------------------------------------------------

test("a tag naming an unknown ALGORITHM is refused, not verified under ours", async () => {
  const p = provider();
  const tag = await p.sign(message());

  const downgraded = {
    ...tag,
    algorithm: "HMAC-MD5",
  } as unknown as MemoryIntegrityTag;
  assert.equal(await p.verify(message(), downgraded), false);
});

test("a key shorter than the digest is refused at construction", () => {
  assert.throws(
    () =>
      localMemoryIntegrityProvider({
        keyId: "key.memory-integrity",
        versions: [{ version: 1, key: Buffer.alloc(16, 0x01) }],
      }),
    /at least 32 bytes/,
  );
});

test("two key versions sharing a number are refused rather than silently shadowing", () => {
  assert.throws(
    () =>
      localMemoryIntegrityProvider({
        keyId: "key.memory-integrity",
        versions: [
          { version: 1, key: KEY_A },
          { version: 1, key: KEY_B },
        ],
      }),
    /duplicate memory integrity key version/,
  );
});

test("a provider with no versions at all is refused", () => {
  assert.throws(
    () => localMemoryIntegrityProvider({ keyId: "k", versions: [] }),
    /at least one key version/,
  );
});

// ---------------------------------------------------------------------------
// THE PROPERTY W1BR-008 IS ABOUT.
// ---------------------------------------------------------------------------

test("holding a tag does not let an offline guesser confirm the content", async () => {
  // The unkeyed digest fails exactly this: sha256 of the guess equals the
  // stored value, with no access to anything. Recomputing the tag requires the
  // key, so the guesser's best effort produces a value that does not match.
  const secret = { ssn: "123-45-6789" };
  const p = provider();
  const stored = await p.sign(
    message({ payload: Buffer.from(JSON.stringify(secret), "utf8") }),
  );

  // The guesser guesses CORRECTLY, and still cannot confirm it.
  const guessedMessage = message({
    payload: Buffer.from(JSON.stringify(secret), "utf8"),
  });
  const unkeyed = crypto
    .createHash("sha256")
    .update(guessedMessage)
    .digest("base64");
  assert.notEqual(unkeyed, stored.tag);

  // And an attacker-chosen key does not reproduce it either.
  const attacker = localMemoryIntegrityProvider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: Buffer.alloc(32, 0xcc) }],
  });
  assert.notEqual((await attacker.sign(guessedMessage)).tag, stored.tag);

  // The holder of the real key, of course, confirms it immediately — so the
  // tag is still an integrity control, not just an opaque blob.
  assert.equal(await p.verify(guessedMessage, stored), true);
});
