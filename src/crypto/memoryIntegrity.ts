import crypto from "node:crypto";

/**
 * KEYED INTEGRITY FOR TRUSTED MEMORY.
 *
 * WHAT THIS IS FOR, SAID PLAINLY. `canonicalDigest` is an UNKEYED SHA-256 over
 * canonical JSON, and W1BR-008 records the consequence: anyone holding a
 * record's `contentDigest` — from a head read, a receipt, a log line, a backup
 * — can confirm guessed content offline by digesting the guess and comparing.
 * For the low-entropy content this path carries (an identity, a status, a
 * short note, a last-four) the guess space is small enough to enumerate.
 *
 * A keyed construction removes that: a tag computed under a key the holder of
 * the ciphertext does not have confirms nothing about the plaintext.
 *
 * WHAT THIS DOES NOT DO, AND IT MATTERS. Introducing this primitive does NOT
 * by itself close W1BR-008. The oracle lives in the STORED unkeyed digest, and
 * that digest is the chain link every compare-and-swap, predecessor reference
 * and nonce binding is computed against, across two repositories. Replacing it
 * is a coordinated contracts migration, not a change to this file. What is
 * delivered here is the primitive that migration requires, and the honest
 * status of the oracle until then is OPEN.
 *
 * WHY AN INTERFACE AND NOT AN HMAC CALL. The key must be able to live outside
 * this process — in a KMS or an HSM — which means the key material may never
 * be a parameter. The provider is asked to SIGN and to VERIFY; it is never
 * asked for the key. A Cloud KMS MacSign/MacVerify adapter and the local
 * provider below implement the same surface, so moving from one to the other
 * changes a factory and nothing in the trusted-memory business logic. This
 * mirrors `KmsKeyWrapper` in ./envelopeEncryption, deliberately.
 */

/**
 * The algorithms a stored tag is allowed to name. A tag records the algorithm
 * it was produced under so a verifier never infers it from context: a stored
 * record whose algorithm was downgraded must be REFUSED, not verified under
 * whatever the verifier happens to prefer today.
 */
export const MEMORY_INTEGRITY_ALGORITHMS = ["HMAC-SHA256"] as const;
export type MemoryIntegrityAlgorithm =
  (typeof MEMORY_INTEGRITY_ALGORITHMS)[number];

/**
 * DOMAIN SEPARATION. Every message authenticated under a memory integrity key
 * is prefixed with the domain it belongs to, so a tag produced over a record's
 * content can never be presented as a tag over an alias binding, a tombstone,
 * or anything else that later shares the key. Without this, two structures
 * that happen to canonicalise to the same bytes are interchangeable under the
 * same key, which is a substitution the store has no way to detect.
 */
export const MEMORY_INTEGRITY_DOMAINS = [
  "aaliyah.trusted-memory.record-content/v1",
  "aaliyah.trusted-memory.alias-binding/v1",
  "aaliyah.trusted-memory.tombstone/v1",
] as const;
export type MemoryIntegrityDomain = (typeof MEMORY_INTEGRITY_DOMAINS)[number];

/**
 * THE PROVENANCE OF A KEY, RECORDED WITH EVERY TAG.
 *
 * `keyId` names the key; `keyVersion` names the generation of it. Both are
 * stored, because rotation means a record written last year must still verify
 * under the version it was written under while new records are written under
 * the current one. A tag that carried only `keyId` would become unverifiable
 * the moment the key rotated, and "unverifiable" and "tampered" would stop
 * being distinguishable.
 *
 * `provenance` is where the key material actually lives, as an honest label.
 * `local_test` is not a production value and is never to be reported as one.
 */
export const MEMORY_INTEGRITY_PROVENANCES = [
  "local_test",
  "env_master_key",
  "gcp_kms",
  "gcp_hsm",
] as const;
export type MemoryIntegrityProvenance =
  (typeof MEMORY_INTEGRITY_PROVENANCES)[number];

export type MemoryIntegrityKeyRef = {
  keyId: string;
  keyVersion: number;
  provenance: MemoryIntegrityProvenance;
};

/**
 * A TAG, AS IT IS STORED.
 *
 * Every field is required. A tag whose algorithm or key version is absent is
 * a tag nobody can check, and storing one would be indistinguishable from
 * storing nothing while looking like integrity was present.
 */
export type MemoryIntegrityTag = {
  algorithm: MemoryIntegrityAlgorithm;
  keyId: string;
  keyVersion: number;
  provenance: MemoryIntegrityProvenance;
  /** base64. */
  tag: string;
};

/**
 * THE KEY IS NOT AVAILABLE, SO THERE IS NO VERDICT.
 *
 * Thrown — never returned as `false` — when the provider cannot reach its key
 * material. This distinction IS the fail-closed behaviour: a verifier that
 * turned an unreachable KMS into `false` would report every record in the
 * system as tampered during an outage, and one that turned it into `true`
 * would accept forgeries during exactly the window an attacker would choose.
 * Neither is a verdict, so neither is returned.
 */
export class MemoryIntegrityKeyUnavailable extends Error {
  readonly keyId: string;
  readonly keyVersion: number | null;

  constructor(input: { keyId: string; keyVersion: number | null; cause?: unknown }) {
    super(
      `memory integrity key unavailable: ${input.keyId}` +
        (input.keyVersion === null ? "" : ` v${input.keyVersion}`),
    );
    this.name = "MemoryIntegrityKeyUnavailable";
    this.keyId = input.keyId;
    this.keyVersion = input.keyVersion;
    if (input.cause !== undefined) this.cause = input.cause;
  }
}

/**
 * THE PROVIDER SURFACE. Narrow and structural, so a Cloud KMS MacSign/MacVerify
 * client satisfies it without adaptation and a deterministic local key
 * satisfies it in tests without a network or a cloud project.
 *
 * `sign` always uses the CURRENT version — a caller cannot ask for an old one,
 * because writing a new record under a retired key is the mistake rotation
 * exists to prevent. `verify` takes an explicit version, because checking a
 * historical record is exactly the case that needs one.
 */
export interface MemoryIntegrityProvider {
  readonly algorithm: MemoryIntegrityAlgorithm;
  /** The key a NEW tag is written under. Throws if the key is unreachable. */
  current(): Promise<MemoryIntegrityKeyRef>;
  /** Authenticate `message` under the current key. */
  sign(message: Buffer): Promise<MemoryIntegrityTag>;
  /**
   * Check `tag` over `message`. Returns a verdict ONLY when a verdict exists:
   * throws `MemoryIntegrityKeyUnavailable` when the named key version cannot
   * be reached, so an outage is never reported as a forgery.
   */
  verify(message: Buffer, tag: MemoryIntegrityTag): Promise<boolean>;
}

/**
 * THE MESSAGE THAT GETS AUTHENTICATED.
 *
 * Length-prefixed, not delimiter-joined. Concatenating fields with a separator
 * lets two different field sets produce identical bytes whenever a value can
 * contain the separator — `tenant:"a|b", workspace:"c"` and
 * `tenant:"a", workspace:"b|c"` are the same string — and a tag over one then
 * authenticates the other. Every part is written as its byte length followed by
 * its bytes, so the encoding is unambiguous.
 *
 * The scope is INSIDE the authenticated message, not alongside it. A tag that
 * authenticated content alone could be lifted from one tenant's record and
 * replayed onto another's, and it would verify.
 */
export function memoryIntegrityMessage(input: {
  domain: MemoryIntegrityDomain;
  tenantId: string;
  workspaceId: string;
  /** Present for record content; null for structures with no principal. */
  principalId: string | null;
  userId: string | null;
  subjectId: string;
  /** Record version, alias binding id, tombstone version — whatever ordinals. */
  sequence: number;
  /** Canonical bytes of the thing being authenticated. */
  payload: Buffer;
}): Buffer {
  const parts: Buffer[] = [
    Buffer.from(input.domain, "utf8"),
    Buffer.from(input.tenantId, "utf8"),
    Buffer.from(input.workspaceId, "utf8"),
    Buffer.from(input.principalId ?? "", "utf8"),
    Buffer.from(input.userId ?? "", "utf8"),
    Buffer.from(input.subjectId, "utf8"),
    Buffer.from(String(input.sequence), "utf8"),
    input.payload,
  ];
  const framed: Buffer[] = [];
  for (const part of parts) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(part.length, 0);
    framed.push(length, part);
  }
  return Buffer.concat(framed);
}

/** Is `value` an algorithm this build knows how to verify under? */
export function isMemoryIntegrityAlgorithm(
  value: string,
): value is MemoryIntegrityAlgorithm {
  return (MEMORY_INTEGRITY_ALGORITHMS as readonly string[]).includes(value);
}

/**
 * A KEY GENERATION, FOR THE LOCAL PROVIDER ONLY.
 *
 * `retired` versions still VERIFY and never SIGN. That asymmetry is what
 * rotation means: yesterday's records stay checkable, and nothing new is
 * written under a key that is being taken out of service.
 */
export type LocalIntegrityKeyVersion = {
  version: number;
  key: Buffer;
  retired?: boolean;
};

/**
 * DETERMINISTIC LOCAL KEY PROVIDER — TESTS AND LOCAL DEVELOPMENT ONLY.
 *
 * This is NOT production key infrastructure and must never be reported as
 * cryptographic proof of anything: the key sits in this process's memory, so
 * anyone who can read the process can forge every tag it has ever produced.
 * Its purpose is to make the surrounding protocol — rotation, historical
 * verification, domain separation, fail-closed behaviour — testable
 * deterministically, without provisioning a KMS or an HSM.
 *
 * `provenance` is fixed to `local_test` and cannot be overridden, so a stored
 * tag can never claim a stronger origin than it has.
 */
export function localMemoryIntegrityProvider(input: {
  keyId: string;
  versions: readonly LocalIntegrityKeyVersion[];
  /** Simulates an unreachable key, for the fail-closed tests. */
  unavailable?: (keyVersion: number) => boolean;
}): MemoryIntegrityProvider {
  if (input.versions.length === 0) {
    throw new Error("local memory integrity provider needs at least one key version");
  }
  const byVersion = new Map<number, LocalIntegrityKeyVersion>();
  for (const version of input.versions) {
    if (version.key.length < 32) {
      // A MAC key shorter than its digest is a weaker key that still produces
      // a correctly shaped tag, which is exactly the kind of downgrade that
      // survives review because nothing about the output looks wrong.
      throw new Error("memory integrity key must be at least 32 bytes");
    }
    if (byVersion.has(version.version)) {
      throw new Error(`duplicate memory integrity key version ${version.version}`);
    }
    byVersion.set(version.version, version);
  }
  const signing = [...byVersion.values()]
    .filter((v) => v.retired !== true)
    .sort((a, b) => b.version - a.version)[0];
  if (signing === undefined) {
    throw new Error("local memory integrity provider has no active key version");
  }

  function keyFor(version: number): Buffer {
    if (input.unavailable?.(version) === true) {
      throw new MemoryIntegrityKeyUnavailable({
        keyId: input.keyId,
        keyVersion: version,
      });
    }
    const found = byVersion.get(version);
    if (found === undefined) {
      // An unknown version is NOT a failed verification. The record may be
      // perfectly intact and written under a key this deployment has not been
      // given; calling that "tampered" would be a false accusation.
      throw new MemoryIntegrityKeyUnavailable({
        keyId: input.keyId,
        keyVersion: version,
      });
    }
    return found.key;
  }

  function mac(key: Buffer, message: Buffer): Buffer {
    return crypto.createHmac("sha256", key).update(message).digest();
  }

  return {
    algorithm: "HMAC-SHA256",
    async current() {
      return {
        keyId: input.keyId,
        keyVersion: signing.version,
        provenance: "local_test",
      };
    },
    async sign(message) {
      const key = keyFor(signing.version);
      return {
        algorithm: "HMAC-SHA256",
        keyId: input.keyId,
        keyVersion: signing.version,
        provenance: "local_test",
        tag: mac(key, message).toString("base64"),
      };
    },
    async verify(message, tag) {
      if (tag.keyId !== input.keyId) {
        // A tag naming a different KEY is not this provider's to judge.
        throw new MemoryIntegrityKeyUnavailable({
          keyId: tag.keyId,
          keyVersion: tag.keyVersion,
        });
      }
      if (tag.algorithm !== "HMAC-SHA256") {
        // A downgraded or unknown algorithm is a REFUSAL, not an attempt to
        // verify under whatever this build happens to implement.
        return false;
      }
      const key = keyFor(tag.keyVersion);
      const expected = mac(key, message);
      let presented: Buffer;
      try {
        presented = Buffer.from(tag.tag, "base64");
      } catch {
        return false;
      }
      // Length must match before timingSafeEqual, which throws on a mismatch
      // rather than returning false. Compared in constant time so the tag
      // cannot be recovered a byte at a time from the response timing.
      if (presented.length !== expected.length) return false;
      return crypto.timingSafeEqual(presented, expected);
    },
  };
}
