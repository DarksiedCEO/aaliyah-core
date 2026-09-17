import crypto from "node:crypto";

/**
 * PERSONAL IDENTIFIERS IN TRUSTED MEMORY: ENCRYPTED, KEYED-INDEXED, ERASABLE.
 *
 * FOUNDER DECISION (Wave 1.3, locked). Erasure covers personally identifying
 * aliases — email addresses, phone numbers, external account identifiers —
 * subject to independently enforced legal-hold and retention rules. It is NOT
 * "delete the record's content and keep the address forever in plaintext",
 * which is exactly what b3efc82 did (red team BREAK 4: after a
 * `subject_erasure_request` the subject's email survived in cleartext in the
 * alias registry, and no writer, including the table owner, could remove it).
 *
 * THE ARCHITECTURE THIS FILE PROVIDES THE KEYS FOR:
 *
 *   alias plaintext
 *     -> ENCRYPTED under a per-binding DATA KEY (AES-256-GCM), with the scope
 *        and the binding bound in as associated data
 *     -> LOOKED UP through a BLIND INDEX: HMAC-SHA256 under a key derived per
 *        (tenant, scope key, purpose, key version), over a domain-separated,
 *        length-prefixed frame — never a raw SHA-256 of the alias, which a
 *        dictionary of addresses inverts offline
 *     -> ERASED by destroying the data key (the ciphertext becomes permanently
 *        unrecoverable, wherever copies of it went) AND by removing the blind
 *        index values from the database (so the address can no longer be
 *        confirmed by lookup), while non-PII evidence of the erasure survives.
 *
 * KEY MATERIAL NEVER ENTERS POSTGRESQL. The database stores ciphertext, key
 * REFERENCES and index values. The provider is asked to index, encrypt,
 * decrypt and destroy; it is never asked for a key.
 *
 * WHAT IS PROVEN AND WHAT IS NOT. This file defines the provider-neutral
 * interface and a LOCAL TEST provider. A production KMS/HSM provider is NOT
 * provisioned and NOT PROVEN; the local provider refuses to run when
 * NODE_ENV=production, and `productionEligible` is false. Nothing here is a
 * legal-compliance claim: these are engineering controls, and whether they
 * satisfy any regulation is not decided by this code.
 */

export type PiiIndexScope = {
  tenantId: string;
  /** The alias scope key: a workspace id, or "*" for a tenant-exclusive policy. */
  scopeKey: string;
};

export type PiiDataScope = {
  tenantId: string;
  workspaceId: string;
};

/** What a blind index is FOR. Keys are separated per purpose. */
export const PII_INDEX_PURPOSES = [
  "alias.normalized",
  "alias.skeleton",
  "alias.assignment-commitment",
] as const;
export type PiiIndexPurpose = (typeof PII_INDEX_PURPOSES)[number];

export const PII_ENVELOPE_ALGORITHM = "AES-256-GCM/aaliyah-pii-envelope-v1" as const;
export const PII_BLIND_INDEX_ALGORITHM = "HMAC-SHA256/aaliyah-pii-blind-index-v1" as const;

/** The stored form of a blind index: `bi1.<keyVersion>.<base64url tag>`. */
export const PII_BLIND_INDEX_FORM = /^bi1\.[1-9][0-9]{0,5}\.[A-Za-z0-9_-]{43}$/u;

export type PiiEnvelope = {
  algorithm: typeof PII_ENVELOPE_ALGORITHM;
  providerId: string;
  keyRef: string;
  keyVersion: number;
  /** base64url */
  iv: string;
  /** base64url */
  tag: string;
  /** base64url */
  ciphertext: string;
};

export type PiiDataKeyState = "active" | "destroyed" | "unknown";

/** A data key that was destroyed. Its ciphertext is unrecoverable by design. */
export class MemoryPiiKeyDestroyed extends Error {
  constructor(readonly keyRef: string) {
    super(`memory PII key destroyed: ${keyRef}`);
    this.name = "MemoryPiiKeyDestroyed";
  }
}
/** A key reference this provider has never issued. */
export class MemoryPiiKeyUnknown extends Error {
  constructor(readonly keyRef: string) {
    super(`memory PII key unknown: ${keyRef}`);
    this.name = "MemoryPiiKeyUnknown";
  }
}
/** A key used outside the tenant/workspace it was issued to. */
export class MemoryPiiScopeMismatch extends Error {
  constructor(readonly keyRef: string) {
    super(`memory PII key used outside its scope: ${keyRef}`);
    this.name = "MemoryPiiScopeMismatch";
  }
}
/** A key version retired from ENCRYPTION (it may still decrypt). */
export class MemoryPiiKeyRetired extends Error {
  constructor(readonly keyRef: string, readonly keyVersion: number) {
    super(`memory PII key version ${keyVersion} is retired for encryption: ${keyRef}`);
    this.name = "MemoryPiiKeyRetired";
  }
}
/** An envelope that is malformed, tampered, or bound to other associated data. */
export class MemoryPiiEnvelopeInvalid extends Error {
  constructor(reason: string) {
    super(`memory PII envelope invalid: ${reason}`);
    this.name = "MemoryPiiEnvelopeInvalid";
  }
}

export interface MemoryPiiKeyProvider {
  readonly providerId: string;
  /** False for anything that must never back production data. */
  readonly productionEligible: boolean;

  /** The blind index of `value` under the CURRENT key version for this purpose. */
  blindIndex(input: {
    scope: PiiIndexScope;
    purpose: PiiIndexPurpose;
    value: string;
  }): Promise<string>;
  /**
   * The blind index of `value` under EVERY version still active for lookup.
   * A value indexed before a rotation must remain findable until its entries
   * are re-indexed and the old version is retired.
   */
  blindIndexesForLookup(input: {
    scope: PiiIndexScope;
    purpose: PiiIndexPurpose;
    value: string;
  }): Promise<string[]>;

  /** Issue a fresh, erasable data key for one subject reference. */
  createDataKey(input: {
    scope: PiiDataScope;
    subjectRef: string;
  }): Promise<{ keyRef: string; keyVersion: number }>;
  encrypt(input: {
    scope: PiiDataScope;
    keyRef: string;
    plaintext: string;
    associatedData: string;
  }): Promise<PiiEnvelope>;
  /** Throws MemoryPiiKeyDestroyed / Unknown / ScopeMismatch / EnvelopeInvalid. */
  decrypt(input: {
    scope: PiiDataScope;
    envelope: PiiEnvelope;
    associatedData: string;
  }): Promise<string>;
  /** Idempotent: destroying a destroyed key reports it destroyed. */
  destroyDataKey(input: {
    scope: PiiDataScope;
    keyRef: string;
  }): Promise<{ state: "destroyed"; destroyedAt: string }>;
  dataKeyState(input: { scope: PiiDataScope; keyRef: string }): Promise<PiiDataKeyState>;
}

/** Length-prefixed framing: no field boundary can be moved by its content. */
export function piiFrame(fields: readonly string[]): Buffer {
  const parts: Buffer[] = [];
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length, 0);
    parts.push(length, bytes);
  }
  return Buffer.concat(parts);
}

/** The associated data an alias envelope is bound to. */
export function aliasEnvelopeAssociatedData(input: {
  tenantId: string;
  workspaceId: string;
  aliasId: string;
  mutationReceiptId: string;
}): string {
  return piiFrame([
    "aaliyah.pii.alias-binding-envelope/v1",
    input.tenantId,
    input.workspaceId,
    input.aliasId,
    input.mutationReceiptId,
  ]).toString("base64url");
}

type LocalDataKey = {
  scope: PiiDataScope;
  keyVersion: number;
  material: Buffer | null;
  destroyedAt: string | null;
};

export type LocalTestPiiKeyProvider = MemoryPiiKeyProvider & {
  /** Start a new blind-index key version for a purpose; old versions stay active for lookup. */
  rotateBlindIndexKey(scope: PiiIndexScope, purpose: PiiIndexPurpose): number;
  /** Stop answering lookups under a version (after re-indexing). */
  retireBlindIndexVersion(scope: PiiIndexScope, purpose: PiiIndexPurpose, version: number): void;
  /** Start a new data-key version for a scope; keys of older versions can no longer ENCRYPT. */
  rotateDataKeys(scope: PiiDataScope): number;
  /** Test-only: make the provider unreachable, to prove fail-closed behaviour. */
  setAvailable(available: boolean): void;
};

/** Thrown while a provider is unavailable. Never a verdict. */
export class MemoryPiiProviderUnavailable extends Error {
  constructor() {
    super("memory PII key provider unavailable");
    this.name = "MemoryPiiProviderUnavailable";
  }
}

/**
 * LOCAL TEST PROVIDER. Keys live in this process's memory and nowhere else.
 *
 * Blind-index keys are DERIVED (HKDF-SHA256) from `rootKey` per tenant, scope
 * key, purpose and version, so tests are deterministic. Data keys are RANDOM
 * and held only in a map: destroying one zeroes and drops the material, and
 * nothing — not the root key, not a seed — can re-derive it. That is the
 * property erasure depends on, and it is why data keys are not derived.
 */
export function createLocalTestPiiKeyProvider(options: {
  rootKey: Buffer;
  env?: NodeJS.ProcessEnv;
}): LocalTestPiiKeyProvider {
  const env = options.env ?? process.env;
  if (env.NODE_ENV === "production") {
    throw new Error(
      "memory PII keys: the LOCAL TEST provider refuses to run with NODE_ENV=production",
    );
  }
  if (options.rootKey.length !== 32) {
    throw new Error("memory PII keys: the local test root key must be 32 bytes");
  }
  const rootKey = Buffer.from(options.rootKey);
  const providerId = "local-test/v1";
  let available = true;

  const indexVersions = new Map<string, { current: number; active: Set<number> }>();
  const dataVersions = new Map<string, number>();
  const dataKeys = new Map<string, LocalDataKey>();

  const indexKeyName = (scope: PiiIndexScope, purpose: PiiIndexPurpose) =>
    piiFrame([scope.tenantId, scope.scopeKey, purpose]).toString("base64url");
  const dataScopeName = (scope: PiiDataScope) =>
    piiFrame([scope.tenantId, scope.workspaceId]).toString("base64url");

  function assertAvailable(): void {
    if (!available) throw new MemoryPiiProviderUnavailable();
  }
  function versions(scope: PiiIndexScope, purpose: PiiIndexPurpose) {
    const name = indexKeyName(scope, purpose);
    let entry = indexVersions.get(name);
    if (!entry) {
      entry = { current: 1, active: new Set([1]) };
      indexVersions.set(name, entry);
    }
    return entry;
  }
  function indexKey(scope: PiiIndexScope, purpose: PiiIndexPurpose, version: number): Buffer {
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        rootKey,
        Buffer.from("aaliyah.pii.blind-index-key/v1"),
        piiFrame([scope.tenantId, scope.scopeKey, purpose, String(version)]),
        32,
      ),
    );
  }
  function computeIndex(
    scope: PiiIndexScope,
    purpose: PiiIndexPurpose,
    value: string,
    version: number,
  ): string {
    const tag = crypto
      .createHmac("sha256", indexKey(scope, purpose, version))
      .update(
        piiFrame([PII_BLIND_INDEX_ALGORITHM, purpose, scope.tenantId, scope.scopeKey, value]),
      )
      .digest("base64url");
    return `bi1.${version}.${tag}`;
  }
  function keyFor(scope: PiiDataScope, keyRef: string): LocalDataKey {
    const key = dataKeys.get(keyRef);
    if (!key) throw new MemoryPiiKeyUnknown(keyRef);
    if (key.scope.tenantId !== scope.tenantId || key.scope.workspaceId !== scope.workspaceId) {
      throw new MemoryPiiScopeMismatch(keyRef);
    }
    return key;
  }

  return {
    providerId,
    productionEligible: false,

    async blindIndex({ scope, purpose, value }) {
      assertAvailable();
      return computeIndex(scope, purpose, value, versions(scope, purpose).current);
    },

    async blindIndexesForLookup({ scope, purpose, value }) {
      assertAvailable();
      return [...versions(scope, purpose).active]
        .sort((a, b) => b - a)
        .map((version) => computeIndex(scope, purpose, value, version));
    },

    async createDataKey({ scope, subjectRef }) {
      assertAvailable();
      const keyVersion = dataVersions.get(dataScopeName(scope)) ?? 1;
      const keyRef = `pii-key:${providerId}:${crypto.randomUUID()}`;
      dataKeys.set(keyRef, {
        scope: { ...scope },
        keyVersion,
        material: crypto.randomBytes(32),
        destroyedAt: null,
      });
      void subjectRef;
      return { keyRef, keyVersion };
    },

    async encrypt({ scope, keyRef, plaintext, associatedData }) {
      assertAvailable();
      const key = keyFor(scope, keyRef);
      if (key.material === null) throw new MemoryPiiKeyDestroyed(keyRef);
      const current = dataVersions.get(dataScopeName(scope)) ?? 1;
      if (key.keyVersion !== current) throw new MemoryPiiKeyRetired(keyRef, key.keyVersion);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", key.material, iv);
      cipher.setAAD(Buffer.from(associatedData, "utf8"));
      const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      return {
        algorithm: PII_ENVELOPE_ALGORITHM,
        providerId,
        keyRef,
        keyVersion: key.keyVersion,
        iv: iv.toString("base64url"),
        tag: cipher.getAuthTag().toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
      };
    },

    async decrypt({ scope, envelope, associatedData }) {
      assertAvailable();
      if (
        envelope === null ||
        typeof envelope !== "object" ||
        envelope.algorithm !== PII_ENVELOPE_ALGORITHM ||
        envelope.providerId !== providerId
      ) {
        throw new MemoryPiiEnvelopeInvalid("unrecognized algorithm or provider");
      }
      const key = keyFor(scope, envelope.keyRef);
      if (key.material === null) throw new MemoryPiiKeyDestroyed(envelope.keyRef);
      if (envelope.keyVersion !== key.keyVersion) {
        throw new MemoryPiiEnvelopeInvalid("key version does not match the key it names");
      }
      try {
        const decipher = crypto.createDecipheriv(
          "aes-256-gcm",
          key.material,
          Buffer.from(envelope.iv, "base64url"),
        );
        decipher.setAAD(Buffer.from(associatedData, "utf8"));
        decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
        return Buffer.concat([
          decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
          decipher.final(),
        ]).toString("utf8");
      } catch {
        throw new MemoryPiiEnvelopeInvalid("authentication failed");
      }
    },

    async destroyDataKey({ scope, keyRef }) {
      assertAvailable();
      const key = keyFor(scope, keyRef);
      if (key.material !== null) {
        key.material.fill(0);
        key.material = null;
        key.destroyedAt = new Date().toISOString();
      }
      return { state: "destroyed", destroyedAt: key.destroyedAt! };
    },

    async dataKeyState({ scope, keyRef }) {
      assertAvailable();
      const key = dataKeys.get(keyRef);
      if (!key) return "unknown";
      if (key.scope.tenantId !== scope.tenantId || key.scope.workspaceId !== scope.workspaceId) {
        throw new MemoryPiiScopeMismatch(keyRef);
      }
      return key.material === null ? "destroyed" : "active";
    },

    rotateBlindIndexKey(scope, purpose) {
      const entry = versions(scope, purpose);
      entry.current += 1;
      entry.active.add(entry.current);
      return entry.current;
    },

    retireBlindIndexVersion(scope, purpose, version) {
      const entry = versions(scope, purpose);
      if (version === entry.current) {
        throw new Error("memory PII keys: the current blind-index version cannot be retired");
      }
      entry.active.delete(version);
    },

    rotateDataKeys(scope) {
      const name = dataScopeName(scope);
      const next = (dataVersions.get(name) ?? 1) + 1;
      dataVersions.set(name, next);
      return next;
    },

    setAvailable(value) {
      available = value;
    },
  };
}
