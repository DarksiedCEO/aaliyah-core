import crypto from "node:crypto";

/**
 * Envelope encryption: every secret is encrypted with its own fresh data key
 * (AES-256-GCM); only the data key — never the secret — crosses the KMS
 * boundary for wrapping. This is the storage shape cloud KMS expects, so
 * swapping the local master for AWS/GCP KMS changes the wrapper, not the data.
 */
export interface KmsKeyWrapper {
  readonly keyId: string;
  wrapDataKey(plainDataKey: Buffer): Buffer;
  unwrapDataKey(wrappedDataKey: Buffer): Buffer;
}

export type EnvelopeSealed = {
  keyId: string;
  wrappedDataKey: string; // base64
  ciphertext: string; // base64: iv || tag || data
};

function gcmSeal(key: Buffer, plaintext: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}

function gcmOpen(key: Buffer, sealed: Buffer): Buffer {
  const iv = sealed.subarray(0, 12);
  const tag = sealed.subarray(12, 28);
  const data = sealed.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag); // throws on tamper
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

export function envelopeSeal(plaintext: string, kms: KmsKeyWrapper): EnvelopeSealed {
  const dataKey = crypto.randomBytes(32);
  try {
    return {
      keyId: kms.keyId,
      wrappedDataKey: kms.wrapDataKey(dataKey).toString("base64"),
      ciphertext: gcmSeal(dataKey, Buffer.from(plaintext, "utf8")).toString("base64"),
    };
  } finally {
    dataKey.fill(0);
  }
}

export function envelopeOpen(sealed: EnvelopeSealed, kms: KmsKeyWrapper): string {
  if (sealed.keyId !== kms.keyId) {
    throw new Error(`envelope key id mismatch: sealed under ${sealed.keyId}`);
  }
  const dataKey = kms.unwrapDataKey(Buffer.from(sealed.wrappedDataKey, "base64"));
  try {
    return gcmOpen(dataKey, Buffer.from(sealed.ciphertext, "base64")).toString("utf8");
  } finally {
    dataKey.fill(0);
  }
}

/**
 * Local master-key wrapper (AES-256-GCM over the data key). The minimum
 * honest bar for production: the master key lives in env/secret-manager,
 * never the database. A cloud KMS adapter implements this same interface
 * with a remote wrap/unwrap call — deliberately NOT faked here.
 */
export function localMasterKms(input: { keyId: string; masterKey: Buffer }): KmsKeyWrapper {
  if (input.masterKey.length !== 32) {
    throw new Error("master key must be 32 bytes (AES-256)");
  }
  return {
    keyId: input.keyId,
    wrapDataKey: (plainDataKey) => gcmSeal(input.masterKey, plainDataKey),
    unwrapDataKey: (wrappedDataKey) => gcmOpen(input.masterKey, wrappedDataKey),
  };
}

/** Env-backed local master: AALIYAH_MAIL_MASTER_KEY (base64, 32 bytes) + key id. */
export function envMasterKms(env: NodeJS.ProcessEnv = process.env): KmsKeyWrapper {
  const keyId = env.AALIYAH_MAIL_MASTER_KEY_ID;
  const raw = env.AALIYAH_MAIL_MASTER_KEY;
  if (!keyId || !raw) {
    throw new Error(
      "envelope encryption not configured: AALIYAH_MAIL_MASTER_KEY_ID and AALIYAH_MAIL_MASTER_KEY are required",
    );
  }
  return localMasterKms({ keyId, masterKey: Buffer.from(raw, "base64") });
}
