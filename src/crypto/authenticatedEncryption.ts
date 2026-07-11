import crypto from "node:crypto";

/**
 * Key material lives OUTSIDE the database (env/KMS), addressed by version so
 * keys can rotate without losing old ciphertext. In production, back this with
 * a KMS; the env provider is the minimum bar, never a hardcoded key.
 */
export interface KeyProvider {
  currentVersion(): string;
  key(version: string): Buffer;
}

export function envKeyProvider(): KeyProvider {
  const version = process.env.AALIYAH_MAIL_ENC_KEY_VERSION;
  if (!version) {
    throw new Error("AALIYAH_MAIL_ENC_KEY_VERSION is required for mail encryption");
  }
  return {
    currentVersion: () => version,
    key: (v: string) => {
      const raw = process.env[`AALIYAH_MAIL_ENC_KEY_${v}`];
      if (!raw) throw new Error(`missing mail encryption key for version ${v}`);
      const key = Buffer.from(raw, "base64");
      if (key.length !== 32) throw new Error("mail encryption key must be 32 bytes (AES-256)");
      return key;
    },
  };
}

export type Sealed = { ciphertext: string; keyVersion: string };

/** Authenticated encryption (AES-256-GCM) — confidentiality + tamper detection. */
export function sealSecret(plaintext: string, kp: KeyProvider): Sealed {
  const keyVersion = kp.currentVersion();
  const key = kp.key(keyVersion);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([iv, tag, enc]).toString("base64"),
    keyVersion,
  };
}

export function openSecret(sealed: Sealed, kp: KeyProvider): string {
  const key = kp.key(sealed.keyVersion);
  const buf = Buffer.from(sealed.ciphertext, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag); // throws on tamper
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}
