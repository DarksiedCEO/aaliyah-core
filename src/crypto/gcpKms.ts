import { KeyManagementServiceClient } from "@google-cloud/kms";

import type { KmsKeyWrapper } from "./envelopeEncryption";

/**
 * The minimal Cloud KMS surface this wrapper needs. Narrow and structural on
 * purpose: the real @google-cloud/kms KeyManagementServiceClient satisfies it
 * without adaptation, and a fake satisfies it in tests without depending on
 * the SDK or a live GCP project.
 */
export interface GcpKmsClient {
  encrypt(request: {
    name: string;
    plaintext: Buffer;
  }): Promise<[{ ciphertext?: Uint8Array | string | null }, ...unknown[]]>;
  decrypt(request: {
    name: string;
    ciphertext: Buffer;
  }): Promise<[{ plaintext?: Uint8Array | string | null }, ...unknown[]]>;
}

export type GcpKmsConfig = {
  projectId: string;
  location: string;
  keyRing: string;
  cryptoKey: string;
};

export function gcpKeyResourceName(config: GcpKmsConfig): string {
  return `projects/${config.projectId}/locations/${config.location}/keyRings/${config.keyRing}/cryptoKeys/${config.cryptoKey}`;
}

function toBuffer(value: Uint8Array | string | null | undefined, missing: string): Buffer {
  if (value === null || value === undefined) {
    throw new Error(`gcp kms: ${missing}`);
  }
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return Buffer.from(value, "base64");
  return Buffer.from(value);
}

/**
 * Wrap/unwrap a data key via Cloud KMS Encrypt/Decrypt. `keyId` is the full
 * KMS resource name — envelopeOpen's key-mismatch check means a secret
 * sealed under one crypto key can never be opened by a wrapper pointed at a
 * different one, even accidentally.
 */
export function createGcpKmsKeyWrapper(config: GcpKmsConfig, client: GcpKmsClient): KmsKeyWrapper {
  const name = gcpKeyResourceName(config);
  return {
    keyId: name,
    async wrapDataKey(plainDataKey) {
      const [response] = await client.encrypt({ name, plaintext: plainDataKey });
      return toBuffer(response.ciphertext, "encrypt returned no ciphertext");
    },
    async unwrapDataKey(wrappedDataKey) {
      const [response] = await client.decrypt({ name, ciphertext: wrappedDataKey });
      return toBuffer(response.plaintext, "decrypt returned no plaintext");
    },
  };
}

const REQUIRED_ENV = [
  "GCP_KMS_PROJECT_ID",
  "GCP_KMS_LOCATION",
  "GCP_KMS_KEY_RING",
  "GCP_KMS_CRYPTO_KEY",
] as const;

/**
 * Real production factory. Client construction is synchronous (matches this
 * codebase's convention for other provider SDKs — googleapis, openai,
 * @anthropic-ai/sdk are all static top-level imports, not lazy-loaded); only
 * the actual wrap/unwrap RPCs are async.
 */
export function gcpKmsFromEnv(env: NodeJS.ProcessEnv = process.env): KmsKeyWrapper {
  const missing = REQUIRED_ENV.filter((k) => !env[k]);
  if (missing.length > 0) {
    throw new Error(`gcp kms not configured; missing: ${missing.join(", ")}`);
  }
  const client = new KeyManagementServiceClient();
  return createGcpKmsKeyWrapper(
    {
      projectId: env.GCP_KMS_PROJECT_ID!,
      location: env.GCP_KMS_LOCATION!,
      keyRing: env.GCP_KMS_KEY_RING!,
      cryptoKey: env.GCP_KMS_CRYPTO_KEY!,
    },
    client,
  );
}
