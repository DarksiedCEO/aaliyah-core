import {
  MailCredentialSchema,
  type MailCredential,
} from "@aaliyah/contracts/v1";

import {
  openSecret,
  sealSecret,
  type KeyProvider,
} from "../../crypto/authenticatedEncryption";
import type { TenantScope } from "../../persistence/tenantScopedStore";

// Keyed by connectionId (which embeds tenant:workspace:user). In production this
// MUST be a durable, tenant-scoped table. Refresh tokens are stored only as
// authenticated ciphertext — plaintext is never persisted, logged, or returned.
const store = new Map<string, MailCredential>();

export function saveMailCredential(
  input: {
    connectionId: string;
    tenantId: string;
    workspaceId: string;
    userId: string;
    refreshToken: string;
    grantedScopes: string[];
    connectedEmail: string;
    accessTokenExpiresAt: string | null;
  },
  kp: KeyProvider,
): MailCredential {
  const sealed = sealSecret(input.refreshToken, kp);
  const credential = MailCredentialSchema.parse({
    connectionId: input.connectionId,
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    provider: "google",
    encryptedRefreshToken: sealed.ciphertext,
    encryptionKeyVersion: sealed.keyVersion,
    grantedScopes: input.grantedScopes,
    connectedEmail: input.connectedEmail,
    accessTokenExpiresAt: input.accessTokenExpiresAt,
    revokedAt: null,
  });
  store.set(credential.connectionId, credential);
  return credential;
}

/** Tenant-scoped read — returns nothing if the record belongs to another tenant. */
export function getMailCredential(
  connectionId: string,
  scope: TenantScope,
): MailCredential | undefined {
  const record = store.get(connectionId);
  if (!record) return undefined;
  if (record.tenantId !== scope.tenantId || record.workspaceId !== scope.workspaceId) {
    return undefined; // cross-tenant access denied
  }
  return record;
}

/** Decrypt the refresh token for use (never returned to a browser/log). */
export function openRefreshToken(
  connectionId: string,
  scope: TenantScope,
  kp: KeyProvider,
): string {
  const record = getMailCredential(connectionId, scope);
  if (!record) throw new Error("credential not found for scope");
  if (record.revokedAt) throw new Error("credential revoked");
  return openSecret(
    { ciphertext: record.encryptedRefreshToken, keyVersion: record.encryptionKeyVersion },
    kp,
  );
}

/** Cryptographically destroy the stored secret and mark revoked. */
export function revokeMailCredential(
  connectionId: string,
  scope: TenantScope,
  now: () => string = () => new Date().toISOString(),
): void {
  const record = getMailCredential(connectionId, scope);
  if (!record) return;
  store.set(connectionId, {
    ...record,
    encryptedRefreshToken: "DESTROYED", // ciphertext gone; cannot be decrypted
    revokedAt: now(),
  });
}

export function deleteMailCredential(connectionId: string): void {
  store.delete(connectionId);
}

export function clearMailCredentials(): void {
  store.clear();
}
