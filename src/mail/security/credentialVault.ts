import {
  envelopeOpen,
  envelopeSeal,
  type KmsKeyWrapper,
} from "../../crypto/envelopeEncryption";
import type { TenantScope } from "../../persistence/tenantScopedStore";
import type { DurableMailCredential } from "../../persistence/postgres/mailStateStore";
import type { MailStateBackend } from "../mailState";

// Refresh tokens rest ONLY as KMS envelopes (fresh data key per secret) —
// plaintext is never persisted, logged, or returned to a browser. Persistence
// lives behind MailStateBackend: Postgres in production, in-memory for tests.

export type VaultDeps = {
  store: MailStateBackend["credentials"];
  kms: KmsKeyWrapper;
};

export async function saveMailCredential(
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
  deps: VaultDeps,
): Promise<DurableMailCredential> {
  const credential: DurableMailCredential = {
    connectionId: input.connectionId,
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    provider: "google",
    envelope: envelopeSeal(input.refreshToken, deps.kms),
    grantedScopes: input.grantedScopes,
    connectedEmail: input.connectedEmail,
    accessTokenExpiresAt: input.accessTokenExpiresAt,
    revokedAt: null,
  };
  await deps.store.save(credential);
  return credential;
}

/** Tenant-scoped read — returns nothing if the record belongs to another tenant. */
export async function getMailCredential(
  connectionId: string,
  scope: TenantScope,
  deps: VaultDeps,
): Promise<DurableMailCredential | null> {
  return deps.store.get(connectionId, scope);
}

/** Decrypt the refresh token for use (never returned to a browser/log). */
export async function openRefreshToken(
  connectionId: string,
  scope: TenantScope,
  deps: VaultDeps,
): Promise<string> {
  const record = await deps.store.get(connectionId, scope);
  if (!record) throw new Error("credential not found for scope");
  if (record.revokedAt) throw new Error("credential revoked");
  return envelopeOpen(record.envelope, deps.kms);
}

/** Cryptographically destroy the stored secret and mark revoked. */
export async function revokeMailCredential(
  connectionId: string,
  scope: TenantScope,
  deps: VaultDeps,
  now: () => string = () => new Date().toISOString(),
): Promise<void> {
  await deps.store.revoke(connectionId, scope, now);
}

export async function deleteMailCredential(
  connectionId: string,
  deps: VaultDeps,
): Promise<void> {
  await deps.store.delete(connectionId);
}
