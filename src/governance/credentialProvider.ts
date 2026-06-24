type CredentialStatus = "active" | "revoked" | "expired";

type CredentialRecord = {
  tenantId: string;
  workspaceId?: string;
  userId: string;
  provider: "google";
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  status: CredentialStatus;
  createdAt: number;
  updatedAt: number;
};

const store = new Map<string, CredentialRecord>();

/**
 * Credentials isolate on (tenant, user) by default — a Google identity belongs
 * to a user, not a workspace. A tenant that wants per-workspace connections may
 * pass `workspaceId` to narrow the key; omitting it preserves the legacy
 * tenant:user scope and keeps existing callers unchanged.
 */
function keyFor(
  tenantId: string,
  userId: string,
  provider: CredentialRecord["provider"],
  workspaceId?: string,
): string {
  return workspaceId
    ? `${tenantId}:${workspaceId}:${userId}:${provider}`
    : `${tenantId}:${userId}:${provider}`;
}

export function registerCredential(record: CredentialRecord): void {
  store.set(
    keyFor(record.tenantId, record.userId, record.provider, record.workspaceId),
    record,
  );
}

export function getCredential(
  tenantId: string,
  userId: string,
  provider: CredentialRecord["provider"],
  workspaceId?: string,
): CredentialRecord {
  const record = store.get(keyFor(tenantId, userId, provider, workspaceId));

  if (!record) {
    throw new Error("Missing credential");
  }

  if (record.status === "revoked") {
    throw new Error("Credential revoked");
  }

  if (record.expiresAt && record.expiresAt < Date.now()) {
    record.status = "expired";
    record.updatedAt = Date.now();
    throw new Error("Credential expired");
  }

  return record;
}

export function revokeCredential(
  tenantId: string,
  userId: string,
  provider: CredentialRecord["provider"],
  workspaceId?: string,
): void {
  const record = store.get(keyFor(tenantId, userId, provider, workspaceId));

  if (!record) {
    return;
  }

  record.status = "revoked";
  record.updatedAt = Date.now();
}

export function clearCredentials(): void {
  store.clear();
}
