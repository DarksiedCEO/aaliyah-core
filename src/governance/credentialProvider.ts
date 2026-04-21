type CredentialStatus = "active" | "revoked" | "expired";

type CredentialRecord = {
  tenantId: string;
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

function keyFor(
  tenantId: string,
  userId: string,
  provider: CredentialRecord["provider"],
): string {
  return `${tenantId}:${userId}:${provider}`;
}

export function registerCredential(record: CredentialRecord): void {
  store.set(keyFor(record.tenantId, record.userId, record.provider), record);
}

export function getCredential(
  tenantId: string,
  userId: string,
  provider: CredentialRecord["provider"],
): CredentialRecord {
  const record = store.get(keyFor(tenantId, userId, provider));

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
): void {
  const record = store.get(keyFor(tenantId, userId, provider));

  if (!record) {
    return;
  }

  record.status = "revoked";
  record.updatedAt = Date.now();
}

export function clearCredentials(): void {
  store.clear();
}
