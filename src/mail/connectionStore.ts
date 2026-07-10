import type { MailboxConnection } from "@aaliyah/contracts/v1";

import type { TenantScope } from "../persistence/tenantScopedStore";

// Non-secret connection metadata (secrets live in the credential vault).
const store = new Map<string, MailboxConnection>();

export function saveConnection(conn: MailboxConnection): MailboxConnection {
  store.set(conn.connectionId, conn);
  return conn;
}

export function getConnection(
  connectionId: string,
  scope: TenantScope,
): MailboxConnection | undefined {
  const conn = store.get(connectionId);
  if (!conn) return undefined;
  if (conn.tenantId !== scope.tenantId || conn.workspaceId !== scope.workspaceId) {
    return undefined; // cross-tenant access denied
  }
  return conn;
}

export function deleteConnection(connectionId: string): void {
  store.delete(connectionId);
}

export function clearConnections(): void {
  store.clear();
}
