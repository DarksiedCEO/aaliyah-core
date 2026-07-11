type TenantScopedRecord = {
  tenantId: string;
  workspaceId?: string;
};

/**
 * Fail-closed read boundary. Asserts every record belongs to the expected
 * tenant and, when an `expectedWorkspaceId` is supplied, the expected
 * workspace. The workspace check is opt-in so existing tenant-only callers are
 * unaffected during the migration window.
 */
export function enforceTenantBoundary<T extends TenantScopedRecord>(
  expectedTenantId: string,
  records: T[],
  expectedWorkspaceId?: string,
): T[] {
  const invalid = records.find(
    (record) =>
      record.tenantId !== expectedTenantId ||
      (expectedWorkspaceId !== undefined &&
        record.workspaceId !== expectedWorkspaceId),
  );

  if (invalid) {
    throw new Error("Tenant boundary violation detected");
  }

  return records;
}
