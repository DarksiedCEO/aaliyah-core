type TenantScopedRecord = {
  tenantId: string;
};

export function enforceTenantBoundary<T extends TenantScopedRecord>(
  expectedTenantId: string,
  records: T[],
): T[] {
  const invalid = records.find((record) => record.tenantId !== expectedTenantId);

  if (invalid) {
    throw new Error("Tenant boundary violation detected");
  }

  return records;
}
