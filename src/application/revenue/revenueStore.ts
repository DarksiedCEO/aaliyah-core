import { RevenueSignalsSchema, type RevenueSignals } from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";

const REVENUE_STORE = "revenue_signals";

/** Persist the latest revenue signals for a thread (append-only, scoped). */
export async function saveRevenueSignals(signals: RevenueSignals): Promise<RevenueSignals> {
  const parsed = RevenueSignalsSchema.parse(signals);
  const scope: TenantScope = {
    tenantId: parsed.tenantId,
    workspaceId: parsed.workspaceId,
  };
  await applicationStoreFromEnv().logs.append(REVENUE_STORE, scope, parsed);
  return parsed;
}

export async function listRevenueSignals(scope: TenantScope): Promise<RevenueSignals[]> {
  const rows = await applicationStoreFromEnv().logs.list(REVENUE_STORE, scope);
  return rows.map((r) => RevenueSignalsSchema.parse(r));
}

/** Latest signals per thread (most recent wins). */
export async function latestRevenueByThread(
  scope: TenantScope,
): Promise<Map<string, RevenueSignals>> {
  const map = new Map<string, RevenueSignals>();
  for (const s of await listRevenueSignals(scope)) {
    map.set(s.threadId, s);
  }
  return map;
}
