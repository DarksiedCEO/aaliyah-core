import fs from "node:fs";
import path from "node:path";

import { RevenueSignalsSchema, type RevenueSignals } from "@aaliyah/contracts/v1";

import {
  scopedJsonlPath,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

const FILE = "revenue-signals.jsonl";

/** Persist the latest revenue signals for a thread (append-only, scoped). */
export function saveRevenueSignals(signals: RevenueSignals): RevenueSignals {
  const parsed = RevenueSignalsSchema.parse(signals);
  const scope: TenantScope = {
    tenantId: parsed.tenantId,
    workspaceId: parsed.workspaceId,
  };
  const fp = scopedJsonlPath(FILE, scope);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.appendFileSync(fp, `${JSON.stringify(parsed)}\n`, "utf8");
  return parsed;
}

export function listRevenueSignals(scope: TenantScope): RevenueSignals[] {
  const fp = scopedJsonlPath(FILE, scope);
  if (!fs.existsSync(fp)) return [];
  return fs
    .readFileSync(fp, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => RevenueSignalsSchema.parse(JSON.parse(l)));
}

/** Latest signals per thread (most recent wins). */
export function latestRevenueByThread(
  scope: TenantScope,
): Map<string, RevenueSignals> {
  const map = new Map<string, RevenueSignals>();
  for (const s of listRevenueSignals(scope)) {
    map.set(s.threadId, s);
  }
  return map;
}
