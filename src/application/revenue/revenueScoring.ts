import { z } from "zod";

import {
  RevenueSignalInputSchema,
  RevenueSignalsSchema,
  type RevenueSignals,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";

const clamp = (n: number): number => Math.max(0, Math.min(100, Math.round(n)));

/**
 * Deterministic revenue-signal scorer. Transparent formulas over thread
 * features — no learning, no model dependency, no decision-making. The output
 * is pure metadata that downstream UIs/monitoring may surface.
 */
export function computeRevenueSignals(
  scope: TenantScope,
  rawInput: z.input<typeof RevenueSignalInputSchema>,
  now: () => string = () => new Date().toISOString(),
): RevenueSignals {
  const input = RevenueSignalInputSchema.parse(rawInput);

  const leadScore = clamp(
    (input.isFromKnownLead ? 50 : 20) +
      (input.mentionsPricing ? 15 : 0) +
      (input.mentionsBudget ? 15 : 0) +
      Math.min(input.inboundCount * 5, 20),
  );

  const dealScore = clamp(
    (input.mentionsPricing ? 30 : 0) +
      (input.mentionsBudget ? 25 : 0) +
      (input.mentionsContract ? 35 : 0) +
      (input.isFromKnownLead ? 10 : 0),
  );

  const opportunityScore = clamp(0.5 * leadScore + 0.5 * dealScore);

  // Staleness pressure rises with days since last reply, capped.
  const staleness = clamp(input.daysSinceLastReply * 12);

  const followupPriority = clamp(0.6 * opportunityScore + 0.4 * staleness);

  // Risk = valuable opportunity going cold.
  const revenueRiskScore = clamp((opportunityScore / 100) * staleness);

  const responseValueScore = clamp(
    0.7 * opportunityScore + 0.3 * Math.min(input.inboundCount * 10, 30),
  );

  return RevenueSignalsSchema.parse({
    tenantId: scope.tenantId,
    workspaceId: scope.workspaceId,
    threadId: input.threadId,
    leadScore,
    dealScore,
    opportunityScore,
    followupPriority,
    revenueRiskScore,
    responseValueScore,
    computedAt: now(),
  });
}
