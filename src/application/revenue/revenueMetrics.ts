import type { TenantScope } from "../../persistence/tenantScopedStore";
import { latestRevenueByThread } from "./revenueStore";

export type RevenueSummary = {
  threadCount: number;
  averageOpportunityScore: number | null;
  averageRevenueRiskScore: number | null;
  highRiskThreads: number; // revenueRiskScore >= 50
};

/**
 * Read-only revenue summary for monitoring. Reads scoped signals; it never
 * alters the frozen monitoring gate math.
 */
export async function summarizeRevenue(scope: TenantScope): Promise<RevenueSummary> {
  const latest = [...(await latestRevenueByThread(scope)).values()];
  if (latest.length === 0) {
    return {
      threadCount: 0,
      averageOpportunityScore: null,
      averageRevenueRiskScore: null,
      highRiskThreads: 0,
    };
  }

  const avg = (pick: (s: (typeof latest)[number]) => number): number =>
    latest.reduce((sum, s) => sum + pick(s), 0) / latest.length;

  return {
    threadCount: latest.length,
    averageOpportunityScore: avg((s) => s.opportunityScore),
    averageRevenueRiskScore: avg((s) => s.revenueRiskScore),
    highRiskThreads: latest.filter((s) => s.revenueRiskScore >= 50).length,
  };
}
