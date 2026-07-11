import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before } from "node:test";

import { computeRevenueSignals } from "../src/application/revenue/revenueScoring";
import {
  saveRevenueSignals,
  latestRevenueByThread,
} from "../src/application/revenue/revenueStore";
import { summarizeRevenue } from "../src/application/revenue/revenueMetrics";

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(
    path.join(os.tmpdir(), "aaliyah-revenue-"),
  );
});

const A = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };
const NOW = () => "2026-06-23T12:00:00.000Z";

test("revenue scoring is deterministic and bounded 0-100", () => {
  const hot = computeRevenueSignals(
    A,
    { threadId: "t1", isFromKnownLead: true, mentionsPricing: true, mentionsBudget: true, mentionsContract: true, inboundCount: 3, daysSinceLastReply: 4 },
    NOW,
  );
  const cold = computeRevenueSignals(A, { threadId: "t2" }, NOW);

  for (const s of [hot, cold]) {
    for (const v of [s.leadScore, s.dealScore, s.opportunityScore, s.followupPriority, s.revenueRiskScore, s.responseValueScore]) {
      assert.ok(v >= 0 && v <= 100);
    }
  }
  // Hot lead scores strictly higher opportunity than a cold cold-open.
  assert.ok(hot.opportunityScore > cold.opportunityScore);
  // Deterministic: same inputs -> same output.
  const again = computeRevenueSignals(A, { threadId: "t1", isFromKnownLead: true, mentionsPricing: true, mentionsBudget: true, mentionsContract: true, inboundCount: 3, daysSinceLastReply: 4 }, NOW);
  assert.deepEqual(again, hot);
});

test("revenue risk rises when a valuable opportunity goes stale", () => {
  const fresh = computeRevenueSignals(A, { threadId: "t3", isFromKnownLead: true, mentionsContract: true, daysSinceLastReply: 0 }, NOW);
  const stale = computeRevenueSignals(A, { threadId: "t3", isFromKnownLead: true, mentionsContract: true, daysSinceLastReply: 8 }, NOW);
  assert.ok(stale.revenueRiskScore > fresh.revenueRiskScore);
});

test("revenue signals persist and summarize, scoped per tenant", () => {
  saveRevenueSignals(computeRevenueSignals(A, { threadId: "t10", isFromKnownLead: true, mentionsPricing: true, mentionsBudget: true, mentionsContract: true, daysSinceLastReply: 9 }, NOW));
  saveRevenueSignals(computeRevenueSignals(A, { threadId: "t11" }, NOW));
  saveRevenueSignals(computeRevenueSignals(B, { threadId: "t12", isFromKnownLead: true }, NOW));

  const summaryA = summarizeRevenue(A);
  assert.equal(summaryA.threadCount, 2);
  assert.ok(summaryA.averageOpportunityScore !== null);
  assert.ok(summaryA.highRiskThreads >= 1);

  // Scoped — tenant_b's thread is not in tenant_a's summary.
  assert.equal(summarizeRevenue(B).threadCount, 1);
  assert.ok(!latestRevenueByThread(A).has("t12"));
});
