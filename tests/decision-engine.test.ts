import assert from "node:assert/strict";
import test, { afterEach } from "node:test";

import { runAaliyahTask } from "../src/application/decision-engine/runAaliyahTask";
import { requiresApproval } from "../src/application/decision-engine/requiresApproval";
import { scoreCandidate } from "../src/application/decision-engine/scoreCandidate";
import { planTask } from "../src/application/planner/planTask";
import { llmPlanner } from "../src/application/planner/llmPlanner";
import { plannerClient } from "../src/application/planner/plannerClient";
import { enforceTenantBoundary } from "../src/governance/enforceTenantBoundary";
import { rankEvidenceSources } from "../src/ranking/rankEvidenceSources";
import { buildEvidence, defaultEvidenceRankingPolicy } from "../src/services/buildEvidence";
import { detectContradictions } from "../src/services/detectContradictions";
import {
  ensureIdempotentExecution,
  idempotencyStoreInternals,
} from "../src/persistence/idempotencyStore";
import { retrieveEvidence } from "../src/services/retrieveEvidence";
import { selectCandidate } from "../src/services/selectCandidate";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

afterEach(() => {
  idempotencyStoreInternals.resetInMemory();
});

test("scoreCandidate rewards fit and penalizes risk", () => {
  const score = scoreCandidate({
    name: "candidate",
    description: "test",
    args: {},
    goalFit: 90,
    evidenceQuality: 85,
    policyFit: 95,
    expectedValue: 70,
    reversibility: 80,
    downsideRisk: 10,
    ambiguity: 15,
    contradictions: 0,
    blockers: [],
  });

  assert.equal(score, 75);
  assert.equal(requiresApproval("A4_IRREVERSIBLE", score, 40), true);
  assert.equal(requiresApproval("A0_READ", score, 40), false);
});

test("runAaliyahTask requests approval for risky writes", async () => {
  const result = await runAaliyahTask({
    taskId: "550e8400-e29b-41d4-a716-446655440000",
    tenantId: "tenant_123",
    userId: "user_123",
    taskType: "write",
    riskTier: "A2_WRITE_APPROVED",
    requestedOutcome: "Send an external message",
    inputs: {
      channel: "email",
    },
    requiredSources: ["source_123"],
    constraints: [],
    createdAt: "2026-04-18T12:00:00.000Z",
  });

  assert.equal(result.success, false);
  assert.equal(result.approvalState, "pending");
});

test("runAaliyahTask skips execution in shadow mode", async () => {
  process.env.AALIYAH_SHADOW_MODE = "true";

  try {
    const result = await runAaliyahTask({
      taskId: "550e8400-e29b-41d4-a716-446655440099",
      tenantId: "tenant_123",
      userId: "user_123",
      taskType: "decision",
      riskTier: "A1_DRAFT",
      requestedOutcome: "Recommend next action",
      inputs: {},
      requiredSources: [],
      constraints: [],
      createdAt: "2026-04-18T12:00:00.000Z",
    });

    assert.equal(result.success, false);
    assert.match(result.message, /Shadow mode predicted action/);
  } finally {
    delete process.env.AALIYAH_SHADOW_MODE;
  }
});

test("planner and ranking produce ranked candidates from evidence", async () => {
  const evidence = await buildEvidence({
    taskId: "550e8400-e29b-41d4-a716-446655440000",
    tenantId: "tenant_123",
    userId: "user_123",
    taskType: "decision",
    riskTier: "A1_DRAFT",
    requestedOutcome: "Choose the best next action",
    requiredSources: ["crm:account", "gmail:thread"],
    constraints: [],
  });

  const rankedEvidence = rankEvidenceSources(
    evidence,
    defaultEvidenceRankingPolicy(),
  );

  const plannerResponse = await planTask({
    request: {
      task: {
        taskId: "550e8400-e29b-41d4-a716-446655440000",
        tenantId: "tenant_123",
        userId: "user_123",
        taskType: "decision",
        riskTier: "A1_DRAFT",
        requestedOutcome: "Choose the best next action",
        inputs: {},
        constraints: [],
        requiredSources: ["crm:account", "gmail:thread"],
        createdAt: "2026-04-18T12:00:00.000Z",
      },
      policy: {
        planningMode: "multi_option",
        maxCandidates: 3,
        requireEvidenceForAllCandidates: true,
        requireDissentCandidate: true,
        minimumScoreThreshold: 75,
        minimumMarginThreshold: 8,
      },
      availableTools: [],
      evidenceBundleId: evidence.bundleId,
    },
    rankedEvidence,
  });

  const selection = selectCandidate(plannerResponse.candidates);

  assert.ok(rankedEvidence.length >= 1);
  assert.equal(rankedEvidence[0]?.source.sourceType, "workflow_state");
  assert.equal(plannerResponse.candidates.length, 2);
  assert.equal(selection.top.candidate.name, "primary_action");
  assert.ok(selection.margin >= 0);
});

test("llmPlanner falls back to deterministic planning when no client is wired", async () => {
  const response = await llmPlanner(
    {
      task: {
        taskId: "550e8400-e29b-41d4-a716-446655440002",
        tenantId: "tenant_123",
        userId: "user_123",
        taskType: "decision",
        riskTier: "A1_DRAFT",
        requestedOutcome: "Recommend the next move",
        inputs: {},
        constraints: [],
        requiredSources: [],
        createdAt: "2026-04-18T12:00:00.000Z",
      },
      policy: {
        planningMode: "multi_option",
        maxCandidates: 2,
        requireEvidenceForAllCandidates: true,
        requireDissentCandidate: true,
        minimumScoreThreshold: 75,
        minimumMarginThreshold: 8,
      },
      availableTools: [],
    },
    [],
  );

  assert.equal(response.plannerVersion, "v1");
  assert.equal(response.candidates.length, 2);
});

test("detectContradictions flags conflicting evidence excerpts", () => {
  const processed = detectContradictions([
    {
      sourceId: "1",
      sourceType: "manual",
      title: "Account status",
      excerpt: "Active",
      trustLevel: "high",
      freshness: "current",
      relevanceScore: 80,
      authorityScore: 80,
      recencyScore: 80,
      contradictionFlags: [],
      tags: [],
      retrievedAt: "2026-04-18T12:00:00.000Z",
    },
    {
      sourceId: "2",
      sourceType: "manual",
      title: "Account status",
      excerpt: "Suspended",
      trustLevel: "high",
      freshness: "current",
      relevanceScore: 80,
      authorityScore: 80,
      recencyScore: 80,
      contradictionFlags: [],
      tags: [],
      retrievedAt: "2026-04-18T12:00:00.000Z",
    },
  ]);

  assert.deepEqual(processed[0]?.contradictionFlags ?? [], []);
  assert.deepEqual(processed[1]?.contradictionFlags ?? [], ["content_mismatch"]);
});

test("plannerClient reports deterministic fallback telemetry when unconfigured", async () => {
  const result = await plannerClient({
    task: {
      taskId: "550e8400-e29b-41d4-a716-446655440010",
      tenantId: "tenant_123",
      userId: "user_123",
      taskType: "decision",
      riskTier: "A1_DRAFT",
      requestedOutcome: "Decide what to do next",
      inputs: {},
      constraints: [],
      requiredSources: [],
      createdAt: "2026-04-18T12:00:00.000Z",
    },
    policy: {
      planningMode: "multi_option",
      maxCandidates: 3,
      requireEvidenceForAllCandidates: true,
      requireDissentCandidate: true,
      minimumScoreThreshold: 75,
      minimumMarginThreshold: 8,
    },
    availableTools: [],
  });

  assert.equal(result.telemetry.plannerMode, "deterministic_fallback");
  assert.equal(result.telemetry.fallbackReason, "unconfigured_client");
  assert.equal(result.response.candidates.length, 1);
});

test("retrieveEvidence returns brokered evidence with a bundle id", async () => {
  const bundle = await retrieveEvidence({
    tenantId: "tenant_123",
    userId: "user_123",
    query: "Find latest client state",
    connectors: ["gmail", "calendar", "workflow_state"],
    limit: 10,
  });

  assert.equal(bundle.sourceCount, 1);
  assert.equal(bundle.sources[0]?.sourceType, "workflow_state");
  assert.match(bundle.bundleId, /^bundle:tenant_123:/);
});

test("ensureIdempotentExecution rejects duplicate in-progress requests", async () => {
  await ensureIdempotentExecution("idem-123", { action: "send" }, "write");

  await assert.rejects(
    () => ensureIdempotentExecution("idem-123", { action: "send" }, "write"),
    /Idempotent request already in progress/,
  );
});

test("enforceTenantBoundary rejects records from another tenant", () => {
  assert.throws(
    () =>
      enforceTenantBoundary("tenant_123", [
        { tenantId: "tenant_123" },
        { tenantId: "tenant_other" },
      ]),
    /Tenant boundary violation detected/,
  );
});
