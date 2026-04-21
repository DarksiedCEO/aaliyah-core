import assert from "node:assert/strict";
import test, { mock } from "node:test";

import {
  plannerClient,
  plannerClientInternals,
} from "../src/application/planner/plannerClient";

process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY = "true";

const request = {
  task: {
    taskId: "550e8400-e29b-41d4-a716-446655440100",
    tenantId: "tenant_123",
    userId: "user_123",
    taskType: "decision" as const,
    riskTier: "A1_DRAFT" as const,
    requestedOutcome: "Choose the next action",
    inputs: {},
    constraints: [],
    requiredSources: [],
    createdAt: "2026-04-18T12:00:00.000Z",
  },
  policy: {
    planningMode: "multi_option" as const,
    maxCandidates: 2,
    requireEvidenceForAllCandidates: true,
    requireDissentCandidate: true,
    minimumScoreThreshold: 75,
    minimumMarginThreshold: 8,
  },
  availableTools: [],
};

test("plannerClient falls back when client is unconfigured", async () => {
  const originalKey = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;

  const result = await plannerClient(request);

  assert.equal(result.telemetry.fallbackReason, "unconfigured_client");
  assert.equal(result.telemetry.plannerMode, "deterministic_fallback");
  assert.equal(result.response.candidates.length, 1);

  process.env.OPENAI_API_KEY = originalKey;
});

test("plannerClient classifies invalid structured output", async () => {
  const originalKey = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = "test-key";

  const restore = mock.method(plannerClientInternals, "buildClient", () => ({
    responses: {
      create: async () => ({ output_text: "{bad json" }),
    },
  }) as never);

  const result = await plannerClient(request);

  assert.equal(result.telemetry.fallbackReason, "invalid_json");
  restore.mock.restore();
  process.env.OPENAI_API_KEY = originalKey;
});

test("plannerClient classifies schema validation failure", async () => {
  const originalKey = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = "test-key";

  const restore = mock.method(plannerClientInternals, "buildClient", () => ({
    responses: {
      create: async () => ({
        output_text: JSON.stringify({
          plannerVersion: "v1",
          candidates: [],
          rejectedAlternatives: [],
        }),
      }),
    },
  }) as never);

  const result = await plannerClient(request);

  assert.equal(result.telemetry.fallbackReason, "schema_validation_failed");
  restore.mock.restore();
  process.env.OPENAI_API_KEY = originalKey;
});

test("plannerClient classifies timeout failures", async () => {
  const originalKey = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = "test-key";

  const restore = mock.method(plannerClientInternals, "buildClient", () => ({
    responses: {
      create: async () => {
        throw new Error("request timeout");
      },
    },
  }) as never);

  const result = await plannerClient(request);

  assert.equal(result.telemetry.fallbackReason, "timeout");
  restore.mock.restore();
  process.env.OPENAI_API_KEY = originalKey;
});

test("plannerClient returns provider results when schema output is valid", async () => {
  const originalKey = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = "test-key";

  const restore = mock.method(plannerClientInternals, "buildClient", () => ({
    responses: {
      create: async () => ({
        output_text: JSON.stringify({
          plannerVersion: "v1",
          candidates: [
            {
              name: "provider_candidate",
              description: "Provider output",
              args: {},
              rationale: "Best option",
              evidenceRefs: [
                {
                  sourceId: "bundle:1",
                  rationale: "Provided evidence bundle",
                },
              ],
              goalFit: 90,
              evidenceQuality: 88,
              policyFit: 92,
              expectedValue: 80,
              reversibility: 85,
              downsideRisk: 15,
              ambiguity: 10,
              contradictions: 0,
              blockers: [],
            },
          ],
          rejectedAlternatives: [],
        }),
      }),
    },
  }) as never);

  const result = await plannerClient(request);

  assert.equal(result.telemetry.plannerMode, "llm_primary");
  assert.equal(result.telemetry.fallbackReason, "none");
  assert.equal(result.response.candidates[0]?.name, "provider_candidate");
  restore.mock.restore();
  process.env.OPENAI_API_KEY = originalKey;
});
