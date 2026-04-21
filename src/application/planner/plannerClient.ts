import OpenAI from "openai";
import type {
  PlannerRequest,
  PlannerResponse,
  PlannerTelemetry,
} from "@aaliyah/contracts/v1";
import {
  PlannerResponseSchema,
  PlannerTelemetrySchema,
} from "@aaliyah/contracts/v1";
import { ZodError } from "zod";

import { logger } from "../../observability/logger";

type PlannerClientResult = {
  response: PlannerResponse;
  telemetry: PlannerTelemetry;
};

type FallbackReason =
  | "unconfigured_client"
  | "timeout"
  | "invalid_json"
  | "schema_validation_failed"
  | "provider_error";

export const plannerClientInternals = {
  buildClient: () =>
    new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    }),
  now: () => Date.now(),
};

function ensureEnv(): void {
  if (!process.env.OPENAI_API_KEY) {
    throw new Error("unconfigured_client");
  }
}

function buildPrompt(request: PlannerRequest): string {
  return [
    "You are Aaliyah Planner.",
    "Return only valid JSON matching the PlannerResponse schema.",
    "Generate multiple viable candidates for the task.",
    "Include one conservative/dissenting option when policy requires it.",
    "Do not invent evidence references outside the provided evidence bundle.",
    "",
    `TASK: ${JSON.stringify(request.task)}`,
    `POLICY: ${JSON.stringify(request.policy)}`,
    `TOOLS: ${JSON.stringify(request.availableTools)}`,
    `EVIDENCE_BUNDLE_ID: ${request.evidenceBundleId ?? "none"}`,
  ].join("\n");
}

function fallbackResponse(request: PlannerRequest): PlannerResponse {
  return {
    plannerVersion: "deterministic-fallback-v1",
    candidates: [
      {
        name: "fallback_candidate",
        description: `Fallback candidate for ${request.task.taskType}`,
        args: {
          requestedOutcome: request.task.requestedOutcome,
        },
        rationale:
          "Fallback deterministic plan due to unavailable or invalid planner provider output.",
        evidenceRefs: request.evidenceBundleId
          ? [
              {
                sourceId: request.evidenceBundleId,
                rationale: "Using available evidence bundle",
              },
            ]
          : [
              {
                sourceId: "none",
                rationale: "No evidence bundle available",
              },
            ],
        goalFit: 78,
        evidenceQuality: 70,
        policyFit: 90,
        expectedValue: 60,
        reversibility: 85,
        downsideRisk: 15,
        ambiguity: 20,
        contradictions: 0,
        blockers: [],
      },
    ],
    rejectedAlternatives: [],
  };
}

function classifyFallbackReason(error: unknown): FallbackReason {
  if (error instanceof Error && error.message === "unconfigured_client") {
    return "unconfigured_client";
  }

  if (error instanceof Error && /timeout/i.test(error.message)) {
    return "timeout";
  }

  if (error instanceof SyntaxError) {
    return "invalid_json";
  }

  if (error instanceof Error && /schema/i.test(error.message)) {
    return "schema_validation_failed";
  }

  if (error instanceof ZodError) {
    return "schema_validation_failed";
  }

  return "provider_error";
}

export async function plannerClient(
  request: PlannerRequest,
): Promise<PlannerClientResult> {
  const start = plannerClientInternals.now();

  try {
    ensureEnv();

    const client = plannerClientInternals.buildClient();
    const response = await client.responses.create({
      model: process.env.AALIYAH_PLANNER_MODEL ?? "gpt-5",
      input: buildPrompt(request),
      text: {
        format: {
          type: "json_schema",
          name: "planner_response",
          strict: true,
          schema: {
            type: "object",
            additionalProperties: false,
            properties: {
              plannerVersion: { type: "string" },
              candidates: {
                type: "array",
                minItems: 1,
                items: {
                  type: "object",
                  additionalProperties: false,
                  properties: {
                    name: { type: "string" },
                    description: { type: "string" },
                    args: {
                      type: "object",
                      additionalProperties: true,
                    },
                    rationale: { type: "string" },
                    evidenceRefs: {
                      type: "array",
                      minItems: 1,
                      items: {
                        type: "object",
                        additionalProperties: false,
                        properties: {
                          sourceId: { type: "string" },
                          rationale: { type: "string" },
                        },
                        required: ["sourceId", "rationale"],
                      },
                    },
                    goalFit: { type: "number" },
                    evidenceQuality: { type: "number" },
                    policyFit: { type: "number" },
                    expectedValue: { type: "number" },
                    reversibility: { type: "number" },
                    downsideRisk: { type: "number" },
                    ambiguity: { type: "number" },
                    contradictions: { type: "integer" },
                    blockers: {
                      type: "array",
                      items: { type: "string" },
                    },
                  },
                  required: [
                    "name",
                    "description",
                    "args",
                    "rationale",
                    "evidenceRefs",
                    "goalFit",
                    "evidenceQuality",
                    "policyFit",
                    "expectedValue",
                    "reversibility",
                    "downsideRisk",
                    "ambiguity",
                    "contradictions",
                    "blockers",
                  ],
                },
              },
              rejectedAlternatives: {
                type: "array",
                items: {
                  type: "object",
                  additionalProperties: false,
                  properties: {
                    name: { type: "string" },
                    reason: { type: "string" },
                  },
                  required: ["name", "reason"],
                },
              },
            },
            required: ["plannerVersion", "candidates", "rejectedAlternatives"],
          },
        },
      },
    });

    const raw = response.output_text;
    const parsed = JSON.parse(raw);
    const plannerResponse = PlannerResponseSchema.parse(parsed);

    const telemetry = PlannerTelemetrySchema.parse({
      plannerMode: "llm_primary",
      plannerProvider: "openai",
      fallbackReason: "none",
      latencyMs: plannerClientInternals.now() - start,
      candidateCount: plannerResponse.candidates.length,
    });

    return {
      response: plannerResponse,
      telemetry,
    };
  } catch (error) {
    logger.warn({ err: error }, "planner.provider.failed");

    const fallback = fallbackResponse(request);

    const telemetry = PlannerTelemetrySchema.parse({
      plannerMode: "deterministic_fallback",
      plannerProvider: "openai",
      fallbackReason: classifyFallbackReason(error),
      latencyMs: plannerClientInternals.now() - start,
      candidateCount: fallback.candidates.length,
    });

    return {
      response: fallback,
      telemetry,
    };
  }
}
