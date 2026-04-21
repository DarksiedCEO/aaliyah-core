import crypto from "node:crypto";
import type {
  ExecutionResult,
  PlannerPolicy,
  PlannerRequest,
} from "@aaliyah/contracts/v1";
import { PlannerPolicySchema, TaskEnvelopeSchema } from "@aaliyah/contracts/v1";

import { logger } from "../../observability/logger";
import { emitMetric } from "../../observability/metrics";
import { persistTrace } from "../../observability/persistTrace";
import { executeIdempotent } from "../../services/executeIdempotent";
import { escalateForReview } from "../../services/escalateForReview";
import { recoverOrEscalate } from "../../services/recoverOrEscalate";
import { requestApproval } from "../../services/requestApproval";
import { scopeTask } from "../../services/scopeTask";
import { selectCandidate } from "../../services/selectCandidate";
import { handleFailure } from "../../services/handleFailure";
import { verifyCandidate } from "../../services/verifyCandidate";
import { verifyPostconditions } from "../../services/verifyPostconditions";
import { requiresApproval } from "./requiresApproval";
import {
  assertEvidenceQuality,
  buildEvidence,
  defaultEvidenceRankingPolicy,
} from "../../services/buildEvidence";
import {
  ensureIdempotentExecution,
  recordIdempotentFailure,
  recordIdempotentResult,
} from "../../persistence/idempotencyStore";
import { rankEvidenceSources } from "../../ranking/rankEvidenceSources";
import { plannerClient } from "../planner/plannerClient";

function defaultPlannerPolicy(): PlannerPolicy {
  return PlannerPolicySchema.parse({
    planningMode: "multi_option",
    maxCandidates: 3,
    requireEvidenceForAllCandidates: true,
    requireDissentCandidate: true,
    minimumScoreThreshold: 75,
    minimumMarginThreshold: 8,
  });
}

function shadowModeEnabled(): boolean {
  return process.env.AALIYAH_SHADOW_MODE === "true";
}

async function buildEvidenceWithPolicy(
  task: ReturnType<typeof TaskEnvelopeSchema.parse>,
  scope: Awaited<ReturnType<typeof scopeTask>>,
): Promise<Awaited<ReturnType<typeof buildEvidence>>> {
  try {
    const evidence = await buildEvidence(scope);
    assertEvidenceQuality(evidence, task.riskTier);
    return evidence;
  } catch (error) {
    const action = handleFailure(
      error instanceof Error ? error : new Error("unknown failure"),
    );

    if (action === "retry") {
      const evidence = await buildEvidence(scope);
      assertEvidenceQuality(evidence, task.riskTier);
      return evidence;
    }

    throw error;
  }
}

export async function runAaliyahTask(raw: unknown): Promise<ExecutionResult> {
  const task = TaskEnvelopeSchema.parse(raw);
  const executionId = crypto.randomUUID();
  const idempotency = await ensureIdempotentExecution<ExecutionResult & {
    plannerTelemetry?: unknown;
  }>(task.taskId, task, task.taskType);

  if (idempotency.replay && idempotency.result) {
    logger.info({ taskId: task.taskId }, "aaliyah.task.replayed");
    return idempotency.result;
  }

  try {
    logger.info(
      {
        taskId: task.taskId,
        tenantId: task.tenantId,
        taskType: task.taskType,
        riskTier: task.riskTier,
      },
      "aaliyah.task.received",
    );

    const scope = await scopeTask(task);
    const evidence = await buildEvidenceWithPolicy(task, scope);

    const evidenceRankingPolicy = defaultEvidenceRankingPolicy();
    const rankedEvidence = rankEvidenceSources(evidence, evidenceRankingPolicy);

    const plannerRequest: PlannerRequest = {
      task,
      policy: defaultPlannerPolicy(),
      availableTools: [],
      evidenceBundleId: evidence.bundleId,
    };

    const { response: plannerResponse, telemetry } = await plannerClient(plannerRequest);

    emitMetric("planner_latency_ms", telemetry.latencyMs, {
      planner_mode: telemetry.plannerMode,
      planner_provider: telemetry.plannerProvider,
      fallback_reason: telemetry.fallbackReason,
    });

    emitMetric("planner_candidate_count", telemetry.candidateCount, {
      planner_mode: telemetry.plannerMode,
    });

    const { ranked, top, margin } = selectCandidate(plannerResponse.candidates);

    const verification = await verifyCandidate({
      task,
      scope,
      evidence,
      candidate: top.candidate,
      score: top.score,
      margin,
    });

    if (!verification.pass) {
      const escalated = await escalateForReview(task, verification);
      const responseWithTelemetry = {
        ...escalated,
        plannerTelemetry: telemetry,
      };

      await persistTrace({
        task,
        scope,
        evidence,
        executionId,
        idempotencyKey: task.taskId,
        tenantId: task.tenantId,
        userId: task.userId,
        rankedEvidence,
        plannerRequest,
        plannerResponse,
        plannerTelemetry: telemetry,
        selectedCandidate: top.candidate,
        rejectedCandidates: ranked.slice(1).map((entry) => entry.candidate),
        evidenceSnapshot: evidence.sources,
        failureMode: "verification_failed",
        decisionPath: "verification -> escalation",
        approvalState: responseWithTelemetry.approvalState,
        ranked,
        verification,
        outcome: responseWithTelemetry,
      });

      await recordIdempotentResult(task.taskId, responseWithTelemetry);
      return responseWithTelemetry;
    }

    if (requiresApproval(task.riskTier, top.score, margin)) {
      const approval = await requestApproval(task, top.candidate, verification);
      const responseWithTelemetry = {
        ...approval,
        plannerTelemetry: telemetry,
      };

      await persistTrace({
        task,
        scope,
        evidence,
        executionId,
        idempotencyKey: task.taskId,
        tenantId: task.tenantId,
        userId: task.userId,
        rankedEvidence,
        plannerRequest,
        plannerResponse,
        plannerTelemetry: telemetry,
        selectedCandidate: top.candidate,
        rejectedCandidates: ranked.slice(1).map((entry) => entry.candidate),
        evidenceSnapshot: evidence.sources,
        failureMode: "approval_required",
        decisionPath: "policy -> approval",
        approvalState: responseWithTelemetry.approvalState,
        ranked,
        verification,
        outcome: responseWithTelemetry,
      });

      await recordIdempotentResult(task.taskId, responseWithTelemetry);
      return responseWithTelemetry;
    }

    if (shadowModeEnabled()) {
      const shadowResult = {
        success: false,
        taskId: task.taskId,
        idempotencyKey: task.taskId,
        approvalState: "not_required" as const,
        externalRefs: [`shadow:${top.candidate.name}`],
        postconditionsMet: false,
        escalated: false,
        message: `Shadow mode predicted action: ${top.candidate.name}`,
        plannerTelemetry: telemetry,
      };

      logger.info(
        {
          taskId: task.taskId,
          predictedAction: top.candidate.name,
        },
        "aaliyah.task.shadow_mode",
      );

      await persistTrace({
        task,
        scope,
        evidence,
        executionId,
        idempotencyKey: task.taskId,
        tenantId: task.tenantId,
        userId: task.userId,
        rankedEvidence,
        plannerRequest,
        plannerResponse,
        plannerTelemetry: telemetry,
        selectedCandidate: top.candidate,
        rejectedCandidates: ranked.slice(1).map((entry) => entry.candidate),
        evidenceSnapshot: evidence.sources,
        failureMode: "shadow_mode_skip",
        decisionPath: "shadow_mode -> execution_skipped",
        approvalState: shadowResult.approvalState,
        ranked,
        verification,
        outcome: shadowResult,
      });

      await recordIdempotentResult(task.taskId, shadowResult);
      return shadowResult;
    }

    const execution = await executeIdempotent(top.candidate, {
      taskId: task.taskId,
      idempotencyKey: task.taskId,
    });

    const postconditionsMet = await verifyPostconditions(task, execution);
    const finalResult: ExecutionResult = {
      ...execution,
      postconditionsMet,
    };
    const finalResultWithTelemetry = {
      ...finalResult,
      plannerTelemetry: telemetry,
    };

    await persistTrace({
      task,
      scope,
      evidence,
      executionId,
      idempotencyKey: task.taskId,
      tenantId: task.tenantId,
      userId: task.userId,
      rankedEvidence,
      plannerRequest,
      plannerResponse,
      plannerTelemetry: telemetry,
      selectedCandidate: top.candidate,
      rejectedCandidates: ranked.slice(1).map((entry) => entry.candidate),
      evidenceSnapshot: evidence.sources,
      failureMode: postconditionsMet ? "none" : "postcondition_failed",
      decisionPath: postconditionsMet ? "execution -> completed" : "execution -> recovery",
      approvalState: finalResultWithTelemetry.approvalState,
      ranked,
      verification,
      outcome: finalResultWithTelemetry,
    });

    if (!postconditionsMet) {
      const recovered = await recoverOrEscalate(task, finalResult);
      const recoveredWithTelemetry = {
        ...recovered,
        plannerTelemetry: telemetry,
      };

      await recordIdempotentResult(task.taskId, recoveredWithTelemetry);
      return recoveredWithTelemetry;
    }

    await recordIdempotentResult(task.taskId, finalResultWithTelemetry);
    logger.info({ taskId: task.taskId }, "aaliyah.task.completed");
    return finalResultWithTelemetry;
  } catch (error) {
    await recordIdempotentFailure(
      task.taskId,
      error instanceof Error ? error.message : "unknown error",
    );
    throw error;
  }
}
