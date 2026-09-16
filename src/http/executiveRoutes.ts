import express from "express";
import { z } from "zod";

import { runEaPipeline, type EaDeps } from "../application/executive/eaPipeline";
import type { Wave1MemoryService } from "../application/memory/wave1MemoryService";
import type { TrustedMemoryActor } from "../application/memory/wave1TrustedMemory";
import {
  CsrfError,
  authenticateRequest,
  type MailAuthDeps,
} from "./mailRoutes";

/**
 * W1BR-016 — THE INBOUND ROUTE THAT ACTUALLY ENTERS THE TRUSTED-MEMORY CHAIN.
 *
 * Before this, the chain was proven end to end and could not be ENTERED: the
 * store and the reconciler were composed at boot, `runEaPipeline` read
 * authoritative memory, and nothing but a test ever called the pipeline.
 * "Reachable only from a test" is not reachable, so item 4 of W1.3 was
 * reported open rather than described as wired.
 *
 * WHAT THIS ROUTE DOES AND DOES NOT DO. It triages an inbound message, decides
 * authority deterministically, and MAY produce a draft for review. It sends
 * nothing. There is no send path here and there is no approval here — a draft
 * is a proposal, and turning one into an outbound message is W1.6 authority
 * work behind its own approval gate.
 *
 * THE MEMORY SERVICE IS REQUIRED, NOT OPTIONAL, ON THIS ROUTE. The pipeline
 * treats memory as optional because a deployment with no durable state has
 * none to read. A deployment serving HTTP has durable state by definition, so
 * mounting this route without a memory service would silently draft with no
 * memory and look identical to a contact nobody has met.
 */

/**
 * DISCLOSED IDENTITY MAPPING (W1BR-017).
 *
 * Trusted memory scopes on four dimensions: tenant, workspace, principal and
 * user. An authenticated `Principal` carries three of them — there is no
 * `principalId` anywhere in Core outside the memory layer.
 *
 * This maps `principalId` to the authenticated user's own id: in Wave 1 the
 * human acts as their own memory principal. That is a DEPLOYMENT FACT, not a
 * weakening — the store still compares all four dimensions independently and
 * every control over them is unchanged; both simply carry the same value here.
 * A distinct assistant principal, acting on a user's behalf, is not yet
 * modelled anywhere, and inventing a namespace for one inside an HTTP handler
 * is exactly the kind of quiet identity decision that should not be made in an
 * HTTP handler.
 */
export function memoryActorFor(input: {
  tenantId: string;
  userId: string;
  workspaceId: string;
}): TrustedMemoryActor {
  return {
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    principalId: input.userId,
    userId: input.userId,
  };
}

const InboundRequestSchema = z.strictObject({
  workspaceId: z.string().min(1).max(128),
  /**
   * Observed mail headers. They are FACTS ABOUT THE MESSAGE the caller saw,
   * not a judgement, so they come from the request rather than being invented
   * here — a hardcoded `false` would silently claim every message lacked an
   * unsubscribe header and defeat the free deterministic filter that exists to
   * keep bulk mail away from the model entirely.
   */
  signals: z
    .strictObject({
      listUnsubscribe: z.boolean(),
      precedenceBulk: z.boolean(),
    })
    .optional(),
  email: z.strictObject({
    messageId: z.string().min(1).max(998),
    threadId: z.string().min(1).max(998),
    fromEmail: z.string().min(3).max(254),
    subject: z.string().max(998),
    body: z.string().max(200_000),
    receivedAt: z.string().datetime(),
    toEmail: z.string().min(3).max(254).optional(),
  }),
});

export type ExecutiveRoutesDeps = {
  auth: MailAuthDeps;
  memory: Wave1MemoryService;
  /** Routers and profile. Injected so a deployment without them mounts nothing. */
  pipeline: Omit<EaDeps, "memory">;
};

export function createExecutiveRouter(
  deps: ExecutiveRoutesDeps,
): express.Router {
  const router = express.Router();

  router.post("/executive/inbound/draft", async (req, res) => {
    let principal;
    try {
      principal = await authenticateRequest(req, deps.auth);
    } catch (error) {
      if (error instanceof CsrfError) {
        res.status(403).json({ error: "csrf_failed" });
        return;
      }
      throw error;
    }
    // FAIL CLOSED. No principal, no chain.
    if (principal === null) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }
    if (principal.actorType !== "user") {
      // A service principal has no executive memory of its own to read.
      res.status(403).json({ error: "user_principal_required" });
      return;
    }

    const parsed = InboundRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "malformed_request" });
      return;
    }

    // THE WORKSPACE IS AUTHORIZED, NOT ACCEPTED. A caller naming a workspace
    // they are not a member of would otherwise read another workspace's
    // memory, which is the whole boundary the store scopes on.
    if (!principal.workspaceIds.includes(parsed.data.workspaceId)) {
      res.status(403).json({ error: "workspace_forbidden" });
      return;
    }

    const actor = memoryActorFor({
      tenantId: principal.tenantId,
      userId: principal.userId,
      workspaceId: parsed.data.workspaceId,
    });

    const outcome = await runEaPipeline(
      { ...deps.pipeline, memory: { service: deps.memory, actor } },
      {
        email: parsed.data.email,
        signals: parsed.data.signals ?? {
          listUnsubscribe: false,
          precedenceBulk: false,
        },
      },
    );

    res.status(200).json({
      category: outcome.category,
      risk: outcome.risk,
      action: outcome.action,
      reason: outcome.reason,
      degraded: outcome.degraded,
      cautionMarker: outcome.cautionMarker,
      // The draft is a PROPOSAL. Nothing here sends it.
      ...(outcome.draft ? { draft: outcome.draft } : {}),
      // Memory provenance, reported rather than folded into the answer: a
      // caller must be able to tell "this contact is not in memory" from
      // "memory could not be consulted", and to see when an alias resolved
      // through a merge rather than directly.
      memory: outcome.memory
        ? {
            canonicalRecordId: outcome.memory.canonicalRecordId,
            resolvedFrom: outcome.memory.resolvedFrom,
          }
        : null,
      memoryUnavailable: outcome.memoryUnavailable === true,
    });
  });

  return router;
}
