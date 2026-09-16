import type { InboundEmail, ModelRouterRequest, NormalizedModelResponse } from "@aaliyah/contracts/v1";
import type { CeoProfile } from "./ceoProfile";
import { stage0SystemFilter, classifyInbound, type MailSignals, type TriageCategory, type RiskLevel } from "./triage";
import { decideAuthority, type EaAction } from "./authorityPolicy";
import { generateExecutiveDraft, DraftDegradedError, type ExecutiveDraft } from "./executiveDraft";
import type {
  ExecutiveMemoryContext,
  Wave1MemoryService,
} from "../memory/wave1MemoryService";
import type { TrustedMemoryActor } from "../memory/wave1TrustedMemory";

type MinimalRouter = { generate(req: ModelRouterRequest): Promise<NormalizedModelResponse> };

/**
 * TRUSTED MEMORY, REACHED FROM THE EXECUTIVE PATH.
 *
 * `memory` is OPTIONAL and that is not a convenience. A deployment with no
 * durable state has no authoritative memory to read, and the honest behaviour
 * there is to draft with none rather than to invent some. When it IS supplied,
 * the sender's address is resolved through the alias registry to a canonical
 * identity and the record is read from the authoritative store — the same
 * store every control in W1.3 was built around.
 *
 * WHAT A MEMORY FAILURE MUST NOT DO. It must not fabricate context and it must
 * not silently continue as though none existed: those are the same outcome to
 * a reader and only one of them is true. A failed read is surfaced on the
 * outcome as `memoryUnavailable`, so a caller can tell "this contact is not in
 * memory" from "memory could not be consulted".
 */
export type EaMemoryDeps = {
  service: Wave1MemoryService;
  actor: TrustedMemoryActor;
};

export type EaDeps = {
  triageRouter: MinimalRouter;
  draftRouter: MinimalRouter;
  profile: CeoProfile;
  memory?: EaMemoryDeps;
};
export type EaInput = { email: InboundEmail; signals: MailSignals };

export type EaOutcome = {
  category: TriageCategory;
  risk: RiskLevel;
  confidence: number;
  action: EaAction;
  reason: string;
  degraded: boolean;
  cautionMarker: boolean;
  draft?: ExecutiveDraft;
  /** The authoritative memory this outcome was built with, when there was any. */
  memory?: ExecutiveMemoryContext;
  /** True when memory was configured and could NOT be consulted. */
  memoryUnavailable?: boolean;
};

/** Lowercased, trimmed sender address. The registry stores normalized aliases. */
function senderAlias(email: InboundEmail): string | null {
  const from = typeof email.fromEmail === "string" ? email.fromEmail.trim() : "";
  if (from.length === 0) return null;
  // `Name <addr@example.com>` and a bare address are both ordinary inputs here.
  const angled = /<([^>]+)>/u.exec(from);
  const address = (angled?.[1] ?? from).trim().toLowerCase();
  return address.length >= 3 ? address : null;
}

export async function runEaPipeline(deps: EaDeps, input: EaInput): Promise<EaOutcome> {
  // Stage 0 — free deterministic filter.
  const stage0 = stage0SystemFilter(input.email, input.signals);
  const triage = stage0 ?? (await classifyInbound(deps.triageRouter, input.email));
  const degradedTriage = triage.degraded === true;

  // ---- THE AUTHORITATIVE MEMORY READ --------------------------------------
  // alias -> identity -> canonical identity -> trusted-memory record. Run
  // BEFORE the authority decision so that a memory outage is visible on every
  // outcome, not only on the ones that go on to draft.
  let memory: ExecutiveMemoryContext | undefined;
  let memoryUnavailable = false;
  if (deps.memory) {
    const alias = senderAlias(input.email);
    if (alias !== null) {
      try {
        memory =
          (await deps.memory.service.resolveExecutiveContext({
            actor: deps.memory.actor,
            normalizedAlias: alias,
          })) ?? undefined;
      } catch {
        // Not fatal, and not invisible. Drafting continues without memory and
        // says so, because "no memory for this contact" and "memory could not
        // be consulted" are different facts and only one of them is safe to
        // treat as absence.
        memoryUnavailable = true;
      }
    }
  }
  const memoryFields = {
    ...(memory ? { memory } : {}),
    ...(memoryUnavailable ? { memoryUnavailable: true } : {}),
  };

  // Stage 2 — deterministic authority.
  const decision = decideAuthority(triage);
  const base: EaOutcome = {
    category: triage.category,
    risk: triage.risk,
    confidence: triage.confidence,
    action: decision.action,
    reason: decision.reason,
    degraded: degradedTriage,
    cautionMarker: decision.cautionMarker,
    ...memoryFields,
  };
  if (degradedTriage) return { ...base, action: "review_only", reason: triage.reason };

  // Stage 3 — draft only when permitted.
  if (decision.draftable && (triage.category === "real_lead" || triage.category === "vendor_solicitation")) {
    try {
      const draft = await generateExecutiveDraft(deps.draftRouter, deps.profile, triage.category, input.email);
      return { ...base, action: "draft", draft };
    } catch (error) {
      if (error instanceof DraftDegradedError) {
        return { ...base, action: "review_only", degraded: true, reason: "drafting model unavailable — review-only" };
      }
      throw error;
    }
  }
  return base;
}
