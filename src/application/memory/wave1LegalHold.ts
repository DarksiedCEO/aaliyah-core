import {
  LegalHoldSchema,
  MEMORY_ACTIONS_NEVER_CARVED_OUT,
  legalHoldRestricts,
  type LegalHold,
  type MemoryAction,
} from "@aaliyah/contracts/v1";
import { z } from "zod";

import type { TrustedMemoryActor } from "./wave1TrustedMemory";

/**
 * Wave 1.3 PART F — LEGAL HOLDS, CORE SIDE.
 *
 * THE DEFECT THIS EXISTS TO CLOSE, STATED FROM THE EVIDENCE. `legalHoldRestricts`
 * shipped in contracts and was never called: a grep for `legalHold|legal_hold`
 * across the trusted-memory files returned ONE hit, a sentence in a header
 * saying enforcement was somebody else's, and `legal_hold_active` was an abort
 * reason no code path could reach. Before that, the hold gated DELETION ONLY,
 * so `correct` — whose schema REQUIRES the content to change — was a fully
 * supported path to rewriting held evidence.
 *
 * WHERE ENFORCEMENT ACTUALLY LIVES. Not here. This module is vocabulary and a
 * store interface. The enforcement is
 * `aaliyah_memory_restricting_hold` and the two triggers migration 036 installs
 * on `memory_record_versions` and `memory_alias_bindings`, because a check that
 * lives in TypeScript binds only the writes that come through TypeScript, and
 * the threat model here explicitly includes a hostile writer holding the
 * `aaliyah_memory_mutator` role. `wave1TrustedMemoryStore` ALSO checks, so that
 * a caller gets a `legal_hold_active` abort receipt instead of a raw storage
 * error and so a held record never burns an approval — that is ergonomics and
 * accounting on top of the enforcement point, never a substitute for it.
 *
 * EVERY ACTION, NOT ONLY DELETE. `legalHoldRestricts` returns true for every
 * action of an active hold unless a carve-out names that exact action, and
 * `MEMORY_ACTIONS_NEVER_CARVED_OUT` cannot be carved out at all. The database
 * mirrors both halves: `memory_legal_hold_carve_outs_never` refuses to store a
 * carve-out for delete, correct, merge_identity or split_identity, and the
 * restricting-hold lookup treats the absence of a carve-out row as restriction.
 */

/** Re-exported so callers read the declaration from one place. */
export { legalHoldRestricts, MEMORY_ACTIONS_NEVER_CARVED_OUT };

/**
 * A retention obligation over one record.
 *
 * Deliberately NOT part of `LegalHold`: a hold preserves evidence for a matter
 * and is lifted by an order, while a retention obligation is a policy clock. A
 * deletion is refused while EITHER is live, and the two are refused
 * separately so a test can kill each one on its own.
 */
export const MemoryRetentionObligationSchema = z.strictObject({
  obligationId: z.string().regex(/^[a-z0-9][a-z0-9._:-]{2,127}$/u),
  recordId: z.string().regex(/^[a-z0-9][a-z0-9._:-]{2,127}$/u),
  policyRef: z
    .string()
    .regex(/^[a-z][a-z0-9_-]{1,31}:[a-z0-9][a-z0-9._:/-]{3,223}$/u),
  imposingAuthorityId: z.string().regex(/^[a-z0-9][a-z0-9._:-]{2,127}$/u),
  imposedAt: z.string().datetime(),
  retainUntil: z.string().datetime(),
});
export type MemoryRetentionObligation = z.infer<
  typeof MemoryRetentionObligationSchema
>;

/**
 * Why a hold or an obligation was not recorded.
 *
 * A CLOSED enum for the same reason every other rejection list on this path is
 * closed: a rejection must never be a place for a record value to travel.
 */
export const LEGAL_HOLD_REJECTIONS = [
  "hold_malformed",
  "hold_scope_mismatch",
  "hold_already_exists",
  "hold_not_found",
  "hold_not_active",
  "hold_carve_out_forbidden",
  "retention_malformed",
  "retention_already_exists",
  "storage_rejected",
] as const;
export type LegalHoldRejection = (typeof LEGAL_HOLD_REJECTIONS)[number];

export type LegalHoldResult = {
  /** True only when the row is on disk and was read back. */
  recorded: boolean;
  rejection: LegalHoldRejection | null;
};

export type ReleaseHoldRequest = {
  actor: TrustedMemoryActor;
  holdId: string;
  releasedAt: string;
  releasingAuthorityId: string;
  releaseOrderRef: string;
};

/** A hold as an independent reader observes it. */
export type LegalHoldView = {
  hold: LegalHold;
  recordIds: readonly string[];
  canonicalParticipantIds: readonly string[];
};

export interface LegalHoldStore {
  /** Place a hold. Written under the hold officer role, never the mutator. */
  placeHold(actor: TrustedMemoryActor, hold: unknown): Promise<LegalHoldResult>;
  /** Release a hold. Monotonic: a released hold can never become active. */
  releaseHold(request: ReleaseHoldRequest): Promise<LegalHoldResult>;
  /** Read a hold on the independent read-back pool. */
  readHold(
    actor: TrustedMemoryActor,
    holdId: string,
  ): Promise<LegalHoldView | null>;
  /** Impose a retention obligation over one record. */
  imposeRetention(
    actor: TrustedMemoryActor,
    obligation: unknown,
  ): Promise<LegalHoldResult>;
  /**
   * Which hold RESTRICTS this action on this record right now, or null.
   *
   * Answers the same question the database trigger answers, through the same
   * SQL function, so the store's pre-check and the enforcement point cannot
   * drift into disagreeing.
   */
  restrictingHold(
    actor: TrustedMemoryActor,
    recordId: string,
    action: MemoryAction,
  ): Promise<string | null>;
}

/** Parse a candidate hold, or answer null. Never throws. */
export function parseLegalHold(value: unknown): LegalHold | null {
  const parsed = LegalHoldSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}
