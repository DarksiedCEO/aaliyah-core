import {
  MemoryFieldNameSchema,
  MemoryIdSchema,
  MemoryTombstoneSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  canonicalDigest,
  type MemoryDerivativeDisposition,
  type MemoryDownstreamPropagation,
  type MemoryPropagationState,
  type MemoryTombstone,
} from "@aaliyah/contracts/v1";
import { z } from "zod";

/**
 * Wave 1.3 PART F — ERASURE, AND THE ACCOUNTING THAT HAS TO SURVIVE IT.
 *
 * WHAT THIS MODULE IS. The Core-side vocabulary for turning a permitted
 * deletion into a `MemoryTombstone`: what the approver must have authorized,
 * which field names were destroyed and which retained, and the digest that
 * binds the whole account together.
 *
 * WHAT IT IS NOT. Nothing here erases anything. Building a tombstone is a
 * CLAIM about a destruction; performing the destruction is
 * `wave1TrustedMemoryStore.delete()`, inside one transaction, and the
 * database is what refuses a deletion that leaves any prior version intact
 * (`memory_record_versions_deletion_erases`, migration 037).
 *
 * THE DELETION ORDER IS THE DELETED VERSION'S CONTENT, ON PURPOSE.
 * ----------------------------------------------------------------
 * A deletion needs a reason and a reference to the order that compelled it,
 * and the caller must not be the one asserting them: a caller-supplied reason
 * is a caller-supplied claim. Every mutation on this path is already bound to
 * an approver by `proposedContentDigest` inside the authorization's nonce, so
 * the deletion order travels as the CONTENT of the version that marks the
 * record deleted. The approver signed off on the exact reason and the exact
 * evidence reference, and nothing else can be smuggled alongside them: the
 * shape is a `strictObject` of three members, two closed grammars and one
 * enum, and migration 037 refuses any other content on a `deleted` version for
 * every writer, not only for callers of this code.
 *
 * That also closes the obvious hole in "erase the prior versions": the version
 * that performs the deletion is itself a version, and if it could carry free
 * content, a delete would be a perfectly legal way to keep a copy.
 */

/** Schema version the deletion order is pinned to. Mirrored in migration 037. */
export const MEMORY_DELETION_ORDER_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#deletion-order` as const;

/** Schema version the tombstone digest is taken under. */
export const MEMORY_TOMBSTONE_DIGEST_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#tombstone` as const;

/**
 * Why a record is being destroyed, and the order that compelled it.
 *
 * A CLOSED ENUM plus a reference, exactly as `MemoryDeletionReasonSchema`
 * requires: free text on this path is where the destroyed payload survives.
 */
export const MemoryDeletionOrderSchema = z.strictObject({
  schemaVersion: z.literal(MEMORY_DELETION_ORDER_SCHEMA_VERSION),
  reason: z.enum([
    "subject_erasure_request",
    "retention_expiry",
    "erroneous_record",
    "policy_violation",
    "legal_requirement",
    "duplicate_record",
  ]),
  reasonEvidenceRef: z
    .string()
    .regex(/^[a-z][a-z0-9_-]{1,31}:[a-z0-9][a-z0-9._:/-]{3,223}$/u, {
      message: "deletion evidence must be a canonical evidence reference",
    }),
});
export type MemoryDeletionOrder = z.infer<typeof MemoryDeletionOrderSchema>;

/** Parse a candidate deletion order, or answer null. Never throws. */
export function parseDeletionOrder(value: unknown): MemoryDeletionOrder | null {
  const parsed = MemoryDeletionOrderSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/**
 * TWO NAMESPACES, TWO PREFIXES, AND WHY.
 *
 * A tombstone must say which field names were RETAINED and which were
 * DESTROYED, and the contract forbids a name appearing in both lists — a field
 * that is claimed as kept and destroyed at once is how an "erased" record keeps
 * its plaintext while reporting erasure.
 *
 * But two different namespaces meet here. The chain ENVELOPE (version, state,
 * digests, authorization linkage) survives erasure, because that is exactly how
 * the append-only chain and real destruction are reconciled. The record's own
 * CONTENT fields do not survive. A record whose content happens to carry a
 * field called `version` would otherwise collide with the envelope's `version`
 * and the tombstone would be unrepresentable — or, worse, a reader would see
 * `version` in the destroyed list and conclude the chain metadata was
 * destroyed, which is false.
 *
 * The prefixes remove the ambiguity without inventing a member the contract
 * does not have: `envelope_*` is chain metadata that survived, `content_*` is a
 * record field that was destroyed, and the bare name `content` means the whole
 * content value was destroyed without nameable fields. Both forms are valid
 * `MemoryFieldNameSchema` identifiers, and the two prefixes cannot collide.
 */
export const MEMORY_ENVELOPE_FIELD_PREFIX = "envelope_" as const;
export const MEMORY_CONTENT_FIELD_PREFIX = "content_" as const;

/**
 * The whole content value, destroyed, where its fields cannot be named: the
 * content was not an object, was an empty object, or carried a key that is not
 * an identifier. Naming what cannot be named would be a fabrication; this says
 * "all of it" instead.
 */
export const MEMORY_WHOLE_CONTENT_FIELD_NAME = "content" as const;

/** The version-envelope members that survive an erasure, verbatim. */
export const MEMORY_RETAINED_ENVELOPE_FIELD_NAMES: readonly string[] = [
  "schemaVersion",
  "recordId",
  "version",
  "state",
  "scope",
  "contentDigest",
  "predecessorDigest",
  "authorizationId",
  "mutationReceiptId",
  "createdAt",
].map((name) => `${MEMORY_ENVELOPE_FIELD_PREFIX}${name}`);

/**
 * The field names actually destroyed, computed from the content that was
 * ACTUALLY THERE — never from a caller's description of it.
 *
 * Fails closed in both directions: a key that cannot be expressed as an
 * identifier, a content value that is not an object, or an object with no keys
 * all fall back to the bare `content` name rather than being dropped silently,
 * and the result is never empty, which is what `destroyedFieldNames.min(1)`
 * requires.
 */
export function destroyedContentFieldNames(
  contents: readonly unknown[],
): string[] {
  const names = new Set<string>();
  let unnameable = false;
  for (const content of contents) {
    if (
      content === null ||
      typeof content !== "object" ||
      Array.isArray(content)
    ) {
      unnameable = true;
      continue;
    }
    const keys = Object.keys(content as Record<string, unknown>);
    if (keys.length === 0) unnameable = true;
    for (const key of keys) {
      const candidate = `${MEMORY_CONTENT_FIELD_PREFIX}${key}`;
      if (MemoryFieldNameSchema.safeParse(candidate).success) {
        names.add(candidate);
      } else {
        unnameable = true;
      }
    }
  }
  if (unnameable || names.size === 0) {
    names.add(MEMORY_WHOLE_CONTENT_FIELD_NAME);
  }
  return [...names].sort();
}

/**
 * WHAT CORE HONESTLY KNOWS ABOUT DERIVATIVES: NOTHING, YET.
 *
 * There is no embedding service, no cache, no index and no export pipeline in
 * this repository that this store can speak for. `unknown` is a first-class
 * propagation state in the contract precisely so that this can be said rather
 * than papered over with `not_applicable`, which would be a claim that those
 * derivatives do not exist anywhere. A caller that genuinely reconciled a
 * derivative may override its disposition; nothing here invents one.
 */
export const MEMORY_DERIVATIVE_KINDS = [
  "embedding",
  "summary",
  "index_entry",
  "cache_entry",
  "export",
  "backup",
  "training_corpus",
] as const;

export function unknownDerivativeDispositions(): MemoryDerivativeDisposition[] {
  return MEMORY_DERIVATIVE_KINDS.map((derivativeKind) => ({
    derivativeKind,
    disposition: "unknown" as const,
    state: "not_started" as const,
    lastAttemptedAt: null,
  }));
}

/** The digest a tombstone is bound by: every member except the digest itself. */
export function memoryTombstoneDigest(
  tombstone: Omit<MemoryTombstone, "tombstoneDigest">,
): string {
  return canonicalDigest({
    schemaVersion: MEMORY_TOMBSTONE_DIGEST_SCHEMA_VERSION,
    value: tombstone,
  });
}

export type BuildTombstoneInput = {
  tombstoneId: string;
  scope: MemoryTombstone["scope"];
  targetRecordId: string;
  targetVersion: number;
  tombstoneVersion: number;
  deletionAuthority: MemoryTombstone["deletionAuthority"];
  order: MemoryDeletionOrder;
  effectiveAt: string;
  retainUntil: string | null;
  legalHoldState: MemoryTombstone["retention"]["legalHoldState"];
  destroyedFieldNames: readonly string[];
  derivedData: readonly MemoryDerivativeDisposition[];
  cacheIndexPropagation: MemoryPropagationState;
  downstreamPropagation: readonly MemoryDownstreamPropagation[];
};

/**
 * Assemble and VALIDATE a tombstone.
 *
 * `restorationEligibility` is always `ineligible_payload_destroyed`, and that
 * is not a placeholder: there is no escrow in this repository, so
 * `eligible_from_escrow` would name a custodian and a restoration window that
 * do not exist. Migration 037 refuses the other variant in the database for the
 * same reason. Restoring the RECORD to an active state is a separate action
 * under a separate `restore` authorization; it does not and cannot return the
 * destroyed payload.
 *
 * Throws if the assembled value is not a structurally valid `MemoryTombstone` —
 * which is the intended behaviour on this path, because a tombstone that does
 * not parse must not be written and the caller aborts the deletion.
 */
export function buildTombstone(input: BuildTombstoneInput): MemoryTombstone {
  if (!MemoryIdSchema.safeParse(input.tombstoneId).success) {
    throw new Error("trusted memory: tombstone id is not a memory identifier");
  }
  const withoutDigest = {
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    tombstoneId: input.tombstoneId,
    scope: input.scope,
    targetRecordId: input.targetRecordId,
    targetVersion: input.targetVersion,
    tombstoneVersion: input.tombstoneVersion,
    deletionAuthority: input.deletionAuthority,
    reason: input.order.reason,
    reasonEvidenceRef: input.order.reasonEvidenceRef,
    effectiveAt: input.effectiveAt,
    retention: {
      retainUntil: input.retainUntil,
      legalHoldState: input.legalHoldState,
    },
    retainedFieldNames: [...MEMORY_RETAINED_ENVELOPE_FIELD_NAMES],
    destroyedFieldNames: [...input.destroyedFieldNames],
    derivedData: [...input.derivedData],
    cacheIndexPropagation: input.cacheIndexPropagation,
    downstreamPropagation: [...input.downstreamPropagation],
    restorationEligibility: { kind: "ineligible_payload_destroyed" as const },
  };
  return MemoryTombstoneSchema.parse({
    ...withoutDigest,
    tombstoneDigest: memoryTombstoneDigest(
      withoutDigest as Omit<MemoryTombstone, "tombstoneDigest">,
    ),
  });
}
