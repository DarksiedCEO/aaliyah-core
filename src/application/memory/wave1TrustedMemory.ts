import {
  CanonicalDigestSchema,
  MemoryAuthorizationIdSchema,
  MemoryIdSchema,
  MemoryScopeSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  canonicalDigest,
  type MemoryMutationReceipt,
  type MemoryScope,
} from "@aaliyah/contracts/v1";
import { z } from "zod";

/**
 * Wave 1.3 TRUSTED MEMORY — the Core-side vocabulary.
 *
 * Contracts (`aaliyah.trusted-memory/v1`) defines the SHAPES and says, in its
 * own header, that it proves none of atomicity, persistence, uniqueness,
 * compare-and-swap, nonce consumption or read-back. This module and
 * `src/persistence/postgres/wave1TrustedMemoryStore.ts` are where those are
 * proven, against a real PostgreSQL, inside one transaction.
 *
 * WHAT A CALLER DOES NOT GET TO SUPPLY
 * ------------------------------------
 * A mutation request carries an `authorizationId` and nothing else about the
 * authorization. Not the receipt. Not the action. Not the expected head. Not
 * the proposed content digest. Not the scope. Every one of those is read from
 * the database inside the mutating transaction, so "verify the authorization
 * is real stored state" is not a check that can be deleted — there is no
 * caller-supplied receipt in the type for a deleted check to fall back to.
 *
 * WHAT `verified` MEANS, AND ONLY THAT
 * ------------------------------------
 * `verified: true` is returned if and only if the returned receipt's outcome
 * is `COMMITTED_AND_READ_BACK`, which the store emits only after an
 * INDEPENDENT post-commit read-back on a different connection agreed with what
 * was written. No read-back, no verified success. An unknown transaction
 * outcome is `UNKNOWN_PENDING_RECONCILIATION` with `verified: false`, durably,
 * and is never indistinguishable from success.
 */

/** Schema version the record CONTENT is digested under. */
export const MEMORY_RECORD_CONTENT_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#record-content` as const;

/** Schema version the stored VERSION ENVELOPE is validated under. */
export const MEMORY_RECORD_VERSION_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#record-version` as const;

export const MemoryRecordStateSchema = z.enum(["active", "deleted"]);
export type MemoryRecordState = z.infer<typeof MemoryRecordStateSchema>;

/**
 * One immutable version in a record's chain. `predecessorDigest` is the
 * content digest of the version this one replaced, and it is null exactly at
 * version 1 — the database enforces both halves of that.
 */
export const MemoryRecordVersionSchema = z.strictObject({
  schemaVersion: z.literal(MEMORY_RECORD_VERSION_SCHEMA_VERSION),
  recordId: MemoryIdSchema,
  version: z.number().int().positive(),
  state: MemoryRecordStateSchema,
  scope: MemoryScopeSchema,
  content: z.unknown(),
  contentDigest: CanonicalDigestSchema,
  predecessorDigest: CanonicalDigestSchema.nullable(),
  authorizationId: MemoryAuthorizationIdSchema,
  mutationReceiptId: MemoryIdSchema,
  createdAt: z.string().datetime(),
});
export type MemoryRecordVersion = z.infer<typeof MemoryRecordVersionSchema>;

/**
 * The authenticated actor, resolved by the caller's authentication layer and
 * NEVER read off the authorization. Every one of the four dimensions is
 * compared against the stored receipt's scope in its own statement, so each is
 * independently killable by a test.
 */
export type TrustedMemoryActor = MemoryScope;

/**
 * Why a mutation did not produce a verified success.
 *
 * A CLOSED enum, deliberately. `MemoryAbortReason` in contracts is coarse by
 * design (seven values, no free text, because free text on this path is where
 * a destroyed payload survives); this is the operational detail, and it is
 * still an enum so it can never carry record content either.
 */
export const TRUSTED_MEMORY_REJECTIONS = [
  "request_malformed",
  "authorization_not_found",
  "authorization_malformed",
  "authorization_scope_mismatch",
  "authorization_action_mismatch",
  "authorization_target_mismatch",
  "record_owner_mismatch",
  "authorization_expected_head_mismatch",
  "authorization_expired",
  "authorization_revoked",
  "authorization_already_consumed",
  "nonce_missing",
  "nonce_disagrees_with_receipt",
  "proposed_content_digest_mismatch",
  "head_mismatch",
  "storage_rejected",
  "read_back_diverged",
  "unknown_outcome",
] as const;
export type TrustedMemoryRejection = (typeof TRUSTED_MEMORY_REJECTIONS)[number];

export type TrustedMemoryMutationRequest = {
  /** Authenticated actor and scope. Authoritative; never taken from a receipt. */
  actor: TrustedMemoryActor;
  /** The ONLY thing the caller says about the authorization. */
  authorizationId: string;
  /** The record the caller claims to be mutating; checked against the receipt. */
  recordId: string;
  /** Must digest to exactly the `proposedContentDigest` the receipt authorized. */
  proposedContent: unknown;
  /** Identity of the mutation receipt this attempt will emit. */
  mutationReceiptId: string;
};

export type TrustedMemoryMutationResult = {
  /** True only for `COMMITTED_AND_READ_BACK`. */
  verified: boolean;
  rejection: TrustedMemoryRejection | null;
  /**
   * Null only when the attempt failed before enough real stored state existed
   * to fill a structurally valid receipt (an unknown authorization id, for
   * example). A null receipt is never a success.
   */
  receipt: MemoryMutationReceipt | null;
};

/** A record's head as Core observed it, or null if the record has no version. */
export type TrustedMemoryHead = {
  recordId: string;
  version: number;
  state: MemoryRecordState;
  contentDigest: string;
  predecessorDigest: string | null;
  scope: MemoryScope;
};

export interface TrustedMemoryStore {
  correct(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  delete(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  readHead(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<TrustedMemoryHead | null>;
}

/**
 * The digest a record's content is bound by.
 *
 * Throws `CanonicalDigestError` on anything that is not canonical JSON data —
 * which is the intended behaviour on this path, because a value that cannot be
 * digested cannot be compared against an authorization.
 *
 * KEY ORDER IS IRRELEVANT HERE, BY CONSTRUCTION. `canonicalDigest` sorts object
 * keys, which is the whole reason this digest exists rather than
 * `JSON.stringify`: PostgreSQL `jsonb` does not preserve insertion order, so a
 * value written as `{a,b}` reads back as `{b,a}` roughly whenever it feels like
 * it, and a naive stringify-and-hash would report a spurious divergence on
 * every second read-back.
 */
export function memoryContentDigest(content: unknown): string {
  return canonicalDigest({
    schemaVersion: MEMORY_RECORD_CONTENT_SCHEMA_VERSION,
    value: content,
  });
}
