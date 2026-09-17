import {
  CanonicalDigestSchema,
  MemoryAuthorizationIdSchema,
  MemoryIdSchema,
  MemoryScopeSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  canonicalDigest,
  type MemoryDerivativeDisposition,
  type MemoryDownstreamPropagation,
  type MemoryMutationReceipt,
  type MemoryPropagationState,
  type MemoryScope,
  type MemoryTombstone,
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
  /**
   * An active legal hold restricts this action on this record. The ONLY
   * rejection on this path that maps to the contract's `legal_hold_active`
   * abort reason, which was unreachable before Wave 1.3 Part F.
   */
  "legal_hold_active",
  /** An unexpired retention obligation forbids destroying this record. */
  "retention_obligation_active",
  /** A delete whose authorized content is not a `MemoryDeletionOrder`. */
  "deletion_order_malformed",
  /** A restore whose head is not in the `deleted` state. */
  "restore_head_not_deleted",
  /** A merge or split whose authorized content is not a valid identity order. */
  "identity_order_malformed",
  /** An identity order naming the record it is issued against. */
  "identity_counterparty_invalid",
  /** An identity order naming a record that is not an active record here. */
  "identity_counterparty_missing",
  /** A merge naming a record that was itself merged away: a merge into a ghost. */
  "identity_counterparty_merged_away",
  /**
   * The target has been merged into another record. It keeps its history and
   * accepts no further versions; the survivor is where mutations go.
   */
  "record_merged_away",
  /**
   * A subject erasure of a record that other records were merged into, while
   * one of them still holds content or an unerased address. Erase those
   * first, each under its own authorization: a merge is not a way around
   * erasure, and one authorization is one mutation.
   */
  "merged_records_not_erased",
  /** A mutation on a record whose head is deleted, other than a restore. */
  "record_deleted",
  /**
   * The deletion committed no tombstone, or did not erase every prior
   * version. Reported rather than swallowed: a partial erasure is not a
   * deletion, and the transaction is unwound.
   */
  "erasure_incomplete",
  /**
   * Another transaction held a lock this mutation needed for longer than the
   * store's lock wait. Nothing was consumed and nothing was written.
   */
  "record_busy",
  /**
   * This mutation receipt id already names a mutation on record. An id that
   * carries a receipt identifies THAT mutation; reusing it for another would
   * let the second's evidence collide with — or be read as — the first's.
   */
  "mutation_receipt_id_reused",
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

/**
 * A DELETION, WITH ITS ACCOUNTING.
 *
 * The three propagation members are OPTIONAL and they are not conveniences:
 * they exist so a caller that genuinely reconciled a derivative, a cache or a
 * downstream system can say so, and so that a caller that did not says
 * `unknown` by omission rather than by claiming `not_applicable`. The default
 * is the honest one.
 *
 * `reason` is deliberately ABSENT. It travels inside `proposedContent` as a
 * `MemoryDeletionOrder`, which means the approver's authorization digest binds
 * it. A reason the CALLER supplies is a reason nobody approved. See
 * `wave1MemoryErasure.ts`.
 */
export type TrustedMemoryDeleteRequest = TrustedMemoryMutationRequest & {
  /** Identity of the tombstone. Defaults to the mutation receipt id. */
  tombstoneId?: string;
  derivedData?: readonly MemoryDerivativeDisposition[];
  cacheIndexPropagation?: MemoryPropagationState;
  downstreamPropagation?: readonly MemoryDownstreamPropagation[];
};

export type TrustedMemoryDeleteResult = TrustedMemoryMutationResult & {
  /**
   * The tombstone that was written, or null. NEVER null on a verified
   * deletion: a deletion with no tombstone is exactly the "deleted is a label"
   * defect, and the store unwinds rather than returning one.
   */
  tombstone: MemoryTombstone | null;
  /**
   * THE SUBJECT'S ALIASES, ERASED WITH THE RECORD (migration 047).
   *
   * Null when the deletion never committed. Otherwise the non-PII accounting:
   * how many bindings naming this participant had their envelope and blind
   * indexes destroyed in the deleting transaction, and how many of their data
   * keys the provider has confirmed destroyed. `keysPending > 0` means the
   * database has forgotten the identifiers but ciphertext copies elsewhere
   * (a backup, a replica) are still decryptable — the deletion is then NOT
   * reported verified, and `completePendingAliasErasures` finishes it.
   */
  aliasErasure: {
    bindingsErased: number;
    keysDestroyed: number;
    keysPending: number;
  } | null;
};

/** A record as ORDINARY RETRIEVAL sees it. Deleted and erased records are not. */
export type TrustedMemoryRecord = {
  recordId: string;
  version: number;
  contentDigest: string;
  content: unknown;
  scope: MemoryScope;
};

export interface TrustedMemoryStore {
  /**
   * BRING A RECORD INTO EXISTENCE, UNDER THE SAME PROTOCOL AS EVERY OTHER
   * MUTATION.
   *
   * Genesis used to be the one mutation with no protocol: a record appeared
   * because something privileged inserted version 1 directly, so the chain
   * every later control compares against was founded on an unauthorized,
   * unreceipted, un-read-back write.
   *
   * The compare-and-swap here asserts ABSENCE. The authorization must carry
   * `no_prior_version` — not a sentinel version 0, which is a number a caller
   * could supply — and any existing head refuses it, including a `deleted`
   * one. Returning a deleted record to service is `restore`, which is a
   * separate authority over a chain that still exists; `create` is only ever
   * the first link.
   */
  create(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  correct(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  /**
   * DESTROY the record's prior content and emit a tombstone.
   *
   * Not a state flag. Refused under an active legal hold or an unexpired
   * retention obligation, and refused by the database if it would leave any
   * prior version unerased.
   */
  delete(request: TrustedMemoryDeleteRequest): Promise<TrustedMemoryDeleteResult>;
  /**
   * Finish alias erasures whose database half committed but whose data keys
   * the provider has not yet confirmed destroyed — after a crash, or while the
   * provider was unavailable. Idempotent. Never reports a key destroyed that
   * the provider did not confirm.
   */
  completePendingAliasErasures(limit?: number): Promise<{
    destroyed: number;
    pending: number;
  }>;
  /**
   * Return a deleted record to an active state under a SEPARATE `restore`
   * authorization. It does NOT return the destroyed payload — that is gone,
   * which is what the tombstone's `ineligible_payload_destroyed` says.
   */
  restore(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  /**
   * ABSORB THIS RECORD INTO ANOTHER.
   *
   * The authorization targets the record being ABSORBED, and the authorized
   * content names the survivor — so the approver's grant is over the identity
   * that loses its independent existence, not the one that gains.
   *
   * Appends one version to the absorbed record and writes one identity edge,
   * atomically. It does NOT write to the survivor: one authorization produces
   * exactly one record version, enforced by the nonce's uniqueness, its single
   * witnessed receipt id, and migration 038. The absorbed record is then
   * FROZEN — it keeps its history and accepts no further versions. A merge is
   * not a deletion and does not become a quiet one.
   */
  mergeIdentity(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  /**
   * RECORD THAT THIS RECORD'S IDENTITY WAS TWO PEOPLE.
   *
   * The authorized content names an ALREADY-EXISTING active record in the same
   * scope, created under its own `create` authorization. A split that also
   * created that record would be two mutations under one approval; one that
   * promised it for later would leave the graph naming something absent.
   */
  splitIdentity(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  /** Advance a record under a `promote` authorization. */
  promote(
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult>;
  /**
   * The chain head, whatever its state. This is the value a compare-and-swap
   * is performed against, so it MUST keep answering for a deleted record;
   * `retrieve` is the ordinary-retrieval path and that one does not.
   */
  readHead(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<TrustedMemoryHead | null>;
  /** ORDINARY RETRIEVAL. Answers null for a deleted or erased record. */
  retrieve(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<TrustedMemoryRecord | null>;
  /** Read a tombstone back on the independent pool. */
  readTombstone(
    actor: TrustedMemoryActor,
    tombstoneId: string,
  ): Promise<MemoryTombstone | null>;
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
