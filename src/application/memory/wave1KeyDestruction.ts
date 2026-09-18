/**
 * WHAT IT MEANS TO HAVE PROVEN THAT A DATA KEY IS GONE — AND WHAT IT MEANS
 * NOT TO KNOW.
 *
 * Founder decision, OPTION B, locked: when a key's destruction cannot be
 * AUTHORITATIVELY confirmed, the subject MUST NOT be represented as erased.
 * Not "probably erased", not "erased once the retry budget runs out", not
 * "erased because a row says destroyed". The state stays UNRESOLVED until an
 * evidence-bound settlement resolves it.
 *
 * Before this module the store had a two-valued question — `state ===
 * "destroyed"` — and everything that was not that word became one permanent
 * refusal with no operator path and no disclosure. Two reviewers found the
 * same hole from opposite ends at 8a0bf05:
 *
 *   - integration, CRITICAL, executed (K-01): with `piiKeys: null`, which is
 *     the ACTUAL production wiring because no production KMS is provisioned,
 *     every survivor of a merge whose absorbed record ever carried a PII
 *     binding could never have its own subject erasure processed, even where
 *     the merged-in key was genuinely destroyed years ago;
 *   - security, LOW, undisclosed (K-09): the same permanent refusal for a
 *     lost key or a provider migration, where the provider answers `unknown`.
 *
 * So the question is now three-valued, and the third value is a STATE rather
 * than an error:
 *
 *   PROVEN_DESTROYED      the provider that owns the key says it is destroyed,
 *                         or an independently verified settlement says so on
 *                         evidence the provider structurally cannot supply.
 *                         The only value that satisfies erasure.
 *   PROVEN_NOT_DESTROYED  the owning provider says the key is alive. This is
 *                         not uncertainty — it is a refusal, and where the
 *                         database claimed otherwise it is also a detected
 *                         forgery.
 *   NOT_PROVEN            we do not know. NEVER erased. Recorded as a durable
 *                         obligation naming WHY, and resolvable only through
 *                         settlement.
 *
 * NOTHING HERE TURNS TIME, RETRIES OR ABSENCE INTO PROOF. There is
 * deliberately no "assumed destroyed", no expiry that promotes NOT_PROVEN, and
 * no path from a database row alone to PROVEN_DESTROYED: a `key_destroyed` row
 * is writable by the mutation role, which is the entire reason the provider is
 * asked in the first place.
 */

/** The erasure states a subject can be in with respect to its keys. */
export const KEY_DESTRUCTION_ERASURE_STATES = [
  /** A subject erasure has been requested and destruction attempted. */
  "ERASURE_REQUESTED",
  /**
   * Destruction could not be proven. The subject is NOT ERASED and stays
   * unresolved until a settlement resolves it. This is the state that used to
   * be a permanent, undisclosed refusal.
   */
  "ERASURE_PENDING_SETTLEMENT",
  /** Every in-scope key is proven destroyed and the erasure contract is met. */
  "ERASED",
] as const;
export type KeyDestructionErasureState =
  (typeof KEY_DESTRUCTION_ERASURE_STATES)[number];

export const KEY_DESTRUCTION_PROOFS = [
  "PROVEN_DESTROYED",
  "PROVEN_NOT_DESTROYED",
  "NOT_PROVEN",
] as const;
export type KeyDestructionProof = (typeof KEY_DESTRUCTION_PROOFS)[number];

/**
 * WHY a key's destruction could not be proven. Every value names a condition
 * an operator can act on; none of them is a synonym for "gave up".
 *
 * `SETTLED` is the one value that is not a failure: it is what an obligation
 * carries once a settlement closed it, so the row keeps its history instead of
 * being deleted.
 */
export const KEY_NOT_PROVEN_REASONS = [
  /** No key provider is configured at all — production's current wiring. */
  "NO_PROVIDER_CONFIGURED",
  /** The provider was asked and failed. */
  "PROVIDER_UNAVAILABLE",
  /** The provider was asked and did not answer within its deadline. */
  "PROVIDER_TIMEOUT",
  /** A provider is configured, but this key belongs to a different one. */
  "PROVIDER_DOES_NOT_OWN_KEY",
  /** The owning provider answered, and its answer was `unknown`. */
  "PROVIDER_ANSWERED_UNKNOWN",
  /**
   * The database says destroyed and the provider says alive. Not uncertainty:
   * a detected disagreement between two trust anchors, which must never
   * resolve in favour of the writable one.
   */
  "CONTRADICTORY_EVIDENCE",
  /** Closed by a settlement; kept for the audit trail. */
  "SETTLED",
] as const;
export type KeyNotProvenReason = (typeof KEY_NOT_PROVEN_REASONS)[number];

/**
 * THE SEVEN SETTLEMENT OUTCOMES, EXACTLY AS THE FOUNDER DECISION ENUMERATES
 * THEM.
 *
 * Only `PROVEN_DESTROYED` may satisfy the key-destruction portion of a
 * verified erasure. `STILL_UNKNOWN` remains unresolved — it is a recorded
 * decision that the evidence did not settle the question, which is a different
 * and more honest thing than no decision at all.
 */
export const SETTLEMENT_DECISIONS = [
  "PROVEN_DESTROYED",
  "PROVEN_NOT_DESTROYED",
  "STILL_UNKNOWN",
  "RETENTION_BLOCKED",
  "PROVIDER_UNAVAILABLE",
  "EVIDENCE_INSUFFICIENT",
  "CONTRADICTORY_EVIDENCE",
] as const;
export type SettlementDecision = (typeof SETTLEMENT_DECISIONS)[number];

/** The only decision that satisfies the key-destruction portion of erasure. */
export const SETTLEMENT_DECISION_THAT_SATISFIES: SettlementDecision =
  "PROVEN_DESTROYED";

/** The policy version every settlement written by this build is bound to. */
export const KEY_DESTRUCTION_POLICY_VERSION = "aaliyah.key-destruction-settlement/v1";

/**
 * One key's destruction question, and the answer this build could get.
 *
 * `keyVersion` is carried because a provider that rotates keys can hold
 * several versions under one reference, and "the key is destroyed" is a claim
 * about a version, not about a name.
 */
export type KeyDestructionAssessment = {
  /**
   * The scope this assessment was made under. Carried ON the assessment and
   * never on the store's closure: two concurrent erasures in different tenants
   * would otherwise share one mutable field, which is a cross-tenant
   * contamination bug and not a style preference.
   */
  tenantId: string;
  workspaceId: string;
  keyRef: string;
  keyVersion: number | null;
  providerId: string;
  aliasId: string;
  bindingMutationReceiptId: string;
  tombstoneId: string;
  subjectRecordId: string;
  proof: KeyDestructionProof;
  /**
   * Why this key is not proven destroyed. Null when `proof` is
   * `PROVEN_DESTROYED`, and also null when the provider positively says the
   * key is ALIVE and the database never claimed otherwise — that is an
   * ordinary not-yet-erased key, which the completion pass resolves, not an
   * unresolved state anyone must settle.
   */
  notProvenReason: KeyNotProvenReason | null;
  /** True when a settlement, not the provider, is what proved it. */
  provenBySettlement: boolean;
};

/**
 * A settlement, as the caller must supply it. Every field the founder decision
 * requires a receipt to bind is here and none is optional, because a receipt
 * with a blank in it binds nothing.
 */
export type KeyDestructionSettlementRequest = {
  settlementReceiptId: string;
  tenantId: string;
  workspaceId: string;
  subjectRecordId: string;
  aliasId: string;
  keyRef: string;
  keyVersion: number;
  providerId: string;
  bindingMutationReceiptId: string;
  erasureAuthorizationId: string;
  erasureTombstoneId: string;
  destructionAttemptId: string;
  /** The evidence the decision rests on. Digested, never free-texted onward. */
  evidence: unknown;
  settlementAuthorityId: string;
  /** MUST differ from `settlementAuthorityId`. The database enforces it too. */
  verifierPrincipalId: string;
  decision: SettlementDecision;
  nonce: string;
  decidedAt: Date;
};

export type KeyDestructionSettlementResult =
  | { recorded: true; replay: boolean; evidenceDigest: string }
  | { recorded: false; rejection: KeyDestructionSettlementRejection };

export const KEY_DESTRUCTION_SETTLEMENT_REJECTIONS = [
  /** The request is not a settlement: a missing or malformed field. */
  "settlement_malformed",
  /** Authority and verifier are the same principal. No self-verification. */
  "settlement_self_verified",
  /** This nonce has already been spent in this tenant. */
  "settlement_nonce_replayed",
  /**
   * The same receipt id already exists with DIFFERENT content. Idempotency
   * means replaying a settlement is free; it does not mean a receipt id can be
   * repointed at another decision.
   */
  "settlement_receipt_conflict",
  /** The key, alias, subject or tombstone the settlement names is not real. */
  "settlement_not_evidence_bound",
  /** A settlement already resolved this key for this erasure request. */
  "settlement_already_resolved",
  /**
   * THE EVIDENCE IS NOT EVIDENCE.
   *
   * The founder's decision requires a settlement to be evidence-bound and
   * forbids a settlement authority from fabricating provider evidence. Until
   * the a9d203d red team, `evidence` was typed `unknown` and validated
   * NOWHERE — not by the store, and not by the database, where
   * `evidence jsonb NOT NULL` accepts the jsonb value `null` because JSON null
   * is a value. `evidence: null` was accepted, digested to sha256("null"),
   * counted as a sound settlement, wrote destruction evidence, and returned
   * `verified: true` for a subject whose key the provider still reported as
   * ACTIVE. No forgery and no privilege abuse: the documented path.
   */
  "settlement_evidence_insufficient",
  /**
   * THE PROVIDER CAN ANSWER, AND IT SAYS THE KEY IS ALIVE.
   *
   * Security review of a9d203d, HIGH: `settleKeyDestruction` never asked the
   * provider anything. A settlement claiming PROVEN_DESTROYED was accepted
   * over a key whose provider was AVAILABLE, owned the key, and reported it
   * `active` — and that acceptance flipped
   * `aaliyah_memory_unerased_merged_records` from refuse to accept, so the
   * database's own erasure guard let a survivor erasure through while the key
   * was alive. Migration 055's own comment claimed "the provider's own answer
   * always wins, and a settlement stands in only where the provider
   * structurally cannot answer"; nothing implemented either clause.
   *
   * A settlement that contradicts an answer the provider actually gave is not
   * a settlement. It is the fabricated provider evidence the founder's
   * decision forbids by name.
   */
  "settlement_contradicted_by_provider",
  /** The database refused it. */
  "settlement_storage_rejected",
] as const;
export type KeyDestructionSettlementRejection =
  (typeof KEY_DESTRUCTION_SETTLEMENT_REJECTIONS)[number];

/**
 * One unresolved obligation, as an operator sees it. No subject content: an
 * obligation is about a KEY, and the alias id is the only identifier on it
 * that a producer chose (see the alias-id residual, K-18).
 */
export type KeyDestructionObligation = {
  tenantId: string;
  workspaceId: string;
  subjectRecordId: string;
  aliasId: string;
  keyRef: string;
  providerId: string;
  bindingMutationReceiptId: string;
  erasureTombstoneId: string;
  state: "KEY_DESTRUCTION_NOT_PROVEN" | "PROVEN_DESTROYED" | "PROVEN_NOT_DESTROYED";
  notProvenReason: KeyNotProvenReason;
  observations: number;
  firstObservedAt: Date;
  lastObservedAt: Date;
  /**
   * HOW it stopped being unresolved, or null while it still is. `PROVIDER`
   * means the provider eventually answered; `SETTLEMENT` means a human
   * judgement on evidence. An operator reading this ledger needs to know
   * which, so the two are never the same value.
   */
  resolvedBy: "PROVIDER" | "SETTLEMENT" | null;
  settledBy: string | null;
};
