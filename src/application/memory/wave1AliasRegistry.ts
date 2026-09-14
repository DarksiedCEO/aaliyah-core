import {
  CanonicalAliasIdentitySchema,
  CanonicalDigestSchema,
  MemoryAuthorizationIdSchema,
  MemoryIdSchema,
  MemoryScopeSchema,
  UnicodeScriptCodeSchema,
  UnicodeRestrictionLevelSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  Wave1EvidenceRefSchema,
  Wave1SubjectBoundEvidenceSchema,
  canonicalDigest,
  type CanonicalAliasIdentity,
  type MemoryMutationReceipt,
  type Wave1SubjectBoundEvidence,
} from "@aaliyah/contracts/v1";
import { z } from "zod";

import {
  CORE_ALIAS_NORMALIZATION_PROFILE,
  CORE_ALIAS_SKELETON_ALGORITHM,
} from "./wave1AliasSkeleton";
import {
  TRUSTED_MEMORY_REJECTIONS,
  type TrustedMemoryActor,
} from "./wave1TrustedMemory";

/**
 * Wave 1.3 Part D — THE AUTHORITATIVE ALIAS REGISTRY, Core-side vocabulary.
 *
 * WHY THIS EXISTS, IN ONE PARAGRAPH
 * ---------------------------------
 * Independent review proved a LIVE alias hijack: an alias record bound
 * "attacker@evil.example" onto a victim participant using identity evidence
 * that had been issued for somebody else, and it verified. Contracts closed
 * the subject-binding half (`Wave1SubjectBoundEvidenceSchema` — evidence that
 * names WHOM it is about). The other half is GLOBAL ALIAS UNIQUENESS, which a
 * per-record validator is structurally incapable of providing: one value at one
 * instant cannot see the other rows. That half needs a table, UNIQUE
 * constraints and a transaction, and it lives in
 * `src/persistence/postgres/wave1AliasRegistryStore.ts`.
 *
 * WHAT A CALLER DOES NOT GET TO SUPPLY
 * ------------------------------------
 * Exactly as in `wave1TrustedMemory`: the request names an `authorizationId`
 * and nothing else about the authorization. Action, scope, target, expected
 * head and proposed-content digest are all read from the database inside the
 * mutating transaction.
 *
 * WHAT A CALLER SUPPLIES BUT IS NEVER BELIEVED
 * --------------------------------------------
 * The `CanonicalAliasIdentity` value. Its `normalizedAlias`, its `skeleton`,
 * its `scriptDetermination`, its `restrictionLevel` and its `lookalikeDomain`
 * are PRODUCER CLAIMS. Core recomputes every one of them from
 * `observedAlias` and refuses the alias on any disagreement. The claim is
 * never the input to a decision; it is only ever the thing a recomputation is
 * compared against.
 *
 * WHY AN ALIAS ASSIGNMENT ADVANCES A RECORD HEAD
 * ----------------------------------------------
 * `MemoryAuthorizationReceiptSchema` admits `expectedHead.kind ===
 * "no_prior_version"` for exactly one action, `create`. Every other action —
 * `assign_alias` and `remove_alias` included — MUST expect a version. So an
 * alias mutation is authorized against, and compare-and-swaps, the PARTICIPANT
 * IDENTITY RECORD it changes: `targetRecordId` is the participant record, the
 * expected head is that record's head, and a successful assignment appends
 * exactly one version to that record's chain in the same transaction that
 * writes the binding. That is not a workaround; binding an alias IS a change to
 * the identity record, and making it one gives the alias path the same
 * compare-and-swap, the same append-only chain and the same mutation receipts
 * the correction path already has.
 *
 * HOW THE ALIAS IS BOUND TO THE AUTHORIZATION
 * -------------------------------------------
 * The authorization's `proposedContentDigest` is `aliasAssignmentDigest`, over
 * the successor record content AND the whole alias value AND the whole
 * subject-bound evidence value. Swap any of the three after issuance and the
 * digest no longer matches, which is refused before anything is written. An
 * authorization to bind one alias is therefore structurally incapable of
 * binding a different one.
 *
 * WHAT THIS MODULE STILL DOES NOT SOLVE
 * -------------------------------------
 * `canonicalDigest` is UNKEYED, so everything the `wave1TrustedMemoryStore`
 * header says about authenticity applies here unchanged: a party that can write
 * both the authorization table and the nonce table can forge an authorization,
 * and nothing in this repository stops a superuser. Authenticity needs a keyed
 * construction with a key outside the database, and that primitive is not here.
 */

/** Schema version the ASSIGN proposal is digested under. */
export const MEMORY_ALIAS_ASSIGNMENT_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#alias-assignment` as const;

/** Schema version the REMOVE proposal is digested under. */
export const MEMORY_ALIAS_REMOVAL_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#alias-removal` as const;

/** Schema version the stored binding envelope is validated under. */
export const MEMORY_ALIAS_BINDING_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#alias-binding` as const;

/**
 * THE CROSS-WORKSPACE POLICY, EXPLICIT AND NEVER IMPLICIT.
 *
 * There is no default. A tenant with no row in `memory_alias_tenant_policy`
 * cannot bind an alias at all — the store refuses with
 * `alias_scope_policy_missing` and the table's foreign key refuses the INSERT
 * independently. "Whether an alias bound in workspace A also excludes
 * workspace B" is the kind of question that must never be answered by whichever
 * WHERE clause somebody wrote first.
 *
 *   workspace_isolated  uniqueness is per (tenant, workspace). The same alias
 *                       may bind to different participants in two workspaces of
 *                       one tenant. Choose this when workspaces are separate
 *                       address spaces.
 *   tenant_exclusive    uniqueness is per tenant. An alias bound in ANY
 *                       workspace excludes it in every other workspace of that
 *                       tenant. Choose this when one human must not be two
 *                       identities.
 *
 * Enforcement is in the DATABASE, not in a query: each binding row carries the
 * policy it was written under, a `scope_key` column that a CHECK constraint
 * derives from that policy, and a foreign key onto the tenant's single policy
 * row. Two rows of one tenant cannot disagree about the policy, and the partial
 * UNIQUE indexes are on `(tenant_id, scope_key, ...)`. CROSS-TENANT reuse is
 * always permitted and is not a policy choice: `tenant_id` leads every index.
 */
export const ALIAS_CROSS_WORKSPACE_POLICIES = [
  "workspace_isolated",
  "tenant_exclusive",
] as const;
export const AliasCrossWorkspacePolicySchema = z.enum(
  ALIAS_CROSS_WORKSPACE_POLICIES,
);
export type AliasCrossWorkspacePolicy = z.infer<
  typeof AliasCrossWorkspacePolicySchema
>;

/** The sentinel `scope_key` a tenant-exclusive binding carries. */
export const ALIAS_TENANT_SCOPE_KEY = "*" as const;

/** The scope key a binding is indexed under, given the tenant's policy. */
export function aliasScopeKey(
  policy: AliasCrossWorkspacePolicy,
  workspaceId: string,
): string {
  return policy === "tenant_exclusive" ? ALIAS_TENANT_SCOPE_KEY : workspaceId;
}

/**
 * The binding as it is stored. Retains the producer's whole alias value for
 * audit alongside EVERY field Core recomputed, so a later reader can see both
 * what was claimed and what Core decided, and does not have to take Core's
 * word for the difference.
 */
export const MemoryAliasBindingSchema = z.strictObject({
  schemaVersion: z.literal(MEMORY_ALIAS_BINDING_SCHEMA_VERSION),
  aliasId: MemoryIdSchema,
  scope: MemoryScopeSchema,
  crossWorkspacePolicy: AliasCrossWorkspacePolicySchema,
  scopeKey: z.string().min(1).max(128),
  canonicalParticipantId: MemoryIdSchema,
  /** Recomputed by Core from `alias.observedAlias`. Never the claim. */
  normalizedAlias: z.string().min(3).max(254),
  normalizationProfile: z.literal(CORE_ALIAS_NORMALIZATION_PROFILE),
  /** Recomputed by Core. Not a UTS-39 skeleton; see `wave1AliasSkeleton`. */
  skeleton: z.string().min(1).max(254),
  skeletonAlgorithm: z.literal(CORE_ALIAS_SKELETON_ALGORITHM),
  registrableDomain: z.string().min(3).max(253),
  scriptCode: UnicodeScriptCodeSchema,
  restrictionLevel: UnicodeRestrictionLevelSchema,
  subjectParticipantId: z.string().min(1),
  sourceEvidenceRef: Wave1EvidenceRefSchema,
  sourceEvidenceDigest: CanonicalDigestSchema,
  observedAt: z.string().datetime(),
  freshUntil: z.string().datetime(),
  authorizationId: MemoryAuthorizationIdSchema,
  mutationReceiptId: MemoryIdSchema,
  boundAt: z.string().datetime(),
  /** The producer's value, verbatim, as evidence of what was claimed. */
  claimed: CanonicalAliasIdentitySchema,
});
export type MemoryAliasBinding = z.infer<typeof MemoryAliasBindingSchema>;

/**
 * The digest an `assign_alias` authorization binds.
 *
 * All three components are inside it. An issuer approves ONE alias, for ONE
 * participant, on ONE piece of subject-bound evidence, advancing ONE record to
 * ONE successor content — and a request that changes any of those is a
 * different mutation than the one approved.
 */
export function aliasAssignmentDigest(input: {
  record: unknown;
  alias: CanonicalAliasIdentity;
  evidence: Wave1SubjectBoundEvidence;
}): string {
  return canonicalDigest({
    schemaVersion: MEMORY_ALIAS_ASSIGNMENT_SCHEMA_VERSION,
    value: {
      record: input.record,
      alias: input.alias,
      evidence: input.evidence,
    },
  });
}

/** The digest a `remove_alias` authorization binds. */
export function aliasRemovalDigest(input: {
  record: unknown;
  aliasId: string;
}): string {
  return canonicalDigest({
    schemaVersion: MEMORY_ALIAS_REMOVAL_SCHEMA_VERSION,
    value: { record: input.record, aliasId: input.aliasId },
  });
}

/**
 * Why an alias mutation did not produce a verified success.
 *
 * The shared authorization failures come from `TRUSTED_MEMORY_REJECTIONS`
 * unchanged, because the authorization mechanism IS the same one — the same
 * receipt table, the same out-of-band nonce, the same atomic single-use
 * consumption. Everything after `alias_` is specific to this path. Still a
 * CLOSED enum: no free text may travel on a rejection, ever, because a
 * rejection is exactly where an alias value would otherwise be quoted back.
 */
export const ALIAS_REGISTRY_REJECTIONS = [
  ...TRUSTED_MEMORY_REJECTIONS,
  /** The alias value is not a structurally valid `CanonicalAliasIdentity`. */
  "alias_malformed",
  /** The alias declares a different tenant/workspace/principal/user. */
  "alias_scope_mismatch",
  /** The alias names a participant other than the authorized target record. */
  "alias_participant_mismatch",
  /** The normalized alias is not `local@host`, or the host is malformed. */
  "alias_not_email_shaped",
  /** Core's normalization disagrees with the producer's claim. */
  "alias_normalization_disagreement",
  /** Core's recomputed confusable skeleton disagrees with the claim. */
  "alias_skeleton_disagreement",
  /** Core's host extraction disagrees with the claimed registrable domain. */
  "alias_domain_disagreement",
  /** The alias mixes scripts. Refused outright, never scored. */
  "alias_mixed_script",
  /** Core cannot name the script of a code point in the alias. */
  "alias_script_undetermined",
  /** The host is an IDN homograph or a typosquat of a protected domain. */
  "alias_lookalike_domain",
  /** The producer did not propose acceptance. */
  "alias_disposition_not_acceptable",
  /** The evidence is not a structurally valid subject-bound evidence value. */
  "alias_evidence_malformed",
  /** THE HIJACK: evidence issued about somebody other than this participant. */
  "alias_evidence_subject_mismatch",
  /** The evidence value and the alias disagree about which evidence it is. */
  "alias_evidence_disagreement",
  /** The evidence freshness window has closed. */
  "alias_evidence_stale",
  /** The tenant has no explicit cross-workspace policy. Fail closed. */
  "alias_scope_policy_missing",
  /** The normalized alias is already bound in this scope. */
  "alias_already_bound",
  /** A visually confusable alias is already bound in this scope. */
  "alias_skeleton_collision",
  /** Nothing active to remove under this alias id in this scope. */
  "alias_not_bound",
] as const;
export type AliasRegistryRejection = (typeof ALIAS_REGISTRY_REJECTIONS)[number];

export type AliasAssignRequest = {
  /** Authenticated actor and scope. Authoritative; never taken from a receipt. */
  actor: TrustedMemoryActor;
  /** The ONLY thing the caller says about the authorization. */
  authorizationId: string;
  /** The participant identity record this assignment advances. */
  participantRecordId: string;
  /** A `CanonicalAliasIdentity`. Parsed here, believed nowhere. */
  alias: unknown;
  /** A `Wave1SubjectBoundEvidence`. Must name this participant as subject. */
  evidence: unknown;
  /** Successor content for the participant record. */
  proposedContent: unknown;
  /** Identity of the mutation receipt this attempt will emit. */
  mutationReceiptId: string;
};

export type AliasRemoveRequest = {
  actor: TrustedMemoryActor;
  authorizationId: string;
  participantRecordId: string;
  /** The binding to retire. Must currently be active and name this participant. */
  aliasId: string;
  proposedContent: unknown;
  mutationReceiptId: string;
};

export type AliasRegistryResult = {
  /** True only for `COMMITTED_AND_READ_BACK` on an independent session. */
  verified: boolean;
  rejection: AliasRegistryRejection | null;
  receipt: MemoryMutationReceipt | null;
};

/** A binding as an independent reader observes it. */
export type AliasBindingView = {
  binding: MemoryAliasBinding;
  removed: boolean;
};

export interface AliasRegistryStore {
  assignAlias(request: AliasAssignRequest): Promise<AliasRegistryResult>;
  removeAlias(request: AliasRemoveRequest): Promise<AliasRegistryResult>;
  /** Read a binding by alias id, on the independent read-back pool. */
  readAliasBinding(
    actor: TrustedMemoryActor,
    aliasId: string,
  ): Promise<AliasBindingView | null>;
  /** Resolve the ACTIVE binding of a normalized alias, if any. */
  resolveAlias(
    actor: TrustedMemoryActor,
    normalizedAlias: string,
  ): Promise<AliasBindingView | null>;
}

/** Parse a candidate alias value, or answer null. Never throws. */
export function parseAliasIdentity(value: unknown): CanonicalAliasIdentity | null {
  const parsed = CanonicalAliasIdentitySchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** Parse candidate subject-bound evidence, or answer null. Never throws. */
export function parseSubjectBoundEvidence(
  value: unknown,
): Wave1SubjectBoundEvidence | null {
  const parsed = Wave1SubjectBoundEvidenceSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}
