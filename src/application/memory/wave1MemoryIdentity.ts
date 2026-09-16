import {
  MemoryIdSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
} from "@aaliyah/contracts/v1";
import { z } from "zod";

/**
 * Wave 1.3 — IDENTITY MERGE AND SPLIT, AND THE CONSTRAINT THAT SHAPES THEM.
 *
 * A trusted-memory record is a canonical participant identity. Two records
 * turn out to be one person (a merge); one record turns out to have conflated
 * two people (a split). The contract already names both as actions and already
 * says why they matter: they "re-shape the record graph", which is why neither
 * can ever be carved out of a legal hold.
 *
 * THE CONSTRAINT, BECAUSE IT DECIDES THE DESIGN. One authorization can produce
 * exactly ONE record version, and this is enforced three times over:
 * `memory_authorization_nonces` is UNIQUE on `authorization_id`, so an
 * authorization has one nonce; a nonce carries one
 * `consumed_by_mutation_receipt_id`, so it witnesses one mutation receipt; and
 * migration 038 makes `(tenant, workspace, mutation_receipt_id)` unique on
 * `memory_record_versions`. That triple is the H-1 fix — "bind one consumed
 * authorization to exactly one mutation" — and it is not negotiable here.
 *
 * So a merge CANNOT append a version to both records, and a split CANNOT
 * append to the source and create the new identity, under one approval. An
 * implementation that tried would either need two approvals pretending to be
 * one, or a weakening of the invariant that exists because it was already
 * violated once.
 *
 * WHAT IS DONE INSTEAD. Each operation appends exactly ONE record version — to
 * the record the authorization targets — and writes ONE row into an
 * append-only identity-edge table, in the SAME transaction. The edge is the
 * graph change; the version is that record's account of it. Both records must
 * already exist and be active, so neither operation leaves a dangling promise
 * to create something later.
 *
 * A merge FREEZES the absorbed record: migration 041 refuses any further
 * version on a record that has an outgoing `merged_into` edge. Correcting a
 * record that has been merged away is editing a ghost, and the absorbed
 * record's history stays readable rather than being destroyed — a merge is not
 * a deletion and must not become a quiet one.
 *
 * WHAT IS DELIBERATELY NOT HERE. There is no un-merge. Reversing a merge is a
 * `split_identity` against the survivor, under its own authority, which is the
 * same path any other party would have to take. A dedicated inverse would be
 * an operation whose whole purpose is to undo an approved decision without a
 * second approval.
 */

/** Schema version the merge order is carried under. */
export const MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#identity-merge-order` as const;

/** Schema version the split order is carried under. */
export const MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION =
  `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#identity-split-order` as const;

/**
 * A canonical evidence reference. Same shape the deletion order requires, and
 * for the same reason: free text on this path is where an unaccountable
 * decision hides behind a plausible sentence.
 */
const EvidenceRefSchema = z
  .string()
  .regex(/^[a-z][a-z0-9_-]{1,31}:[a-z0-9][a-z0-9._:/-]{3,223}$/u, {
    message: "identity evidence must be a canonical evidence reference",
  });

/**
 * WHY TWO RECORDS ARE ONE PERSON, AND WHO SAID SO.
 *
 * A CLOSED ENUM plus a reference. `survivorRecordId` is the record that keeps
 * receiving mutations; the authorization's own `targetRecordId` is the one
 * being absorbed, so the approver's grant names the record that LOSES its
 * independent existence rather than the one that gains.
 */
export const MemoryIdentityMergeOrderSchema = z.strictObject({
  schemaVersion: z.literal(MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION),
  reason: z.enum([
    "duplicate_participant",
    "confirmed_same_person",
    "erroneous_split_reversed",
  ]),
  reasonEvidenceRef: EvidenceRefSchema,
  /** The record that survives and keeps receiving mutations. */
  survivorRecordId: MemoryIdSchema,
});
export type MemoryIdentityMergeOrder = z.infer<
  typeof MemoryIdentityMergeOrderSchema
>;

/**
 * WHY ONE RECORD WAS TWO PEOPLE, AND WHERE THE OTHER ONE NOW LIVES.
 *
 * `splitRecordId` MUST already exist as an active record, created under its
 * own `create` authorization. A split that also created the record would be
 * two mutations under one approval; a split that promised a record for later
 * would leave the graph naming something that does not exist.
 */
export const MemoryIdentitySplitOrderSchema = z.strictObject({
  schemaVersion: z.literal(MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION),
  reason: z.enum([
    "conflated_participants",
    "distinct_person_identified",
    "erroneous_merge_reversed",
  ]),
  reasonEvidenceRef: EvidenceRefSchema,
  /** The already-existing record the split-off identity lives in. */
  splitRecordId: MemoryIdSchema,
});
export type MemoryIdentitySplitOrder = z.infer<
  typeof MemoryIdentitySplitOrderSchema
>;

/** The two edge kinds the graph can carry. */
export const MEMORY_IDENTITY_EDGE_KINDS = ["merged_into", "split_to"] as const;
export type MemoryIdentityEdgeKind =
  (typeof MEMORY_IDENTITY_EDGE_KINDS)[number];

/** An edge as it is stored and read back. */
export type MemoryIdentityEdge = {
  kind: MemoryIdentityEdgeKind;
  fromRecordId: string;
  toRecordId: string;
  authorizationId: string;
  mutationReceiptId: string;
  /** Version of the FROM record that recorded this edge. */
  fromVersion: number;
  reason: string;
  reasonEvidenceRef: string;
  effectiveAt: string;
};

/** Parse a candidate merge order, or answer null. Never throws. */
export function parseIdentityMergeOrder(
  value: unknown,
): MemoryIdentityMergeOrder | null {
  const parsed = MemoryIdentityMergeOrderSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** Parse a candidate split order, or answer null. Never throws. */
export function parseIdentitySplitOrder(
  value: unknown,
): MemoryIdentitySplitOrder | null {
  const parsed = MemoryIdentitySplitOrderSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/**
 * The record an identity order points AT, whichever order it is.
 *
 * Returned as a discriminated pair rather than a bare string so a caller
 * cannot accidentally treat a survivor as a split target: the two mean
 * opposite things about which record keeps its independent existence.
 */
export function identityCounterparty(
  order: MemoryIdentityMergeOrder | MemoryIdentitySplitOrder,
): { kind: MemoryIdentityEdgeKind; recordId: string } {
  return "survivorRecordId" in order
    ? { kind: "merged_into", recordId: order.survivorRecordId }
    : { kind: "split_to", recordId: order.splitRecordId };
}
