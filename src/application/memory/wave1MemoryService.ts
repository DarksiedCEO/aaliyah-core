import type {
  KeyDestructionObligation,
  KeyDestructionSettlementRequest,
  KeyDestructionSettlementResult,
} from "./wave1KeyDestruction";
import type {
  TrustedMemoryActor,
  TrustedMemoryRecord,
  TrustedMemoryStore,
} from "./wave1TrustedMemory";

/**
 * Wave 1.3 — THE AUTHORITATIVE MEMORY SERVICE, AND WHY IT EXISTS.
 *
 * Every control in `wave1TrustedMemoryStore` was real and proven, and nothing
 * in Core called any of it. The only callers were tests. A store with no
 * production consumer is a library that cannot be wrong in production because
 * it does not run there, and reporting it as a completed capability would be
 * reporting the tests rather than the system.
 *
 * This is the seam a real Core path goes through to reach memory. It composes
 * the three pieces that were already built — the trusted-memory store, the
 * alias registry, the reconciler — and exposes the two operations a consumer
 * of executive context actually needs.
 *
 * READ-TIME CANONICAL RESOLUTION, AND WHAT IT IS NOT. A merge freezes the
 * absorbed record; it does not delete it and does not rewrite it. So an alias
 * that still points at an absorbed identity resolves, at READ time only, to
 * the surviving identity. Nothing is mutated, no evidence is rewritten, and
 * the absorbed record stays exactly as readable as it was. That separation is
 * the whole point: the graph says where an identity went, and reading follows
 * it without editing history to make the answer convenient.
 */

/** How far a resolver will walk a merge chain before refusing to continue. */
export const MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH = 16;

/** Reading a merge chain that does not terminate. */
export class MemoryCanonicalResolutionFailed extends Error {
  readonly startRecordId: string;
  constructor(startRecordId: string, reason: string) {
    super(`canonical identity resolution failed for ${startRecordId}: ${reason}`);
    this.name = "MemoryCanonicalResolutionFailed";
    this.startRecordId = startRecordId;
  }
}

/** The merge graph, read-only. */
export interface MemoryIdentityGraphReader {
  /** The record `recordId` was merged into, or null when it stands alone. */
  mergedInto(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<string | null>;
}

/** The alias registry's read half. */
export interface MemoryAliasResolver {
  resolveAlias(
    actor: TrustedMemoryActor,
    normalizedAlias: string,
  ): Promise<{ binding: { canonicalParticipantId: string } } | null>;
}

/** The reconciler's entry point. */
export interface MemoryReconcilerRunner {
  reconcileAll(limit?: number): Promise<readonly unknown[]>;
}

/**
 * What an executive-context consumer gets back.
 *
 * `resolvedFrom` is non-null exactly when the alias pointed at a record that
 * has since been absorbed. A consumer that wants to say "this address belongs
 * to a contact we merged" has the fact; one that does not can ignore it. It is
 * never silently hidden, because a reader that cannot tell the difference
 * between "this is the record" and "this is where the record went" cannot
 * explain its own output.
 */
export type ExecutiveMemoryContext = {
  canonicalRecordId: string;
  resolvedFrom: string | null;
  record: TrustedMemoryRecord;
};

export type Wave1MemoryServiceDeps = {
  store: TrustedMemoryStore;
  aliases: MemoryAliasResolver;
  identityGraph: MemoryIdentityGraphReader;
  reconciler: MemoryReconcilerRunner;
};

export type Wave1MemoryService = {
  /**
   * alias -> identity -> canonical identity -> authoritative record.
   *
   * Null when the alias is unknown here, or when the record it names — with no
   * merge redirect — cannot be retrieved (deleted, erased, or outside this
   * actor's scope). Null is an ANSWER: it means "no memory to bring", never
   * "assume none". A redirect whose canonical record cannot be retrieved
   * THROWS `MemoryCanonicalResolutionFailed`: that is not an absence.
   */
  resolveExecutiveContext(input: {
    actor: TrustedMemoryActor;
    normalizedAlias: string;
  }): Promise<ExecutiveMemoryContext | null>;
  /** Resolve outstanding UNKNOWN outcomes. Returns how many it settled. */
  reconcilePending(limit?: number): Promise<number>;
  /**
   * Destroy alias data keys whose erasure committed but was never confirmed
   * — the other half of a deletion a crash or a provider outage interrupted.
   */
  completePendingErasures(limit?: number): Promise<{
    destroyed: number;
    /**
     * Keys whose `key_destroyed` evidence was a FORGERY — the provider said
     * the key was alive — which this pass then destroyed for real. Counted
     * apart from `destroyed` because the forged row already occupies the
     * evidence slot, so the insert conflicts and `destroyed` cannot see it.
     */
    repaired: number;
    /** Contradictions seen between the evidence and the provider. */
    contradictions: number;
    pending: number;
    /**
     * Of `pending`, how many are unprovable rather than late, and why. Boot
     * reads this to say WHICH it is, instead of printing a counter that never
     * moves (founder decision, OPTION B).
     */
    notProven: number;
    notProvenReasons: Record<string, number>;
    /**
     * Obligations this pass could not write. Non-zero means a subject is NOT
     * ERASED and has NO ledger row to settle against (red team, a9d203d).
     */
    obligationsUnrecorded: number;
  }>;
  /**
   * SETTLE one key's destruction on evidence, or record that the evidence did
   * not settle it.
   *
   * The bounded way out of `ERASURE_PENDING_SETTLEMENT`, and NOT an
   * administrative bypass: evidence-bound, scoped, independently authorized,
   * independently verified, replay-safe, idempotent, versioned and immutable
   * once written. Only `PROVEN_DESTROYED` satisfies the key-destruction
   * portion of a verified erasure; `STILL_UNKNOWN` is a recorded decision
   * that the question remains open.
   */
  settleKeyDestruction(
    request: KeyDestructionSettlementRequest,
  ): Promise<KeyDestructionSettlementResult>;
  /** The unresolved key-destruction obligations an operator has to settle. */
  listKeyDestructionObligations(input: {
    actor: TrustedMemoryActor;
    limit?: number;
  }): Promise<KeyDestructionObligation[]>;
  /** The canonical identity a record has been merged into, transitively. */
  canonicalIdentity(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<string>;
};

export function createWave1MemoryService(
  deps: Wave1MemoryServiceDeps,
): Wave1MemoryService {
  /**
   * Walk the merge chain to the identity that still stands.
   *
   * BOUNDED, and the bound is not decoration. Migration 042 refuses a merge
   * naming an already-absorbed record, which is what stops a cycle being
   * created; this stops an existing one — from a replica, a restored backup,
   * or a database where that trigger was dropped — from hanging a reader
   * forever. A guard and a bounded walk protect against different failures.
   *
   * Refuses rather than returning the last id it saw: a truncated walk returns
   * a NON-canonical identity that looks exactly like a canonical one, and a
   * consumer cannot tell it was cut short.
   */
  async function canonicalIdentity(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<string> {
    const seen = new Set<string>([recordId]);
    let current = recordId;
    // A chain of MAX hops takes MAX + 1 lookups: MAX redirects and the one
    // that finds the canonical record. `<` here refused a chain of exactly
    // MAX (red team M3 against 2b2e554).
    for (let depth = 0; depth <= MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH; depth += 1) {
      const next = await deps.identityGraph.mergedInto(actor, current);
      if (next === null) return current;
      if (seen.has(next)) {
        throw new MemoryCanonicalResolutionFailed(
          recordId,
          `merge chain cycles at ${next}`,
        );
      }
      seen.add(next);
      current = next;
    }
    throw new MemoryCanonicalResolutionFailed(
      recordId,
      `merge chain deeper than ${MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH}`,
    );
  }

  return {
    canonicalIdentity,

    async resolveExecutiveContext(input) {
      const binding = await deps.aliases.resolveAlias(
        input.actor,
        input.normalizedAlias,
      );
      if (binding === null) return null;

      const named = binding.binding.canonicalParticipantId;
      const canonicalRecordId = await canonicalIdentity(input.actor, named);

      // The AUTHORITATIVE read. `retrieve` answers null for a deleted or
      // erased record, which is the behaviour a context consumer needs: a
      // destroyed identity must not come back as context.
      const record = await deps.store.retrieve(input.actor, canonicalRecordId);
      if (record === null) {
        // NULL MEANS "NO MEMORY" ONLY WHEN NOTHING WAS FOLLOWED. Falsified
        // against b3efc82: once an alias had been REDIRECTED to a survivor
        // that is not retrievable, answering null reported "no memory for
        // this contact" while the absorbed record the alias actually names
        // still held content — resolution hiding evidence. A redirect to
        // nothing is not an absence; it is resolution that could not be
        // completed, and it is refused as such so a consumer marks memory
        // UNAVAILABLE rather than empty.
        if (canonicalRecordId !== named) {
          throw new MemoryCanonicalResolutionFailed(
            named,
            `canonical record ${canonicalRecordId} is not retrievable`,
          );
        }
        return null;
      }

      return {
        canonicalRecordId,
        resolvedFrom: canonicalRecordId === named ? null : named,
        record,
      };
    },

    async reconcilePending(limit) {
      const settled = await deps.reconciler.reconcileAll(limit);
      return settled.length;
    },

    completePendingErasures(limit) {
      return deps.store.completePendingAliasErasures(limit);
    },

    settleKeyDestruction(request) {
      return deps.store.settleKeyDestruction(request);
    },

    listKeyDestructionObligations(input) {
      return deps.store.listKeyDestructionObligations(input);
    },
  };
}
