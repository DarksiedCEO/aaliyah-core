import type { Pool } from "pg";
import { enterMemoryRole } from "./pool";

import {
  createWave1MemoryService,
  type MemoryIdentityGraphReader,
  type Wave1MemoryService,
} from "../../application/memory/wave1MemoryService";
import type { TrustedMemoryActor } from "../../application/memory/wave1TrustedMemory";
import { createPostgresAliasRegistryStore } from "./wave1AliasRegistryStore";
import { createPostgresMemoryReconciler } from "./wave1MemoryReconciler";
import { createPostgresTrustedMemoryStore } from "./wave1TrustedMemoryStore";
import type { MemoryPiiKeyProvider } from "../../crypto/memoryPiiKeys";

/**
 * THE MERGE GRAPH, READ-ONLY.
 *
 * Runs under the SELECT-only reader role. It cannot write an edge, cannot
 * append a version, and cannot consume an authorization — so "resolving an
 * identity never changes one" is a privilege boundary rather than a property
 * of this file's control flow.
 *
 * Scoped on ALL FOUR dimensions, not merely tenant and workspace. An edge is
 * written under a principal and a user, and a resolver that filtered on two of
 * them would let one principal's merge redirect another principal's reads —
 * the read-side form of the takeover migration 039 closed for genesis.
 */
export function createPostgresIdentityGraph(
  pool: Pool,
  options: { readerRole?: string | null } = {},
): MemoryIdentityGraphReader {
  const readerRole =
    options.readerRole === undefined ? "aaliyah_memory_reader" : options.readerRole;
  if (readerRole !== null && !/^[a-z_][a-z0-9_]*$/.test(readerRole)) {
    throw new Error(`identity graph: ${readerRole} is not a valid role identifier`);
  }

  return {
    async mergedInto(actor: TrustedMemoryActor, recordId: string) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        // Least privilege AND a pinned search path (K-07): `"$user"` off the
        // path, `pg_temp` last. Called UNCONDITIONALLY — the null-role guard
        // that used to wrap this skipped the path pinning too, which is the
        // one part that matters even when no role is dropped into.
        await enterMemoryRole(client, readerRole);
        const result = await client.query(
          `SELECT to_record_id
             FROM memory_identity_edges
            WHERE tenant_id = $1 AND workspace_id = $2
              AND principal_id = $3 AND user_id = $4
              AND from_record_id = $5
              AND kind = 'merged_into'
            ORDER BY id DESC
            LIMIT 1`,
          [
            actor.tenantId,
            actor.workspaceId,
            actor.principalId,
            actor.userId,
            recordId,
          ],
        );
        await client.query("COMMIT");
        return (result.rows[0]?.to_record_id as string | undefined) ?? null;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

/**
 * THE PRODUCTION COMPOSITION OF THE MEMORY SERVICE.
 *
 * Kept here, next to the graph reader, rather than in the application layer,
 * because it is the one place that knows about pools. The application module
 * takes interfaces and has no PostgreSQL dependency at all, which is what lets
 * a consumer be tested without one.
 *
 * TWO POOLS, DELIBERATELY. The store's post-commit read-back has to run on a
 * connection that is not the mutating one, and `createPostgresAliasRegistryStore`
 * refuses to be built with a single pool for exactly that reason.
 */
export function createPostgresWave1MemoryService(
  writePool: Pool,
  readPool: Pool,
  options: {
    /**
     * The PII key provider aliases are encrypted, indexed and erased under.
     * REQUIRED to be stated: null is an explicit "none", under which the alias
     * registry stores and resolves nothing (migration 047 has no plaintext to
     * fall back to) and a deletion reports its alias erasure incomplete.
     */
    piiKeys: MemoryPiiKeyProvider | null;
  },
): Wave1MemoryService {
  const store = createPostgresTrustedMemoryStore(writePool, readPool, {
    piiKeys: options.piiKeys,
  });
  return createWave1MemoryService({
    store,
    aliases: createPostgresAliasRegistryStore(writePool, readPool, {
      piiKeys: options.piiKeys,
    }),
    identityGraph: createPostgresIdentityGraph(readPool),
    reconciler: createPostgresMemoryReconciler(writePool),
  });
}
