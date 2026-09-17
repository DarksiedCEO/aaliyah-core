import type { Pool, PoolClient } from "pg";

/**
 * A MUTUAL EXCLUSION BETWEEN TEST FILES THAT TRUNCATE THE SAME TABLES.
 *
 * `node --test` runs test FILES in parallel processes. Two files that both
 * `TRUNCATE memory_record_versions, memory_authorization_receipts,
 * memory_authorization_nonces, memory_mutation_receipts` therefore delete each
 * other's fixtures mid-run, and the failure that produces is not a flake in
 * either file — it is two suites racing for one database.
 *
 * The fix is a SESSION-level PostgreSQL advisory lock, held on a dedicated
 * connection for the whole file. It is real mutual exclusion in the database,
 * not a sleep, not a retry, and not a reordering that happens to work today.
 * Any future file that touches these tables must take the same lock.
 *
 * The lock is SESSION scope, not transaction scope, precisely because it has to
 * outlive every transaction the file opens. It is released in `after`, and a
 * process that dies without releasing drops its connection, which releases it.
 */

/**
 * The key. An arbitrary but FIXED bigint; every holder must use this exact
 * value or the exclusion is not an exclusion.
 */
const MEMORY_TABLES_LOCK_KEY = 728_133_001;

/**
 * THE WAIT IS BOUNDED. A file that died holding this lock on a connection the
 * server has not yet noticed is gone would otherwise block every other memory
 * file forever — a hang with no verdict. The bound is set explicitly on this
 * session, overriding the suite-wide `lock_timeout` / `statement_timeout`
 * (scripts/test-watchdog.mjs), because waiting for another FILE is legitimately
 * longer than waiting for another statement. It stays below the watchdog's
 * per-file timeout so this refusal, with its reason, is what gets reported.
 */
export const SHARED_TABLE_LOCK_WAIT_MS = 200_000;

export type SharedTableLock = { release(): Promise<void> };

/** Acquire the lock, blocking until the other file's suite has finished. */
export async function lockSharedMemoryTables(
  pool: Pool,
): Promise<SharedTableLock> {
  const client: PoolClient = await pool.connect();
  try {
    await client.query(`SET lock_timeout = ${SHARED_TABLE_LOCK_WAIT_MS}`);
    await client.query(`SET statement_timeout = ${SHARED_TABLE_LOCK_WAIT_MS}`);
    await client.query("SELECT pg_advisory_lock($1)", [MEMORY_TABLES_LOCK_KEY]);
  } catch (error) {
    client.release(true);
    throw new Error(
      `shared memory-table lock not acquired within ${SHARED_TABLE_LOCK_WAIT_MS}ms: ` +
        String((error as Error).message),
    );
  }
  return {
    async release() {
      try {
        await client.query("SELECT pg_advisory_unlock($1)", [
          MEMORY_TABLES_LOCK_KEY,
        ]);
      } finally {
        client.release();
      }
    },
  };
}
