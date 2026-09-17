import { Pool } from "pg";

/**
 * THE BOUNDS EVERY DURABLE-STATE CONNECTION CARRIES.
 *
 * Found by the b3efc82 reliability review: this factory set only `max`, and
 * `grep -rn "statement_timeout|lock_timeout|connectionTimeoutMillis" src/`
 * returned nothing. A held advisory lock kept `store.create()` pending past 8s
 * with no error and no fallback, occupying a pool slot the whole time — and
 * nothing bounded it. Each value below is sent as a startup parameter, so it
 * holds for every statement on every connection this pool opens, including
 * the ones a caller forgets to bound. A transaction that needs a DIFFERENT
 * bound sets it explicitly with `SET LOCAL`.
 */
export const MAIL_DB_POOL_BOUNDS = {
  max: 10,
  /** Waiting for a free pooled client, or for a new connection to open. */
  connectionTimeoutMillis: 10_000,
  /** Any single statement. */
  statementTimeoutMs: 30_000,
  /** Waiting for any lock, including a transaction-scoped advisory lock. */
  lockTimeoutMs: 10_000,
  /** A session left idle inside an open transaction is terminated. */
  idleInTransactionSessionTimeoutMs: 60_000,
} as const;

export type PoolErrorEvent = {
  pool: string;
  code: string | null;
  message: string;
};

export type PoolErrorSink = (event: PoolErrorEvent) => void;

const stderrSink: PoolErrorSink = (event) => {
  process.stderr.write(
    `${JSON.stringify({ level: "error", event: "postgres_idle_client_error", ...event })}\n`,
  );
};

/**
 * AN IDLE-CONNECTION ERROR IS LOGGED, NOT FATAL.
 *
 * node-postgres re-emits an error on an IDLE pooled client as an `'error'`
 * event on the pool. With no listener, Node throws it: the reliability review
 * killed the database container under a process holding one idle client per
 * pool, exactly as `src/server.ts` does at boot, and the process died with an
 * uncaught `57P01` — every concurrent in-flight request destroyed at once, the
 * SIGTERM drain path bypassed, and under a sustained outage a crash loop. The
 * pool has already discarded the broken client when this fires; the next
 * checkout opens a fresh connection. There is nothing to recover beyond
 * recording that it happened.
 *
 * A CHECKED-OUT CLIENT NEEDS ITS OWN LISTENER. Found by the 2b2e554
 * reliability review: pg-pool removes its idle listener the moment a client is
 * checked out and re-attaches it only on release, so the pool-level listener
 * covers idle clients only. When a backend dies mid-transaction, the in-flight
 * query rejects catchably, but the client ALSO emits `'error'` — and the
 * store's own `ROLLBACK ... .catch(() => undefined)` on that dead client then
 * crashed the process from outside every promise chain. Every client this pool
 * opens therefore carries a permanent listener from the moment it connects,
 * idle or not. The failure itself still reaches the caller: the query that hit
 * the dead connection rejects, and so does anything issued after it.
 *
 * The sink is called inside a try: a logger that throws must not re-create the
 * crash this listener exists to prevent.
 */
export function guardPoolErrors(
  pool: Pool,
  name: string,
  sink: PoolErrorSink = stderrSink,
): Pool {
  const record = (error: Error & { code?: string }) => {
    try {
      sink({
        pool: name,
        code: typeof error?.code === "string" ? error.code : null,
        message: String(error?.message ?? error),
      });
    } catch {
      // Deliberately swallowed. See above.
    }
  };
  pool.on("error", record);
  pool.on("connect", (client) => {
    client.on("error", record);
  });
  return pool;
}

/**
 * Durable mail-state pool. Fails closed: without an explicit database URL
 * there is no silent fallback to anything in-memory — callers must decide,
 * visibly, which backend they run.
 */
export function createMailDbPool(
  env: NodeJS.ProcessEnv = process.env,
  options: { name?: string; onError?: PoolErrorSink } = {},
): Pool {
  const url = env.AALIYAH_DATABASE_URL;
  if (!url) {
    throw new Error("durable mail state not configured: AALIYAH_DATABASE_URL is required");
  }
  return guardPoolErrors(
    new Pool({
      connectionString: url,
      max: MAIL_DB_POOL_BOUNDS.max,
      connectionTimeoutMillis: MAIL_DB_POOL_BOUNDS.connectionTimeoutMillis,
      statement_timeout: MAIL_DB_POOL_BOUNDS.statementTimeoutMs,
      lock_timeout: MAIL_DB_POOL_BOUNDS.lockTimeoutMs,
      idle_in_transaction_session_timeout:
        MAIL_DB_POOL_BOUNDS.idleInTransactionSessionTimeoutMs,
    }),
    options.name ?? "mail",
    options.onError,
  );
}
