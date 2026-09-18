import { Pool } from "pg";
import type { QueryResult } from "pg";

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
  /**
   * THE CLIENT'S OWN CEILING, BECAUSE EVERY BOUND ABOVE IS THE SERVER'S.
   *
   * Found by the 03581a3 reliability review (K-05): `statement_timeout`,
   * `lock_timeout` and `idle_in_transaction_session_timeout` are all enforced
   * by the PostgreSQL BACKEND, so they bound a backend that is running. They
   * bound nothing when the backend is not running its own timers — a
   * SIGSTOPped backend held boot 30 SECONDS past its 10s bound, because the
   * process was simply waiting for bytes that were never coming.
   *
   * Deliberately ABOVE `statementTimeoutMs`: when the server is alive, its own
   * error should win, because `57014 statement timeout` says what happened and
   * `Query read timeout` does not. This fires only when the server never
   * answers at all.
   *
   * A query that trips it leaves the connection AMBIGUOUS. node-postgres
   * rejects the caller and stops listening, but it does not cancel the
   * backend and does not close the socket, so a result for the abandoned
   * query can still arrive on that connection afterwards. Such a connection
   * must be DESTROYED, never returned to the pool — see `isConnectionAmbiguous`
   * and `releaseClient`.
   */
  queryTimeoutMs: 35_000,
  /**
   * A dead peer that never sends a FIN is indistinguishable from a silent one.
   * Keepalives make the kernel ask, so a severed connection surfaces as an
   * error instead of as a wait with no end.
   */
  keepAliveInitialDelayMillis: 10_000,
} as const;

/**
 * BOUNDS FOR WORK THAT IS LEGITIMATELY SLOWER THAN A REQUEST.
 *
 * Migrations take DDL over populated tables and legitimately wait behind
 * another instance's migration during a rolling deploy; `runMailMigrations`
 * already raises the server's own bounds with `SET LOCAL`. The client ceiling
 * has to be raised WITH them — a 35s client timeout over a 300s server bound
 * would abandon a perfectly healthy migration mid-DDL and leave the operator
 * with an ambiguous outcome, which is worse than waiting.
 */
export const MIGRATION_BOUNDS = {
  lockTimeoutMs: 120_000,
  statementTimeoutMs: 300_000,
  /** Above `statementTimeoutMs`, for the same reason as the pool's. */
  queryTimeoutMs: 330_000,
} as const;

/**
 * A QUERY WITH ITS OWN CLIENT-SIDE CEILING.
 *
 * node-postgres honours `query_timeout` PER QUERY — `config.query_timeout ||
 * this.connectionParameters.query_timeout` in `pg/lib/client.js` — but the
 * property is missing from `@types/pg`'s `QueryConfig`, so reaching a real
 * feature of the driver needs this one cast, in one place, rather than a cast
 * at every call site.
 *
 * Used where the SERVER's bound is deliberately wider than the pool's default
 * (migrations) and where a caller needs a TIGHTER ceiling than the pool's
 * (a provider-adjacent path that must not sit on a pool slot).
 */
export type BoundedQuery = (text: string, values?: unknown[]) => Promise<QueryResult>;

export function boundedQuery(
  client: { query: unknown },
  queryTimeoutMs: number,
): BoundedQuery {
  const run = client.query as (config: {
    text: string;
    values: unknown[] | undefined;
    query_timeout: number;
  }) => Promise<QueryResult>;
  return (text, values) => run.call(client, { text, values, query_timeout: queryTimeoutMs });
}

/**
 * ENTER A LEAST-PRIVILEGE ROLE ON A PINNED SEARCH PATH.
 *
 * ONE function, used by every store, because the property it carries is one a
 * caller must not be able to forget.
 *
 * Red team B2 / security NEW-1 against 8a0bf05, MEDIUM, with a working proof
 * of concept (K-07): the stores name their tables UNQUALIFIED under
 * `SET LOCAL ROLE`, on PostgreSQL's default search path of `"$user", public`.
 * With `GRANT CREATE ON DATABASE`, the mutator can create a schema called
 * `aaliyah_memory_mutator` — which `"$user"` resolves to FIRST. `ATK-P1` did
 * exactly that, shadowed `memory_identity_edges`, and a survivor's subject
 * erasure then verified over a LIVE data key with forged evidence: key
 * `active`, and a ciphertext copy still decrypting to the subject's address.
 * The declared privilege map could not see the grant either, so the
 * regression would not have been caught by the test that exists for it.
 *
 * Qualifying every identifier closes it one statement at a time and reopens
 * the moment somebody adds the next one. This closes it for every statement,
 * including the ones not written yet.
 *
 * ---- WHAT IS REMOVED, AND WHAT IS DELIBERATELY KEPT --------------------
 *
 * Exactly two entries are stripped, and neither is something an operator ever
 * chooses:
 *
 *   `"$user"`  is the attack. It is on PostgreSQL's DEFAULT path, it resolves
 *              to a schema named after the CURRENT ROLE, and a role holding
 *              CREATE on the database can therefore create its own shadow of
 *              any table this store reads — which is precisely what ATK-P1
 *              did. `SET LOCAL ROLE` does not apply a role's own `ALTER ROLE
 *              ... SET search_path`, so with `"$user"` gone the entered role
 *              has no way to influence name resolution at all.
 *   `pg_temp`  is searched FIRST when it is not named, so it is re-appended
 *              LAST instead — the same reason every SECURITY DEFINER guard
 *              from migration 048 onward spells it out. Red team B2 created
 *              `pg_temp.memory_identity_edges` and had it resolve unqualified.
 *
 * Every OTHER schema the session was configured with is KEPT, in order. That
 * is not a concession: an explicit schema list on a connection string is set
 * by whoever deploys the process, and a store that silently discarded it would
 * be overriding its operator rather than defending against an attacker. It is
 * also what lets a read-back pool be pointed at a deliberately divergent
 * schema — the mechanism a dozen tests use to prove this store never reports
 * success on a read-back that disagrees with the commit, which is the single
 * most important property in this file.
 *
 * Computed in ONE statement, inside the transaction, so there is no extra
 * round trip on the hot path and no window where the path is the default one.
 * `SET LOCAL` / `set_config(..., true)` throughout, so neither the role nor
 * the path leaks onto a pooled connection when the transaction ends.
 *
 * ---- AND THE COMPARISON IS CASE-INSENSITIVE ---------------------------
 *
 * Red team against 86d33c9, MEDIUM (B3): this compared literal lowercase
 * strings, and a search_path carries the casing whoever set it wrote — so
 * `$User` or `$USER` survived the strip and still resolved to the current
 * role's schema. Delivered through `PGOPTIONS`, the effective path became
 * `pg_catalog, aaliyah_memory_mutator, public`. ATK-P1's HARM did not
 * reproduce, because the erasure SQL is `public.`-qualified and all 44 guards
 * pin their own path — but "`$user` is stripped" has to be TRUE, and the test
 * asserting it was itself case-sensitive and could not see the difference.
 */
const PINNED_SEARCH_PATH_SQL = `
  SELECT set_config('search_path',
    'pg_catalog, ' ||
    COALESCE(NULLIF((
      -- WITH ORDINALITY and an explicit ORDER BY: a search path is an ORDERED
      -- list, and string_agg without one is not obliged to preserve it.
      SELECT string_agg(btrim(part), ', ' ORDER BY ord)
        FROM unnest(string_to_array(current_setting('search_path'), ','))
               WITH ORDINALITY AS t(part, ord)
       -- CASE-INSENSITIVELY: see the note above this statement (B3).
       WHERE lower(btrim(part)) NOT IN ('"$user"', '$user', 'pg_catalog', 'pg_temp')
         AND btrim(part) <> ''
    ), ''), 'public') || ', pg_temp', true)`;

export async function enterMemoryRole(
  client: { query: (sql: string) => Promise<unknown> },
  role: string | null,
): Promise<void> {
  await client.query(PINNED_SEARCH_PATH_SQL);
  if (role === null) return;
  await client.query(`SET LOCAL ROLE "${role}"`);
}

/**
 * A CONNECTION WHOSE LAST QUERY'S OUTCOME IS UNKNOWN IS NOT REUSABLE.
 *
 * Three shapes, all of which leave bytes that belong to an abandoned query
 * either in flight or already lost:
 *   - the client's own read timeout, which stops listening without cancelling;
 *   - the backend gone (`57P01` admin shutdown, `25P03` idle-in-transaction
 *     kill, class `08` connection exceptions);
 *   - the socket broken under us.
 * Returning any of them to the pool hands the NEXT caller a connection that
 * may answer with the previous caller's result. Destroy instead: the pool
 * opens a fresh one on the next checkout.
 */
export function isConnectionAmbiguous(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code === "string") {
    if (code === "57P01" || code === "25P03" || code === "ECONNRESET" || code === "EPIPE") {
      return true;
    }
    if (code.startsWith("08")) return true;
  }
  const message = String((error as { message?: unknown } | null)?.message ?? "");
  return (
    /Query read timeout/i.test(message) ||
    /Connection terminated/i.test(message) ||
    /connection is closed/i.test(message) ||
    /socket hang up/i.test(message)
  );
}

/**
 * Release a pooled client, destroying it when the last query's outcome is
 * unknown. `release(true)` is node-postgres' destroy path.
 */
export function releaseClient(
  client: { release: (destroy?: boolean) => void },
  error?: unknown,
): void {
  client.release(error !== undefined && isConnectionAmbiguous(error) ? true : undefined);
}

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
      // The client's own ceiling, and the kernel's. See the bounds above.
      query_timeout: MAIL_DB_POOL_BOUNDS.queryTimeoutMs,
      keepAlive: true,
      keepAliveInitialDelayMillis: MAIL_DB_POOL_BOUNDS.keepAliveInitialDelayMillis,
    }),
    options.name ?? "mail",
    options.onError,
  );
}
