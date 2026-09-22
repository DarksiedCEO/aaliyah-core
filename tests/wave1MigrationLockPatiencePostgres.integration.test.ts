import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { MIGRATION_BOUNDS } from "../src/persistence/postgres/pool";

/**
 * R2.4 — A SECOND MIGRATOR WAITS FOR A SLOW FIRST ONE; IT DOES NOT CRASH AT BOOT.
 *
 * Candidate-4 reliability R-04, re-executed before this file was written: with
 * the ledger lock held for longer than `MIGRATION_BOUNDS.lockTimeoutMs`, a
 * second `runMailMigrations` was REJECTED with 55P03 at the 120s mark — and
 * `src/server.ts` turns that into `process.exit(1)`, every boot, for as long as
 * the first migration runs. The wait is now retried in bounded attempts up to
 * `ledgerLockTotalWaitMs`.
 *
 * Deliberately SLOW (about two minutes): the defect only exists past the old
 * single-attempt bound, so the test has to hold the lock past it. In a file of
 * its own so it runs beside the rest of the suite rather than in series.
 */

const ADMIN_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";
const DB = "aaliyah_lock_patience";

let adminPool: Pool;

before(async () => {
  adminPool = new Pool({ connectionString: ADMIN_URL, max: 1 });
  adminPool.on("error", () => undefined);
  await adminPool.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${DB}`);
});

after(async () => {
  await adminPool.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
  await adminPool.end();
});

test("R2.4: the migrators' total patience outlasts the work it waits for — the bounds are related, not independent", () => {
  // R-04's falsifier: nothing compared the waiter's patience with the waited-on
  // work. A waiter that gives up before a dozen maximal statements have run is
  // a crash-loop in a rolling deploy.
  assert.ok(
    MIGRATION_BOUNDS.ledgerLockTotalWaitMs >= 12 * MIGRATION_BOUNDS.statementTimeoutMs,
    `a waiter gives up after ${MIGRATION_BOUNDS.ledgerLockTotalWaitMs}ms, less than twelve ${MIGRATION_BOUNDS.statementTimeoutMs}ms statements`,
  );
  assert.ok(
    MIGRATION_BOUNDS.lockTimeoutMs < MIGRATION_BOUNDS.ledgerLockTotalWaitMs,
    "one attempt must be shorter than the total, or nothing is ever retried",
  );
  assert.ok(MIGRATION_BOUNDS.queryTimeoutMs > MIGRATION_BOUNDS.statementTimeoutMs);
});

test("R2.4: a second migrator held past the single-attempt bound WAITS, says so, and then succeeds", async () => {
  const url = ADMIN_URL.replace(/\/[^/]+$/, `/${DB}`);
  const holder = new Pool({ connectionString: url, max: 1 });
  holder.on("error", () => undefined);
  const pool = new Pool({ connectionString: url, max: 2 });
  pool.on("error", () => undefined);
  const warnings: string[] = [];
  const write = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    const text = String(chunk);
    if (text.includes("migration_waiting_for_another_migrator")) warnings.push(text);
    return (write as (c: string | Uint8Array, ...r: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
  const held = await holder.connect();
  let release: NodeJS.Timeout | undefined;
  try {
    await held.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", ["aaliyah_mail_migrations"]);
    const holdMs = MIGRATION_BOUNDS.lockTimeoutMs + 5_000;
    release = setTimeout(() => {
      void held.query("SELECT pg_advisory_unlock_all()").catch(() => undefined);
    }, holdMs);
    const started = Date.now();
    const outcome = await runMailMigrations(pool).then(
      () => "fulfilled",
      (error: { code?: string; message?: string }) => `rejected ${error.code ?? ""} ${error.message ?? ""}`,
    );
    const elapsed = Date.now() - started;
    assert.equal(outcome, "fulfilled", `the second migrator crashed instead of waiting: ${outcome}`);
    assert.ok(elapsed >= holdMs - 1_000, `it finished in ${elapsed}ms, before the lock was released — it never waited`);
    assert.ok(warnings.length >= 1, "a migrator waited past a whole attempt and said nothing");
    assert.match(warnings[0]!, /"attempt":1/);
  } finally {
    clearTimeout(release);
    process.stderr.write = write;
    await held.query("SELECT pg_advisory_unlock_all()").catch(() => undefined);
    held.release();
    await pool.end().catch(() => undefined);
    await holder.end().catch(() => undefined);
  }
});
