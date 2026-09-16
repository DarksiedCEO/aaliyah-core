import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";

/**
 * W1BR-014 — MIGRATIONS ARE NOT INDEPENDENTLY REPLAYABLE.
 *
 * Several migrations use CREATE OR REPLACE to HARDEN a definition an earlier
 * one introduced. Migration 033 redefines `aaliyah_memory_jsonb_numbers` and
 * `aaliyah_memory_reject_inexact_numbers` as `public.`-qualified with a pinned
 * `search_path`; migration 027 defines them unqualified. Replaying 027 after
 * 033 silently reverts that hardening, and the only symptom is a search-path
 * shadowing test failing somewhere else entirely.
 *
 * This was encountered exactly that way — by deleting a migration row to
 * restore a mutant and re-running — not by reasoning about it in advance.
 *
 * These run on a database of their own, because they delete migration rows and
 * a suite that shared a database with them would be running against a schema
 * mid-repair.
 */

const ADMIN_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";
const REPLAY_DB = "aaliyah_replay_test";
const REPLAY_URL = ADMIN_URL.replace(/\/[^/]+$/, `/${REPLAY_DB}`);

let adminPool: Pool;
let replayPool: Pool;

before(async () => {
  adminPool = new Pool({ connectionString: ADMIN_URL, max: 2 });
  await adminPool.query(`DROP DATABASE IF EXISTS ${REPLAY_DB} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${REPLAY_DB}`);
  replayPool = new Pool({ connectionString: REPLAY_URL, max: 2 });
});

after(async () => {
  await replayPool.end();
  await adminPool.query(`DROP DATABASE IF EXISTS ${REPLAY_DB} WITH (FORCE)`);
  await adminPool.end();
});

test("migrations apply cleanly from an EMPTY database — the positive control", async () => {
  // Without this, the refusal below would pass against a runner that refused
  // to migrate anything at all.
  await runMailMigrations(replayPool);
  const applied = await replayPool.query(
    `SELECT count(*)::int AS n FROM aaliyah_mail_migrations`,
  );
  assert.ok(
    (applied.rows[0].n as number) >= 42,
    "every migration must have applied",
  );
  // And the hardened definition is the one that is live: 033's version pins
  // its search_path, 027's does not.
  const definition = await replayPool.query(
    `SELECT pg_get_functiondef(oid) AS def FROM pg_proc
      WHERE proname = 'aaliyah_memory_jsonb_numbers'`,
  );
  assert.match(String(definition.rows[0].def), /SET search_path/);
});

test("running migrations again is a no-op, not a replay", async () => {
  await runMailMigrations(replayPool);
  const before = await replayPool.query(
    `SELECT count(*)::int AS n FROM aaliyah_mail_migrations`,
  );
  await runMailMigrations(replayPool);
  const after = await replayPool.query(
    `SELECT count(*)::int AS n FROM aaliyah_mail_migrations`,
  );
  assert.equal(after.rows[0].n, before.rows[0].n);
});

test("W1BR-014: replaying an OLDER migration is REFUSED, so later hardening cannot be reverted", async () => {
  await runMailMigrations(replayPool);

  // Exactly the operator action that caused this: delete a row to re-apply a
  // migration, believing it is a repair.
  await replayPool.query(
    `DELETE FROM aaliyah_mail_migrations WHERE id = '027_memory_exact_numeric_domain'`,
  );

  await assert.rejects(
    () => runMailMigrations(replayPool),
    (error: unknown) => {
      // Pinned: a bare rejects() would pass on a connection error and prove
      // nothing about ordering.
      assert.match(String(error), /is older than migration ordinal/);
      assert.match(String(error), /027_memory_exact_numeric_domain/);
      return true;
    },
  );

  // AND THE HARDENING SURVIVED. The refusal happens before any SQL runs, so
  // 033's pinned-search_path definition is still the live one.
  const definition = await replayPool.query(
    `SELECT pg_get_functiondef(oid) AS def FROM pg_proc
      WHERE proname = 'aaliyah_memory_jsonb_numbers'`,
  );
  assert.match(String(definition.rows[0].def), /SET search_path/);

  // Put the row back so the rest of the file runs against a consistent ledger.
  await replayPool.query(
    `INSERT INTO aaliyah_mail_migrations (id)
     VALUES ('027_memory_exact_numeric_domain')`,
  );
});

test("W1BR-014: the refusal is about ORDER, not about that one migration", async () => {
  await runMailMigrations(replayPool);
  // A different, much later migration — the rule is general.
  await replayPool.query(
    `DELETE FROM aaliyah_mail_migrations WHERE id = '038_memory_one_authorization_one_mutation'`,
  );

  await assert.rejects(
    () => runMailMigrations(replayPool),
    /038_memory_one_authorization_one_mutation is older than migration ordinal/,
  );

  await replayPool.query(
    `INSERT INTO aaliyah_mail_migrations (id)
     VALUES ('038_memory_one_authorization_one_mutation')`,
  );
});

test("W1BR-014: deleting the HIGHEST applied migration is allowed to re-apply", async () => {
  // The bound. Re-applying the newest migration reverts nothing, because
  // nothing later exists to revert — so the guard must NOT refuse it, or an
  // ordinary re-run after an interrupted deploy would be impossible.
  await runMailMigrations(replayPool);
  const highest = await replayPool.query(
    `SELECT id FROM aaliyah_mail_migrations ORDER BY id DESC LIMIT 1`,
  );
  const id = highest.rows[0].id as string;
  await replayPool.query(`DELETE FROM aaliyah_mail_migrations WHERE id = $1`, [
    id,
  ]);

  await runMailMigrations(replayPool);

  const reapplied = await replayPool.query(
    `SELECT count(*)::int AS n FROM aaliyah_mail_migrations WHERE id = $1`,
    [id],
  );
  assert.equal(reapplied.rows[0].n, 1);
});

test("a migration id without a three-digit ordinal fails loudly rather than sorting arbitrarily", async () => {
  await runMailMigrations(replayPool);
  await replayPool.query(
    `INSERT INTO aaliyah_mail_migrations (id) VALUES ('hotfix_manual_patch')`,
  );

  await assert.rejects(
    () => runMailMigrations(replayPool),
    /does not begin with a three-digit ordinal/,
  );

  await replayPool.query(
    `DELETE FROM aaliyah_mail_migrations WHERE id = 'hotfix_manual_patch'`,
  );
});
