import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { Pool } from "pg";
import type { PoolClient } from "pg";

import {
  createLedgerToleratingARace,
  LEDGER_RACE_LOST,
  migrationDigest,
  MIGRATIONS,
  runMailMigrations,
} from "../src/persistence/postgres/migrations";
import { MIGRATION_BOUNDS } from "../src/persistence/postgres/pool";

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

/** Re-insert a ledger row a test deleted, with the digest it had. */
async function restoreLedgerRow(id: string): Promise<void> {
  const migration = MIGRATIONS.find((m) => m.id === id);
  assert.ok(migration, `no migration ${id}`);
  await replayPool.query(
    `INSERT INTO aaliyah_mail_migrations (id, sql_digest) VALUES ($1, $2)`,
    [id, migrationDigest(migration.sql)],
  );
}

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
    `SELECT id FROM aaliyah_mail_migrations ORDER BY id`,
  );
  // EXACTLY the build's migrations (R3.5, candidate-4 gate 1 F3). This read
  // `>= 42` against a true count of 60, so eighteen migrations — 043..060, all
  // of the W1.3 hardening — could silently not apply with this assertion,
  // whose message is "every migration must have applied", still true.
  assert.deepEqual(
    applied.rows.map((r) => r.id),
    MIGRATIONS.map((m) => m.id),
    "every migration must have applied — exactly this build's set",
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

  // Put the row back EXACTLY as it was, digest included, so the rest of the
  // file runs against a consistent ledger. (Restoring the id alone left a NULL
  // digest, which R2.1 now refuses as the D-03 L5 shape — correctly.)
  await restoreLedgerRow("027_memory_exact_numeric_domain");
});

test("the migrator leaves NO session state on the connection it returns — success AND refusal", async () => {
  // ---- WHAT THE MIGRATOR'S SESSION STATE MUST NOT LEAVE BEHIND ------
  // The runner takes a session advisory lock (restored in c2e5747; an earlier
  // version of this comment said it was gone — candidate-4 I-7) and raises
  // `lock_timeout` and, since R2.4, `statement_timeout` for its wait. Both are
  // real session state that outlives the transaction, and the `finally` block
  // that resets it is gated on the CONNECTION's health rather than on "did
  // anything throw" — because the first version of that gate returned a
  // perfectly healthy connection to the pool with migrator state still on it,
  // and W1BR-014's ordinary refusal was the path that did it.
  //
  // `pg_locks` is server-wide, so the existing lock assertions can be made
  // from any connection. A GUC is NOT: `SHOW lock_timeout` on a fresh pool
  // says nothing about the migrator's session. So this asks the MIGRATOR'S OWN
  // pool, with `max: 1`, which hands back the same backend.
  await withFreshDatabase("session_state", async (url) => {
    const pool = new Pool({ connectionString: url, max: 1 });
    pool.on("error", () => undefined);
    try {
      const pid = async () => {
        const r = await pool.query(
          `SELECT pg_backend_pid()::int AS pid, current_setting('lock_timeout') AS lt,
                  current_setting('statement_timeout') AS st`,
        );
        return {
          pid: r.rows[0].pid as number,
          lockTimeout: String(r.rows[0].lt),
          statementTimeout: String(r.rows[0].st),
        };
      };
      // The BASELINE, not a literal: the watchdog sets its own `lock_timeout`
      // through PGOPTIONS, so a fresh connection here reads `1min`, not `0`.
      // What the runner owes the pool is the value it was GIVEN, whatever that
      // is — and `RESET` restores exactly that startup value.
      const before = await pid();
      assert.notEqual(
        before.lockTimeout,
        `${MIGRATION_BOUNDS.lockTimeoutMs}ms`,
        "fixture precondition: the baseline must differ from the migrator's raised value, or a missing reset is invisible",
      );

      // ---- THE SUCCESS PATH ----
      await runMailMigrations(pool);
      const afterSuccess = await pid();
      assert.equal(
        afterSuccess.pid,
        before.pid,
        "fixture precondition: max:1 must hand back the same backend, or this proves nothing",
      );
      assert.equal(
        afterSuccess.lockTimeout,
        before.lockTimeout,
        "the migrator left its raised lock_timeout on the connection it returned",
      );
      assert.equal(
        afterSuccess.statementTimeout,
        before.statementTimeout,
        "the migrator left its raised statement_timeout on the connection it returned (R2.4)",
      );

      // ---- AND THE REFUSAL PATH, WHICH IS THE ONE THAT BROKE ----
      await pool.query(
        `DELETE FROM aaliyah_mail_migrations WHERE id = '027_memory_exact_numeric_domain'`,
      );
      await assert.rejects(
        () => runMailMigrations(pool),
        /is older than migration ordinal/,
      );
      const afterRefusal = await pid();
      assert.equal(afterRefusal.pid, before.pid, "the refusal destroyed a healthy connection");
      assert.equal(
        afterRefusal.lockTimeout,
        before.lockTimeout,
        "an ordinary refusal returned a healthy connection carrying migrator session state",
      );
      assert.equal(
        afterRefusal.statementTimeout,
        before.statementTimeout,
        "an ordinary refusal returned a connection carrying the migrator's raised statement_timeout (R2.4)",
      );
      // No advisory lock either, from either path.
      const held = await pool.query(
        `SELECT count(*)::int AS n FROM pg_locks
          WHERE locktype = 'advisory'
            AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
      );
      assert.equal(held.rows[0].n, 0);
    } finally {
      await pool.end().catch(() => undefined);
    }
  });
});

test("K-06b: each SQLSTATE a lost ledger race can raise is tolerated, and only when the ledger really appeared", async () => {
  // ---- TESTED AT ITS OWN SEAM, AND WHY ------------------------------
  //
  // Candidate-3 crashed intermittently in full-suite runs, ~1 in 5 and never
  // in isolation, with `type "aaliyah_mail_migrations" already exists` —
  // SQLSTATE 42710, which the tolerated set did not list. `CREATE TABLE` also
  // creates a type of the same name, so a losing racer can die on `pg_type`
  // rather than on the table.
  //
  // Two ways of staging that race were tried and BOTH failed to reproduce it:
  //   - six concurrent migrators over eight fresh databases: 0 crashes in 48,
  //     because the window only opens under load;
  //   - a barrier, with a winner holding an uncommitted CREATE TABLE: the
  //     loser blocks, then RE-CHECKS after the wait and skips cleanly, which
  //     is the benign path and never 42710. A destroyer run proved that
  //     version did not discriminate: removing 42710 left it passing.
  //
  // 42710 needs the loser past its existence check BEFORE the winner commits,
  // too narrow to stage on demand. So the tolerance is exercised where it
  // lives: a `bounded` that raises each SQLSTATE and then answers the presence
  // re-check.
  for (const code of ["42P07", "23505", "42710"]) {
    let asked = 0;
    const bounded = (async (sql: string) => {
      if (/CREATE TABLE/i.test(sql)) {
        const error = new Error(`already exists (${code})`) as Error & { code: string };
        error.code = code;
        throw error;
      }
      asked += 1;
      return { rows: [{ present: true }], rowCount: 1 };
    }) as unknown as Parameters<typeof createLedgerToleratingARace>[0];

    await createLedgerToleratingARace(bounded);
    assert.equal(asked, 1, `${code}: the tolerance did not re-check that the ledger exists`);
  }

  // ---- TOLERANCE, NOT BLANKET SUPPRESSION ---------------------------
  const other = (async (sql: string) => {
    if (/CREATE TABLE/i.test(sql)) {
      const error = new Error("permission denied for schema public") as Error & { code: string };
      error.code = "42501";
      throw error;
    }
    return { rows: [{ present: true }], rowCount: 1 };
  }) as unknown as Parameters<typeof createLedgerToleratingARace>[0];
  await assert.rejects(() => createLedgerToleratingARace(other), /permission denied/);

  // A lost-race code whose ledger did NOT appear is a duplicate object from
  // something that is not this table, and must still propagate.
  const absent = (async (sql: string) => {
    if (/CREATE TABLE/i.test(sql)) {
      const error = new Error("type already exists") as Error & { code: string };
      error.code = "42710";
      throw error;
    }
    return { rows: [{ present: false }], rowCount: 1 };
  }) as unknown as Parameters<typeof createLedgerToleratingARace>[0];
  await assert.rejects(() => createLedgerToleratingARace(absent), /type already exists/);
});

test("K-06c: migrators SERIALIZE on the advisory lock before the ledger exists", async () => {
  // ---- THE LOCK'S OWN FALSIFIER, WHICH IT DID NOT HAVE --------------
  //
  // The seventh pass deleted this lock because no test failed when it was
  // removed, and recorded: "a mechanism nothing can falsify is a claim, not a
  // control". The premise was right; the conclusion was not. Nothing caught
  // the removal because nothing COVERED it — and the race it prevents came
  // back as an intermittent crash.
  //
  // A property that only shows up under load is not testable by waiting for
  // load. So the test TAKES the lock itself and requires a migrator to wait
  // for it: deterministic, and red the moment the lock is removed from the
  // runner.
  await withFreshDatabase("lock_serializes", async (url) => {
    const holder = new Pool({ connectionString: url, max: 1 });
    holder.on("error", () => undefined);
    const pool = new Pool({ connectionString: url, max: 2 });
    pool.on("error", () => undefined);
    let migratorPromise: Promise<unknown> | undefined;
    // Hoisted so the `finally` can hand it back. Released ONLY on the happy
    // path, a failed assertion left this client checked out and `holder.end()`
    // waited on it for ever — which is why removing the lock produced
    // HUNG_WORKER with no named failure instead of the assertion's own
    // message. The control worked; its cleanup buried the diagnosis.
    let held: PoolClient | undefined;
    try {
      held = await holder.connect();
      await held.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", [
        "aaliyah_mail_migrations",
      ]);

      let finished = false;
      // CAUGHT, not floating. When the assertion below fails, this promise is
      // still in flight and its pool is about to close underneath it; an
      // unhandled rejection then hangs the worker instead of reporting, which
      // is how the first version of this test "detected" the lock's removal —
      // as a HUNG_WORKER with no named failure. A destroyer that can only say
      // "something hung" is a poor control even when it is a control.
      let migratorFailure: unknown;
      const migrator = (migratorPromise = runMailMigrations(pool)
        .then(() => {
          finished = true;
        })
        .catch((error: unknown) => {
          migratorFailure = error;
        }));

      // ---- ASSERT THE BLOCK, NOT THE CLOCK ---------------------------
      //
      // This first asserted `finished === false` after 1500ms. That passes
      // whether or not the lock exists, because applying sixty migrations
      // takes longer than that anyway — it could not tell "waiting for the
      // lock" from "busy working". A destroyer run proved it: removing the
      // lock did not turn this red, it made the test HANG.
      //
      // An UNGRANTED advisory request in `pg_locks` is unambiguous. Only a
      // migrator that actually takes this lock can produce one.
      let waiting = 0;
      for (let attempt = 0; attempt < 60 && waiting === 0; attempt += 1) {
        const locks = await adminPool.query(
          `SELECT count(*)::int AS n FROM pg_locks
            WHERE locktype = 'advisory' AND NOT granted
              AND database = (SELECT oid FROM pg_database WHERE datname = $1)`,
          [new URL(url).pathname.slice(1)],
        );
        waiting = locks.rows[0].n as number;
        if (waiting === 0) await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.ok(
        waiting > 0,
        "no migrator ever waited on the ledger advisory lock — the runner is not taking it",
      );
      assert.equal(finished, false, "the migrator finished while the lock was held");

      // ---- AND IT WAITS *BEFORE* THE LEDGER EXISTS (R2.3, red team RT4-3) --
      //
      // The two assertions above are satisfied by a migrator that CREATES the
      // ledger and only then asks for the lock: an ungranted request appears
      // either way. The red team swapped the two lines (MUT-B), kept this file
      // 18/18 green, and measured the race back at N-1 of N migrators — the
      // lock taken after the creation it exists to cover protects nothing.
      // The ordering is the entire property, so it is read directly: while the
      // migrator is blocked on the lock, the ledger it would create must not
      // exist yet. This is a FRESH database; nothing else could have made it.
      const ledgerWhileBlocked = await held.query(
        `SELECT to_regclass('public.aaliyah_mail_migrations') IS NOT NULL AS present`,
      );
      assert.equal(
        ledgerWhileBlocked.rows[0].present,
        false,
        "the migrator created the ledger BEFORE taking the advisory lock — the lock no longer covers the creation it exists for",
      );

      await held.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [
        "aaliyah_mail_migrations",
      ]);

      await migrator;
      assert.equal(migratorFailure, undefined, `the migrator failed: ${String(migratorFailure)}`);
      assert.equal(finished, true);
    } finally {
      // Order matters: release the lock so a waiting migrator can finish,
      // hand the client back so the pool can close, and only then drain —
      // otherwise a failed assertion strands one of the three and the test
      // hangs instead of reporting.
      if (held !== undefined) {
        await held
          .query("SELECT pg_advisory_unlock_all()")
          .catch(() => undefined);
        held.release();
      }
      await migratorPromise?.catch(() => undefined);
      await pool.end().catch(() => undefined);
      await holder.end().catch(() => undefined);
    }
  });
});

test("the LEDGER-CREATION phase leaves no session state either, when it fails for a real reason", async () => {
  // ---- RELIABILITY REVIEW OF a9d203d, HIGH, REPRODUCED ---------------
  //
  // `runMailMigrations` used to be TWO try blocks. The first covered the
  // session `SET lock_timeout` and the ledger's CREATE TABLE, and its catch
  // was `releaseClient(client, error); throw error;` with NO finally. So a
  // real, non-race, non-ambiguous failure of that CREATE — a role without
  // CREATE on schema public, 42501 — returned a perfectly healthy connection
  // to the pool still carrying a 120s `lock_timeout`. Only the SECOND block's
  // finally reset it.
  //
  // The test written for that reset claimed "success AND refusal", and both
  // paths it exercised were inside the second block. The one path that leaked
  // was the one path neither covered, which is why this case names the PHASE
  // rather than the outcome.
  await withFreshDatabase("ledger_phase", async (url) => {
    const admin = new Pool({ connectionString: url, max: 1 });
    admin.on("error", () => undefined);
    const role = "aaliyah_ledger_phase_probe";
    try {
      await admin.query(`DROP ROLE IF EXISTS ${role}`);
      await admin.query(`CREATE ROLE ${role} LOGIN PASSWORD 'probe'`);
      // It may CONNECT and it may SET, but it may not CREATE — so the failure
      // lands exactly on the ledger's CREATE TABLE and nowhere earlier.
      await admin.query(`REVOKE CREATE ON SCHEMA public FROM ${role}`);
      await admin.query(`REVOKE CREATE ON SCHEMA public FROM PUBLIC`);
      const asRole = new URL(url);
      asRole.username = role;
      asRole.password = "probe";
      const pool = new Pool({ connectionString: asRole.href, max: 1 });
      pool.on("error", () => undefined);
      try {
        const state = async () => {
          const r = await pool.query(
            `SELECT pg_backend_pid()::int AS pid, current_setting('lock_timeout') AS lt`,
          );
          return { pid: r.rows[0].pid as number, lockTimeout: String(r.rows[0].lt) };
        };
        const before = await state();
        assert.notEqual(
          before.lockTimeout,
          `${MIGRATION_BOUNDS.lockTimeoutMs}ms`,
          "fixture precondition: the baseline must differ from the migrator's raised value",
        );

        await assert.rejects(
          () => runMailMigrations(pool),
          (error: { code?: unknown }) => {
            // PINNED to the permission failure. A bare rejects() would pass on
            // any error at all and prove nothing about which phase failed.
            assert.equal(error.code, "42501", `expected 42501, got ${String(error.code)}`);
            return true;
          },
        );

        const after = await state();
        assert.equal(
          after.pid,
          before.pid,
          "a non-ambiguous failure destroyed a healthy connection instead of cleaning it",
        );
        assert.equal(
          after.lockTimeout,
          before.lockTimeout,
          "the ledger-creation phase leaked its raised lock_timeout onto a pooled connection",
        );
      } finally {
        await pool.end().catch(() => undefined);
      }
    } finally {
      await admin.query(`GRANT CREATE ON SCHEMA public TO PUBLIC`).catch(() => undefined);
      await admin.query(`DROP ROLE IF EXISTS ${role}`).catch(() => undefined);
      await admin.end().catch(() => undefined);
    }
  });
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

  await restoreLedgerRow("038_memory_one_authorization_one_mutation");
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

test("047 REFUSES to run over an existing plaintext alias binding, and the plaintext row survives the refusal", async () => {
  // P6 survivor P3-13: disabling this refusal left the suite green, because no
  // test ever built a database that still held a plaintext binding when 047
  // arrived.
  //
  // R2: built as a GENUINE pre-047 database — migrated through 046 and never
  // further. It used to be a fully migrated database walked back by hand (the
  // plaintext column re-added, 047..049 unrecorded), and the catalog read-back
  // R2 added refused it, correctly: 047 had also dropped `skeleton` and
  // `registrable_domain`, which the walk-back never restored, so it was not a
  // pre-047 schema at all. A fixture the runner can tell is fake was testing a
  // state no real database is in.
  await withFreshDatabase("pre047", async (url) => {
    const pool = new Pool({ connectionString: url, max: 2 });
    pool.on("error", () => undefined);
    try {
      await runMailMigrations(pool, { through: "046_memory_identity_edge_bindings_not_vacuous" });
      const client = await pool.connect();
      try {
        await client.query(
          `INSERT INTO memory_alias_tenant_policy (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
           VALUES ('tenant-replay','workspace_isolated','actor.replay','alias-policy/v1')`,
        );
        await client.query("BEGIN");
        await client.query(`ALTER TABLE memory_alias_bindings DISABLE TRIGGER USER`);
        await client.query(
          `INSERT INTO memory_alias_bindings
             (tenant_id, workspace_id, principal_id, user_id, cross_workspace_policy, scope_key,
              alias_id, normalized_alias, skeleton, skeleton_algorithm, normalization_profile,
              canonical_participant_id, registrable_domain, script_code, restriction_level,
              subject_participant_id, source_evidence_ref, source_evidence_digest, observed_at,
              fresh_until, authorization_id, mutation_receipt_id, bound_at, payload)
           VALUES ('tenant-replay','workspace-replay','p','u','workspace_isolated','workspace-replay',
                   'alias-replay','plaintext.person@example.com','sk','sk','np',
                   'participant-replay','example.com','Latn','ascii_only',
                   'participant-replay','identity:x/y',$1, now(),
                   now() + interval '1 hour','auth-replay','mutation.replay', now(), $2::jsonb)`,
          [
            `sha256:${"a".repeat(64)}`,
            JSON.stringify({
              scope: { tenantId: "tenant-replay", workspaceId: "workspace-replay", principalId: "p", userId: "u" },
              aliasId: "alias-replay",
              // A pre-047 payload carries the plaintext too; 031's binding
              // CHECKs hold the columns equal to it.
              normalizedAlias: "plaintext.person@example.com",
              skeleton: "sk",
              canonicalParticipantId: "participant-replay",
              subjectParticipantId: "participant-replay",
              crossWorkspacePolicy: "workspace_isolated",
              scopeKey: "workspace-replay",
              authorizationId: "auth-replay",
              mutationReceiptId: "mutation.replay",
            }),
          ],
        );
        await client.query(`ALTER TABLE memory_alias_bindings ENABLE TRIGGER USER`);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }

      // A pre-057 ledger: the forward run needs an operator's attestation
      // (R2.2), which is not what this test is about — supplied, so the
      // refusal below can only be 047's own.
      const attest = { attestUndigestedRows: { actor: "operator:047-replay" } };
      await assert.rejects(
        () => runMailMigrations(pool, attest),
        /1 plaintext alias binding\(s\) exist; migration 047 will not drop personal identifiers it cannot first re-encrypt/,
      );
      const survived = await pool.query(
        `SELECT normalized_alias FROM memory_alias_bindings WHERE alias_id = 'alias-replay'`,
      );
      assert.equal(survived.rows[0]?.normalized_alias, "plaintext.person@example.com");

      // Positive control: with the plaintext gone, the same forward run succeeds.
      await pool.query(`ALTER TABLE memory_alias_bindings DISABLE TRIGGER USER`);
      await pool.query(`DELETE FROM memory_alias_bindings`);
      await pool.query(`ALTER TABLE memory_alias_bindings ENABLE TRIGGER USER`);
      await runMailMigrations(pool, attest);
      const column = await pool.query(
        `SELECT count(*)::int AS n FROM information_schema.columns
          WHERE table_name = 'memory_alias_bindings' AND column_name = 'normalized_alias'`,
      );
      assert.equal(column.rows[0].n, 0);
    } finally {
      await pool.end().catch(() => undefined);
    }
  });
});

/**
 * K-06 — CONCURRENT MIGRATORS ON A FRESH DATABASE.
 *
 * 03581a3 reliability review, HIGH, executed: `runMailMigrations` issued
 * `CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations` as its FIRST statement,
 * outside any lock, and only then took the table lock that serializes
 * migrators. `IF NOT EXISTS` is not atomic against a concurrent creator — 2-way
 * and 3-way runs crashed N-1 instances with `23505` on
 * `pg_type_typname_nsp_index`, the duplicate being the table's implicit ROW
 * TYPE — and `src/server.ts` turns a migration failure into `process.exit(1)`.
 * Every instance of a fresh rolling deploy but one died at boot.
 *
 * Each case below gets its OWN database, created and dropped inside the test,
 * because "fresh" is the whole precondition.
 */
async function withFreshDatabase<T>(
  suffix: string,
  body: (url: string) => Promise<T>,
): Promise<T> {
  const name = `aaliyah_concurrent_${suffix}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${name}`);
  try {
    return await body(ADMIN_URL.replace(/\/[^/]+$/, `/${name}`));
  } finally {
    await adminPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  }
}

/**
 * The ledger creation as a PRE-K-06 build issued it: no advisory lock, and the
 * table lock it then takes cannot protect a table that does not exist yet.
 * This is the other participant a real first rollout has, and it cannot be
 * made to take a lock it does not know about.
 */
async function migrateLikeAnOlderBuild(url: string): Promise<void> {
  const pool = new Pool({ connectionString: url, max: 1 });
  pool.on("error", () => undefined);
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations (
      id text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    await client.query("BEGIN");
    await client.query("LOCK TABLE aaliyah_mail_migrations IN ACCESS EXCLUSIVE MODE");
    await client.query("SELECT id FROM aaliyah_mail_migrations");
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end().catch(() => undefined);
  }
}

test("INT-DIGEST: an applied migration whose CONTENT changed is refused, and a fresh apply is fully digested", async () => {
  // ---- WHAT THE INTEGRATION REVIEW OF 86d33c9 FOUND, HIGH -----------
  // The ledger recorded only an id, so EDITING an already-applied migration's
  // SQL was completely silent. The reviewer proved it against the real
  // compiled runner: migrate through 055, weaken 055's trigger function to a
  // no-op, re-run `runMailMigrations` — success reported, weakened definition
  // still live, nothing said.
  //
  // W1BR-014 already refuses the neighbouring case (a ledger ROW deleted and
  // an older migration replayed). It did not cover "row present, content
  // edited" — and that variant is not hypothetical: it happened during this
  // round's own remediation, and the only reason anyone noticed was that T-1
  // happens to assert a property of a function 055 redefines.
  await withFreshDatabase("digest", async (url) => {
    const pool = new Pool({ connectionString: url, max: 2 });
    pool.on("error", () => undefined);
    try {
      await runMailMigrations(pool);
      // A FRESH apply is fully digested, in ONE run. On a fresh database
      // 001..056 are applied before 057 exists, so the runner has to look
      // again afterwards — the first version of this fix did not, and left
      // every row undigested until a second run.
      const counted = await pool.query(
        `SELECT count(*)::int AS rows, count(sql_digest)::int AS digested
           FROM aaliyah_mail_migrations`,
      );
      assert.equal(
        counted.rows[0].digested,
        counted.rows[0].rows,
        `${counted.rows[0].rows - counted.rows[0].digested} applied migrations have no digest`,
      );
      assert.equal(counted.rows[0].rows, MIGRATIONS.length, "a fresh apply must record every migration");
      // Re-running is still a clean no-op.
      await runMailMigrations(pool);

      // THE REFUSAL. The digest is rewritten rather than the SQL, which is the
      // same comparison from the ledger's side and does not need a mutated
      // build to demonstrate.
      await pool.query(
        `UPDATE aaliyah_mail_migrations SET sql_digest = 'sha256:' || repeat('a', 64)
          WHERE id = $1`,
        ["055_memory_key_destruction_settlement"],
      );
      await assert.rejects(
        () => runMailMigrations(pool),
        /055_memory_key_destruction_settlement was applied with different content/,
      );
      // Refused BEFORE anything was applied: the ledger is untouched.
      const after = await pool.query(
        `SELECT count(*)::int AS n FROM aaliyah_mail_migrations`,
      );
      assert.equal(after.rows[0].n, counted.rows[0].rows);
    } finally {
      await pool.end().catch(() => undefined);
    }
  });
});

test("K-06 REOPENED: the real migrator survives a concurrent OLDER build on a FRESH database", async () => {
  // ---- WHAT THE 86d33c9 RELIABILITY REVIEW FALSIFIED ----------------
  // The first fix for K-06 serialized migrators on a session advisory lock and
  // then claimed `LOCK TABLE` would "bind a migrator running an OLDER build of
  // this function, which knows nothing about this key". It does not, and the
  // reviewer proved it 10 trials out of 10 on a fresh database: an advisory
  // lock serializes only the participants that TAKE it, an older build races
  // the `CREATE TABLE` directly, and `LOCK TABLE` cannot protect a table that
  // does not exist yet. The instance that died was the NEW one, with the
  // original defect's exact error — `23505` on `pg_type_typname_nsp_index`.
  //
  // An older build cannot be bound, so this build no longer tries to win that
  // race; it tolerates losing it. Ten trials, because one is luck.
  for (let trial = 0; trial < 10; trial += 1) {
    await withFreshDatabase(`old_new_${trial}`, async (url) => {
      const pool = new Pool({ connectionString: url, max: 2 });
      pool.on("error", () => undefined);
      try {
        const [real, older] = await Promise.allSettled([
          runMailMigrations(pool),
          migrateLikeAnOlderBuild(url),
        ]);
        // THE ASSERTION. The real migrator must fulfil whatever the other
        // participant does; the older build is allowed to lose, because
        // nothing in this repository can change what it does.
        assert.equal(
          real.status,
          "fulfilled",
          `trial ${trial}: the real migrator was crashed by an older build: ${
            real.status === "rejected" ? String(real.reason) : ""
          }`,
        );
        void older;
        const check = new Pool({ connectionString: url, max: 1 });
        check.on("error", () => undefined);
        try {
          // EXACTLY the build's set (F3): `n = count(DISTINCT id)` was true by
          // the ledger's PRIMARY KEY whatever the migrator did, and `>= 56`
          // let five migrations silently not apply.
          const ledger = await check.query(`SELECT id FROM aaliyah_mail_migrations ORDER BY id`);
          assert.deepEqual(
            ledger.rows.map((r) => r.id),
            MIGRATIONS.map((m) => m.id),
            `trial ${trial}: the ledger is not exactly this build's migrations`,
          );
          const held = await check.query(
            `SELECT count(*)::int AS n FROM pg_locks
              WHERE locktype = 'advisory'
                AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
          );
          assert.equal(held.rows[0].n, 0, `trial ${trial}: a session advisory lock survived`);
        } finally {
          await check.end();
        }
      } finally {
        await pool.end().catch(() => undefined);
      }
    });
  }
});

test("K-06: a STEADY-STATE database is raced cleanly by an older build too", async () => {
  // The reviewer measured this half as already sound (5/5). Pinned so a future
  // change to the tolerant creation cannot quietly break the ordinary case,
  // where the ledger already exists and `LOCK TABLE` really does serialize.
  await withFreshDatabase("old_new_steady", async (url) => {
    const seed = new Pool({ connectionString: url, max: 1 });
    seed.on("error", () => undefined);
    try {
      await runMailMigrations(seed);
    } finally {
      await seed.end();
    }
    const pool = new Pool({ connectionString: url, max: 2 });
    pool.on("error", () => undefined);
    try {
      for (let trial = 0; trial < 5; trial += 1) {
        const [real, older] = await Promise.allSettled([
          runMailMigrations(pool),
          migrateLikeAnOlderBuild(url),
        ]);
        assert.equal(real.status, "fulfilled", `trial ${trial}: ${real.status === "rejected" ? String(real.reason) : ""}`);
        assert.equal(older.status, "fulfilled", `trial ${trial}: the older build lost a race it should win here`);
      }
    } finally {
      await pool.end().catch(() => undefined);
    }
  });
});

test("POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash N-1, with a lost-race code the migrator tolerates", async () => {
  // Proves the hazard is real on THIS server, so the refusal below is about
  // the runner's ordering and not about `IF NOT EXISTS` being safe anyway.
  await withFreshDatabase("control", async (url) => {
    // R1.5 — THE 57P01 THAT KILLED THIS TEST WAS ITS OWN (candidate-4 gate 3
    // R-14). `pool.end()` can resolve before every socket has closed, and
    // `withFreshDatabase`'s `DROP DATABASE ... WITH (FORCE)` then terminates
    // the leftovers. With no listener, that `error` event on an already-ended
    // pool is an uncaught throw attributed to whatever test is running.
    // Measured in isolation: 2 in 200 teardowns, matched 1:1 by the server
    // log's terminations on that database. The concurrency cases below
    // already carried this listener; this one did not.
    const pools = Array.from({ length: 3 }, () => {
      const pool = new Pool({ connectionString: url, max: 1 });
      pool.on("error", () => undefined);
      return pool;
    });
    try {
      const results = await Promise.allSettled(
        pools.map((p) =>
          p.query(`CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations (
            id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`),
        ),
      );
      const codes = results
        .filter((r): r is PromiseRejectedResult => r.status === "rejected")
        .map((r) => (r.reason as { code?: string }).code);
      assert.ok(
        codes.length >= 1,
        `expected at least one concurrent creator to lose; all ${results.length} succeeded`,
      );
      // THE LOSS IS ONE PRODUCTION FORGIVES (R1.4, candidate-4 gate 3 R-11).
      // This read `code === "23505"` while `createLedgerToleratingARace`
      // tolerates `LEDGER_RACE_LOST` — 42P07, 23505 and 42710 — so a
      // legitimate 42710 loss (the ROW TYPE's name, about 1 run in 360 here)
      // failed the control, and 42P07/42710 had never been exercised by it.
      // Asserted against the PRODUCTION constant, not a re-typed list: if a
      // code the server really raises is ever dropped from the tolerance, this
      // is the test that says so.
      const unforgiven = codes.filter((code) => typeof code !== "string" || !LEDGER_RACE_LOST.has(code));
      assert.deepEqual(
        unforgiven,
        [],
        `a concurrent creator lost with a code the migrator does NOT tolerate; got ${JSON.stringify(codes)}, tolerated ${JSON.stringify([...LEDGER_RACE_LOST])}`,
      );
    } finally {
      await Promise.all(pools.map((p) => p.end()));
    }
  });
});

for (const concurrency of [2, 3, 5]) {
  test(`${concurrency} concurrent migrators on a FRESH database ALL fulfil, and the ledger is applied exactly once`, async () => {
    await withFreshDatabase(`n${concurrency}`, async (url) => {
      const pools = Array.from({ length: concurrency }, () => {
        const pool = new Pool({ connectionString: url, max: 2 });
        // `pool.end()` can resolve before every socket has finished closing,
        // and the NEXT case's `DROP DATABASE ... WITH (FORCE)` then terminates
        // the leftovers — which arrives as a stray `error` event on an
        // already-ended pool and, with no listener, as an uncaught throw
        // attributed to whichever test happens to be running. src/ handles
        // this with `guardPoolErrors`; these bare test pools need the same.
        pool.on("error", () => undefined);
        return pool;
      });
      try {
        const results = await Promise.allSettled(pools.map((p) => runMailMigrations(p)));
        const rejected = results.filter((r) => r.status === "rejected");
        assert.deepEqual(
          rejected.map((r) => String((r as PromiseRejectedResult).reason)),
          [],
          "no migrator may be crashed by another migrator",
        );
        const check = new Pool({ connectionString: url, max: 1 });
        check.on("error", () => undefined);
        try {
          // Exactly once each, and exactly the full set (F3: the count was
          // `n = d` — guaranteed by the PRIMARY KEY — and `>= 54`).
          const ledger = await check.query(`SELECT id FROM aaliyah_mail_migrations ORDER BY id`);
          assert.deepEqual(
            ledger.rows.map((r) => r.id),
            MIGRATIONS.map((m) => m.id),
            "the ledger is not exactly this build's migrations",
          );
          // And the ledger agrees with the schema, not just with itself.
          const helper = await check.query(
            `SELECT count(*)::int AS n FROM pg_proc
              WHERE proname = 'aaliyah_memory_unerased_merged_records'`,
          );
          assert.equal(helper.rows[0].n, 1);
          // ---- NO SESSION STATE RODE BACK INTO THE POOL ----------------
          //
          // The runner no longer TAKES an advisory lock (it was removed as
          // unfalsifiable once the ledger creation tolerated a lost race), so
          // this assertion is now a forward leak check rather than a proof
          // about today's code: it holds any future session lock to the same
          // standard, and it must keep passing.
          const held = await check.query(
            `SELECT count(*)::int AS n FROM pg_locks
              WHERE locktype = 'advisory'
                AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
          );
          assert.equal(held.rows[0].n, 0, "a migrator left a session advisory lock held");
        } finally {
          await check.end();
        }
      } finally {
        await Promise.all(pools.map((p) => p.end()));
      }
    });
  });
}
