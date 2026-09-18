import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";
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

test("the migrator leaves NO session state on the connection it returns — success AND refusal", async () => {
  // ---- WHAT THE ADVISORY LOCK'S REMOVAL LEFT BEHIND ------------------
  // The runner used to take a session advisory lock and raise `lock_timeout`
  // to MIGRATION bounds. The lock is gone (removed as unfalsifiable once the
  // ledger creation tolerated a lost race), but the raised `lock_timeout` is
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
        const r = await pool.query(`SELECT pg_backend_pid()::int AS pid, current_setting('lock_timeout') AS lt`);
        return { pid: r.rows[0].pid as number, lockTimeout: String(r.rows[0].lt) };
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

test("047 REFUSES to run over an existing plaintext alias binding, and the plaintext row survives the refusal", async () => {
  // P6 survivor P3-13: disabling this refusal left the suite green, because no
  // test ever built a database that still held a plaintext binding when 047
  // arrived. Built here: a migrated database is walked back to its pre-047
  // shape — the plaintext column restored, one binding in it, and 047..049
  // unrecorded — and the runner is asked to go forward again.
  await runMailMigrations(replayPool);
  const client = await replayPool.connect();
  try {
    await client.query(`ALTER TABLE memory_alias_bindings ADD COLUMN normalized_alias text`);
    await client.query(
      `INSERT INTO memory_alias_tenant_policy (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
       VALUES ('tenant-replay','workspace_isolated','actor.replay','alias-policy/v1')`,
    );
    await client.query("BEGIN");
    await client.query(`ALTER TABLE memory_alias_bindings DISABLE TRIGGER USER`);
    await client.query(
      `INSERT INTO memory_alias_bindings
         (tenant_id, workspace_id, principal_id, user_id, cross_workspace_policy, scope_key,
          alias_id, skeleton_algorithm, normalization_profile, canonical_participant_id,
          script_code, restriction_level, subject_participant_id, source_evidence_ref,
          source_evidence_digest, observed_at, fresh_until, authorization_id,
          mutation_receipt_id, bound_at, payload, pii_envelope, pii_key_ref, pii_key_version,
          normalized_alias)
       VALUES ('tenant-replay','workspace-replay','p','u','workspace_isolated','workspace-replay',
               'alias-replay','sk','np','participant-replay','Latn','ascii_only','participant-replay',
               'identity:x/y',$1, now(), now() + interval '1 hour','auth-replay','mutation.replay',
               now(), $2::jsonb, '{"keyRef":"k","keyVersion":1}'::jsonb,'k',1,
               'plaintext.person@example.com')`,
      [
        `sha256:${"a".repeat(64)}`,
        JSON.stringify({
          scope: { tenantId: "tenant-replay", workspaceId: "workspace-replay", principalId: "p", userId: "u" },
          aliasId: "alias-replay",
          canonicalParticipantId: "participant-replay",
          subjectParticipantId: "participant-replay",
          crossWorkspacePolicy: "workspace_isolated",
          scopeKey: "workspace-replay",
          authorizationId: "auth-replay",
          mutationReceiptId: "mutation.replay",
        }),
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  await replayPool.query(
    `DELETE FROM aaliyah_mail_migrations WHERE id IN (
       SELECT id FROM aaliyah_mail_migrations WHERE substring(id from 1 for 3)::int >= 47)`,
  );

  await assert.rejects(
    () => runMailMigrations(replayPool),
    /1 plaintext alias binding\(s\) exist; migration 047 will not drop personal identifiers it cannot first re-encrypt/,
  );
  const survived = await replayPool.query(
    `SELECT normalized_alias FROM memory_alias_bindings WHERE alias_id = 'alias-replay'`,
  );
  assert.equal(survived.rows[0]?.normalized_alias, "plaintext.person@example.com");

  // Positive control: with the plaintext gone, the same forward run succeeds.
  await replayPool.query(`ALTER TABLE memory_alias_bindings DISABLE TRIGGER USER`);
  await replayPool.query(`DELETE FROM memory_alias_bindings`);
  await replayPool.query(`ALTER TABLE memory_alias_bindings ENABLE TRIGGER USER`);
  await runMailMigrations(replayPool);
  const column = await replayPool.query(
    `SELECT count(*)::int AS n FROM information_schema.columns
      WHERE table_name = 'memory_alias_bindings' AND column_name = 'normalized_alias'`,
  );
  assert.equal(column.rows[0].n, 0);
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
      assert.ok((counted.rows[0].rows as number) >= 57);
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
          const ledger = await check.query(
            `SELECT count(*)::int AS n, count(DISTINCT id)::int AS d FROM aaliyah_mail_migrations`,
          );
          assert.equal(ledger.rows[0].n, ledger.rows[0].d, `trial ${trial}: duplicate ledger rows`);
          assert.ok((ledger.rows[0].n as number) >= 56, `trial ${trial}: only ${ledger.rows[0].n} applied`);
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

test("POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash N-1 with 23505", async () => {
  // Proves the hazard is real on THIS server, so the refusal below is about
  // the runner's ordering and not about `IF NOT EXISTS` being safe anyway.
  await withFreshDatabase("control", async (url) => {
    const pools = Array.from({ length: 3 }, () => new Pool({ connectionString: url, max: 1 }));
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
      assert.ok(
        codes.every((code) => code === "23505"),
        `expected 23505 unique-violation losses; got ${JSON.stringify(codes)}`,
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
          const ledger = await check.query(
            `SELECT count(*)::int AS n, count(DISTINCT id)::int AS d FROM aaliyah_mail_migrations`,
          );
          // Exactly once each: no duplicate rows, and the full set applied.
          assert.equal(ledger.rows[0].n, ledger.rows[0].d);
          assert.ok((ledger.rows[0].n as number) >= 54, `only ${ledger.rows[0].n} migrations applied`);
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
