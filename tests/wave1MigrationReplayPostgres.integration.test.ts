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
      const pools = Array.from({ length: concurrency }, () => new Pool({ connectionString: url, max: 2 }));
      try {
        const results = await Promise.allSettled(pools.map((p) => runMailMigrations(p)));
        const rejected = results.filter((r) => r.status === "rejected");
        assert.deepEqual(
          rejected.map((r) => String((r as PromiseRejectedResult).reason)),
          [],
          "no migrator may be crashed by another migrator",
        );
        const check = new Pool({ connectionString: url, max: 1 });
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
          // The session advisory lock the runner takes must not survive it:
          // it would otherwise ride back into the pool on that connection.
          const held = await check.query(
            `SELECT count(*)::int AS n FROM pg_locks
              WHERE locktype = 'advisory'
                AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
          );
          assert.equal(held.rows[0].n, 0, "a migrator left its session advisory lock held");
        } finally {
          await check.end();
        }
      } finally {
        await Promise.all(pools.map((p) => p.end()));
      }
    });
  });
}
