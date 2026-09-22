import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import { MIGRATION_CATALOG_EVIDENCE } from "../src/persistence/postgres/migrationEvidence.generated";
import {
  migrationDigest,
  MIGRATIONS,
  runMailMigrations,
} from "../src/persistence/postgres/migrations";
import { deriveMigrationEvidence, EVIDENCE_FILE, renderEvidence } from "../scripts/migration-evidence";
import * as fs from "node:fs";

/**
 * R2 — THE LEDGER IS VERIFIED AGAINST THE SCHEMA, AND NEVER RE-BLESSED SILENTLY.
 *
 * Candidate-4's data gate (D-03) and integration gate (I-5, I-6) attacked the
 * migration ledger AS DATA and found it failing OPEN four ways, every one
 * re-executed at 5fe8ea0 before this file was written
 * (aaliyah-w13-evidence/r2/probes/d03-premises.at-5fe8ea0.txt):
 *
 *   L4   rows for 057..060 inserted, never applied         -> ACCEPTED
 *   L4b  the same with their TRUE digests                  -> ACCEPTED
 *   L5   an applied row's digest NULLed                     -> ACCEPTED, re-blessed
 *   I-5  a pre-057 ledger upgraded                          -> digests written, unattested
 *   I-6  an EMPTIED ledger over a populated schema          -> refused only by a DDL collision
 *
 * Each case below runs on a database of its own, created and dropped inside
 * the test: "what the ledger says" and "what the schema holds" are the whole
 * subject, and a shared database would put other files' schema in play.
 */

const ADMIN_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

let adminPool: Pool;

before(() => {
  adminPool = new Pool({ connectionString: ADMIN_URL, max: 2 });
  adminPool.on("error", () => undefined);
});

after(async () => {
  await adminPool.end();
});

const id = (prefix: string): string => {
  const found = MIGRATIONS.find((m) => m.id.startsWith(prefix));
  assert.ok(found, `no migration ${prefix}`);
  return found.id;
};

async function withLedgerDatabase(
  suffix: string,
  body: (pool: Pool) => Promise<void>,
): Promise<void> {
  const name = `aaliyah_ledger_${suffix}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${name}`);
  const pool = new Pool({ connectionString: ADMIN_URL.replace(/\/[^/]+$/, `/${name}`), max: 2 });
  // Its own FORCE-drop below can terminate sockets `end()` has not closed yet
  // (R1.5): absorbed here rather than surfacing as an uncaught 57P01.
  pool.on("error", () => undefined);
  try {
    await body(pool);
  } finally {
    await pool.end().catch(() => undefined);
    await adminPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  }
}

async function ledger(pool: Pool): Promise<Array<{ id: string; sql_digest: string | null; digest_attested_by: string | null }>> {
  const cols = (
    await pool.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'aaliyah_mail_migrations'`,
    )
  ).rows.map((r) => r.column_name as string);
  const digest = cols.includes("sql_digest") ? "sql_digest" : "NULL::text AS sql_digest";
  const attested = cols.includes("digest_attested_by") ? "digest_attested_by" : "NULL::text AS digest_attested_by";
  return (await pool.query(`SELECT id, ${digest}, ${attested} FROM aaliyah_mail_migrations ORDER BY id`)).rows;
}

test("R2.1 / D-03 L4: ledger rows for migrations that never ran are REFUSED before anything is applied", async () => {
  await withLedgerDatabase("l4", async (pool) => {
    await runMailMigrations(pool, { through: id("056") });
    const phantoms = MIGRATIONS.map((m) => m.id).filter((m) => m >= "057");
    for (const phantom of phantoms) {
      await pool.query("INSERT INTO aaliyah_mail_migrations (id) VALUES ($1)", [phantom]);
    }
    const before = await ledger(pool);
    await assert.rejects(
      () => runMailMigrations(pool),
      /the ledger lists migrations whose effect the schema does not hold before anything was applied: 057_migration_content_digest \[col:aaliyah_mail_migrations\.sql_digest absent/,
    );
    assert.deepEqual(await ledger(pool), before, "a refused run changed the ledger");
  });
});

test("R2.1 / D-03 L4b: phantom rows carrying their TRUE digests are refused too — the digest proves the source, not the schema", async () => {
  await withLedgerDatabase("l4b", async (pool) => {
    await runMailMigrations(pool, { through: id("057") });
    for (const migration of MIGRATIONS.filter((m) => m.id >= "058")) {
      await pool.query(
        "INSERT INTO aaliyah_mail_migrations (id, sql_digest) VALUES ($1, $2)",
        [migration.id, migrationDigest(migration.sql)],
      );
    }
    await assert.rejects(
      () => runMailMigrations(pool),
      /does not hold before anything was applied: 058_settled_obligation_resolution_immutable \[/,
    );
    const trigger = await pool.query(
      `SELECT count(*)::int AS n FROM pg_trigger WHERE tgname = 'memory_key_destruction_obligations_settled_frozen'`,
    );
    assert.equal(trigger.rows[0].n, 0, "fixture precondition: 058's trigger was never applied");
  });
});

test("R2.2: a ledger row whose migration's objects were REMOVED from the schema is refused, naming that migration", async () => {
  await withLedgerDatabase("absent", async (pool) => {
    await runMailMigrations(pool);
    await pool.query(
      `DROP TRIGGER memory_key_destruction_obligations_settled_frozen ON memory_key_destruction_obligations`,
    );
    await assert.rejects(
      () => runMailMigrations(pool),
      /058_settled_obligation_resolution_immutable \[trg:memory_key_destruction_obligations\.memory_key_destruction_obligations_settled_frozen absent\]/,
    );
  });
});

test("R2.2: a migration whose SQL silently produced nothing is refused AFTER applying — read back, not assumed", async () => {
  // `CREATE TABLE IF NOT EXISTS` over a same-named table of a different shape
  // succeeds without creating anything. Before R2 the ledger then said 001 ran.
  // Staged with 001 already applied: on an EMPTY ledger a pre-existing
  // migration object is refused earlier, as a partial restore (B5).
  await withLedgerDatabase("silent", async (pool) => {
    await runMailMigrations(pool, { through: id("001") });
    await pool.query(`CREATE TABLE mail_connections (connection_id integer PRIMARY KEY)`);
    await assert.rejects(
      () => runMailMigrations(pool, { through: id("002") }),
      /does not hold after this run applied its migrations: 002_mail_connections \[col:mail_connections\./,
    );
    const rows = await pool.query(`SELECT id FROM aaliyah_mail_migrations ORDER BY id`);
    assert.deepEqual(rows.rows.map((r) => r.id), [id("001")], "the refused run's transaction must leave its ledger rows behind");
  });
});

test("R2.1 / D-03 L5: an applied row's digest NULLed is REFUSED, and stays NULL — never re-derived from the source", async () => {
  await withLedgerDatabase("l5", async (pool) => {
    await runMailMigrations(pool);
    await pool.query(`UPDATE aaliyah_mail_migrations SET sql_digest = NULL WHERE id = $1`, [id("055")]);
    await assert.rejects(
      () => runMailMigrations(pool),
      /1 applied migration\(s\) carry NO digest on a ledger that records digests \(055_memory_key_destruction_settlement\)/,
    );
    const row = (await ledger(pool)).find((r) => r.id === id("055"));
    assert.equal(row?.sql_digest, null, "the NULLed digest was re-blessed");
  });
});

test("R2.2 / I-5: a pre-057 ledger is NOT backfilled silently; with an operator's attestation it is, and the ledger says who", async () => {
  await withLedgerDatabase("pre057", async (pool) => {
    await runMailMigrations(pool, { through: id("056") });
    const preExisting = (await ledger(pool)).map((r) => r.id);
    await assert.rejects(
      () => runMailMigrations(pool),
      /this ledger predates migration digests: 56 applied migration\(s\) carry none/,
    );
    assert.equal((await ledger(pool)).length, 56, "the refused upgrade applied something");

    await assert.rejects(
      () => runMailMigrations(pool, { attestUndigestedRows: { actor: "   " } }),
      /an attestation must name the operator making it/,
    );

    await runMailMigrations(pool, { attestUndigestedRows: { actor: "operator:r2-test" } });
    const rows = await ledger(pool);
    assert.equal(rows.length, MIGRATIONS.length);
    assert.equal(rows.filter((r) => r.sql_digest === null).length, 0, "every row is digested");
    // EXACTLY the rows this run did not apply are attested; the ones it applied are its own evidence.
    assert.deepEqual(
      rows.filter((r) => r.digest_attested_by !== null).map((r) => r.id),
      preExisting,
    );
    assert.ok(rows.filter((r) => r.digest_attested_by !== null).every((r) => r.digest_attested_by === "operator:r2-test"));
    const when = await pool.query(
      `SELECT count(*)::int AS n FROM aaliyah_mail_migrations WHERE digest_attested_at IS NOT NULL`,
    );
    assert.equal(when.rows[0].n, preExisting.length);
  });
});

test("R2.2: a pre-057 database migrated only to a point BEFORE 057 needs no attestation — nothing is certified", async () => {
  await withLedgerDatabase("stay_pre057", async (pool) => {
    await runMailMigrations(pool, { through: id("040") });
    await runMailMigrations(pool, { through: id("049") });
    assert.equal((await ledger(pool)).length, 49);
  });
});

test("R2.5 / I-6 B5: an EMPTIED ledger over a populated schema is refused as a partial restore, by design", async () => {
  await withLedgerDatabase("b5", async (pool) => {
    await runMailMigrations(pool);
    await pool.query("DELETE FROM aaliyah_mail_migrations");
    await assert.rejects(
      () => runMailMigrations(pool),
      /the migration ledger is EMPTY but the schema already holds objects created by \d+ migration\(s\) \(001_mail_oauth_states, .*This is what a partial restore that lost the ledger looks like/,
    );
    assert.equal((await ledger(pool)).length, 0);
  });
});

test("R2.2: a build whose recorded catalog effect was not generated from its own SQL is refused (the p4 shape)", async () => {
  // Gate 5's p4 probe edited a COMPILED migration. The evidence the read-back
  // compares against would then describe different SQL; the runner refuses to
  // use it. Exercised by corrupting this process's copy of the evidence.
  const target = MIGRATION_CATALOG_EVIDENCE[id("055")] as { sqlDigest: string };
  const original = target.sqlDigest;
  target.sqlDigest = `sha256:${"e".repeat(64)}`;
  try {
    await withLedgerDatabase("p4", async (pool) => {
      await assert.rejects(
        () => runMailMigrations(pool),
        /recorded catalog effect for 055_memory_key_destruction_settlement was not generated from the SQL this build carries/,
      );
    });
  } finally {
    target.sqlDigest = original;
  }
});

test("R2.2: the attestation columns are whole or absent — enforced by the table, not only by the runner", async () => {
  await withLedgerDatabase("attest_check", async (pool) => {
    await runMailMigrations(pool);
    for (const [label, sql] of [
      ["actor without a time", `UPDATE aaliyah_mail_migrations SET digest_attested_by = 'x' WHERE id = $1`],
      ["time without an actor", `UPDATE aaliyah_mail_migrations SET digest_attested_at = now() WHERE id = $1`],
      ["blank actor", `UPDATE aaliyah_mail_migrations SET digest_attested_by = '  ', digest_attested_at = now() WHERE id = $1`],
      ["attestation without a digest", `UPDATE aaliyah_mail_migrations SET sql_digest = NULL, digest_attested_by = 'x', digest_attested_at = now() WHERE id = $1`],
    ] as const) {
      await assert.rejects(
        () => pool.query(sql, [id("001")]),
        (error: { code?: string; constraint?: string }) =>
          error.code === "23514" && error.constraint === "aaliyah_mail_migrations_attestation_whole",
        label,
      );
    }
    // Positive control: a whole attestation is accepted.
    await pool.query(
      `UPDATE aaliyah_mail_migrations SET digest_attested_by = 'x', digest_attested_at = now() WHERE id = $1`,
      [id("001")],
    );
  });
});

test("R2.2: the committed catalog evidence is exactly what the SQL does — regenerated here and compared byte for byte", async () => {
  const derived = await deriveMigrationEvidence(ADMIN_URL);
  assert.equal(
    renderEvidence(derived),
    fs.readFileSync(EVIDENCE_FILE, "utf8"),
    "migrationEvidence.generated.ts drifted from the migrations' actual effect; regenerate it and review the diff",
  );
  assert.deepEqual(Object.keys(derived), MIGRATIONS.map((m) => m.id));
});
