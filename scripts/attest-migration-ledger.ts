/**
 * AN OPERATOR ATTESTS THE LEDGER'S UNDIGESTED ROWS (R2.2, candidate-4 I-5).
 *
 *   AALIYAH_DATABASE_URL=... node --require ts-node/register \
 *     scripts/attest-migration-ledger.ts --actor "<who is attesting>"
 *
 * The migration runner refuses to give a ledger row a digest it did not earn
 * by applying that migration itself — a pre-057 ledger, or a row whose digest
 * was removed. This is the one path that does, and only:
 *   - after the runner's catalog read-back has found every applied
 *     migration's recorded effect in the schema (it runs first, as always);
 *   - with the actor named, recorded in the ledger beside each digest it
 *     writes, with the time (migration 061).
 * Boot never calls this. Running it is a statement, by the named actor, that
 * they have looked.
 */
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";

async function main(): Promise<void> {
  const index = process.argv.indexOf("--actor");
  const actor = index === -1 ? undefined : process.argv[index + 1];
  const url = process.env.AALIYAH_DATABASE_URL;
  if (!url || actor === undefined || actor.trim() === "" || actor.startsWith("--")) {
    process.stderr.write(
      'usage: AALIYAH_DATABASE_URL=... attest-migration-ledger.ts --actor "<who is attesting>"\n',
    );
    process.exit(2);
  }
  const pool = new Pool({ connectionString: url, max: 1 });
  pool.on("error", () => undefined);
  try {
    await runMailMigrations(pool, { attestUndigestedRows: { actor } });
    const attested = await pool.query(
      `SELECT count(*)::int AS n FROM aaliyah_mail_migrations WHERE digest_attested_by = $1`,
      [actor.trim()],
    );
    process.stdout.write(`ledger attested by ${actor.trim()}: ${attested.rows[0].n} row(s) carry this attestation\n`);
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  process.stderr.write(`attest-migration-ledger: REFUSED: ${error?.message ?? error}\n`);
  process.exit(1);
});
