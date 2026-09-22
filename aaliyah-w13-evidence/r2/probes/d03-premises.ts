/**
 * R2 premise re-execution: gate 7 D-03 (L4, L4b, L5, L5-control), gate 5 I-5
 * (P3b: a NULLed digest re-blessed) and I-6 B5 (an emptied ledger). Each case
 * on its own freshly created database; the real runMailMigrations from the
 * working tree this is run from. Prints one JSON line per case.
 *   node --require ts-node/register aaliyah-w13-evidence/r2/probes/d03-premises.ts
 */
import { Pool } from "pg";
import { runMailMigrations } from "../../../src/persistence/postgres/migrations";

const ADMIN = process.env.AALIYAH_TEST_DATABASE_URL ?? "postgres://postgres:test@127.0.0.1:54610/aaliyah_test";
const admin = new Pool({ connectionString: ADMIN, max: 1 });
admin.on("error", () => undefined);

async function fresh(name: string): Promise<Pool> {
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${name}`);
  const pool = new Pool({ connectionString: ADMIN.replace(/\/[^/]+$/, `/${name}`), max: 2 });
  pool.on("error", () => undefined);
  return pool;
}
async function outcome(p: Promise<unknown>): Promise<string> {
  try { await p; return "ACCEPTED"; } catch (e) { return `REFUSED: ${String((e as Error).message).slice(0, 160)}`; }
}
async function present(pool: Pool, sql: string): Promise<boolean> {
  return (await pool.query(sql)).rows[0].p === true;
}
const TRIG058 = `SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'memory_key_destruction_obligations_settled_frozen') AS p`;
const CON060 = `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'memory_key_destruction_obligations_settled_by_real') AS p`;
const COL057 = `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='aaliyah_mail_migrations' AND column_name='sql_digest') AS p`;

(async () => {
  const out: Record<string, unknown>[] = [];
  const ids = async (pool: Pool) => (await pool.query("SELECT id FROM aaliyah_mail_migrations ORDER BY id")).rows.map((r) => r.id as string);
  // Reference: a fully migrated database, to read TRUE digests and ids from.
  const ref = await fresh("r2p_ref");
  await runMailMigrations(ref);
  const all = await ids(ref);
  const digests = new Map((await ref.query("SELECT id, sql_digest FROM aaliyah_mail_migrations")).rows.map((r) => [r.id, r.sql_digest]));
  const late = all.filter((id) => id >= "057");

  { // L5-control: an applied row's digest set WRONG
    const p = await fresh("r2p_l5c"); await runMailMigrations(p);
    await p.query(`UPDATE aaliyah_mail_migrations SET sql_digest = 'sha256:' || repeat('0',64) WHERE id LIKE '055%'`);
    out.push({ case: "L5-control", result: await outcome(runMailMigrations(p)) }); await p.end();
  }
  { // L4: through 056, rows for 057.. inserted, never applied (no digest column)
    const p = await fresh("r2p_l4"); await runMailMigrations(p, { through: all.find((i) => i.startsWith("056"))! });
    for (const id of late) await p.query("INSERT INTO aaliyah_mail_migrations (id) VALUES ($1)", [id]);
    const r = await outcome(runMailMigrations(p));
    out.push({ case: "L4", phantomRows: late, result: r, col057: await present(p, COL057), trig058: await present(p, TRIG058), con060: await present(p, CON060), ledgerRows: (await ids(p)).length }); await p.end();
  }
  { // L4b: through 057, rows for 058.. with their TRUE digests, never applied
    const p = await fresh("r2p_l4b"); await runMailMigrations(p, { through: all.find((i) => i.startsWith("057"))! });
    for (const id of late.filter((i) => i >= "058")) await p.query("INSERT INTO aaliyah_mail_migrations (id, sql_digest) VALUES ($1,$2)", [id, digests.get(id)]);
    const r = await outcome(runMailMigrations(p));
    out.push({ case: "L4b", result: r, trig058: await present(p, TRIG058), con060: await present(p, CON060), ledgerRows: (await ids(p)).length }); await p.end();
  }
  { // L5 / I-5 P3b: an applied row's digest NULLed
    const p = await fresh("r2p_l5"); await runMailMigrations(p);
    await p.query(`UPDATE aaliyah_mail_migrations SET sql_digest = NULL WHERE id LIKE '055%'`);
    const r = await outcome(runMailMigrations(p));
    const after = (await p.query(`SELECT sql_digest FROM aaliyah_mail_migrations WHERE id LIKE '055%'`)).rows[0].sql_digest;
    out.push({ case: "L5", result: r, digestAfter: after, reblessed: after === digests.get(all.find((i) => i.startsWith("055"))!) }); await p.end();
  }
  { // I-5 pre-057 upgrade: through 056, then the full build — is the backfill silent?
    const p = await fresh("r2p_pre057"); await runMailMigrations(p, { through: all.find((i) => i.startsWith("056"))! });
    const r = await outcome(runMailMigrations(p));
    const d = (await p.query(`SELECT count(*)::int AS n, count(sql_digest)::int AS d FROM aaliyah_mail_migrations`)).rows[0];
    out.push({ case: "I-5-pre057-upgrade", result: r, rows: d.n, digested: d.d, note: "ACCEPTED+fully digested = silent unattested backfill" }); await p.end();
  }
  { // I-6 B5: emptied ledger over a populated schema
    const p = await fresh("r2p_b5"); await runMailMigrations(p);
    await p.query("DELETE FROM aaliyah_mail_migrations");
    const r = await outcome(runMailMigrations(p));
    out.push({ case: "I-6-B5-emptied-ledger", result: r, ledgerRowsAfter: (await ids(p)).length }); await p.end();
  }
  await ref.end();
  for (const n of ["r2p_ref", "r2p_l5c", "r2p_l4", "r2p_l4b", "r2p_l5", "r2p_pre057", "r2p_b5"]) await admin.query(`DROP DATABASE IF EXISTS ${n} WITH (FORCE)`);
  await admin.end();
  for (const o of out) console.log(JSON.stringify(o));
})().catch((e) => { console.error(e); process.exit(1); });
