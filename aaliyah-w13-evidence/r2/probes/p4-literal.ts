/**
 * Gate 5 I-5's p4 probe, re-executed literally for R2.2.
 *   setup <db>             (run from the UNMODIFIED build) a pre-057 database: through 056
 *   upgrade <db> [actor]   (run from the EDITED build) upgrade it; prints ACCEPTED/REFUSED
 */
import { Pool } from "pg";
import { runMailMigrations } from "../../../src/persistence/postgres/migrations";
const ADMIN = "postgres://postgres:test@127.0.0.1:54610/postgres";
(async () => {
  const [mode, db, actor] = process.argv.slice(2);
  const admin = new Pool({ connectionString: ADMIN, max: 1 });
  const pool = new Pool({ connectionString: ADMIN.replace(/\/[^/]+$/, `/${db}`), max: 2 });
  pool.on("error", () => {});
  try {
    if (mode === "setup") {
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.query(`CREATE DATABASE ${db}`);
      await runMailMigrations(pool, { through: "056_memory_least_privilege_trim" });
      console.log(JSON.stringify({ mode, db, rows: (await pool.query("SELECT count(*)::int n FROM aaliyah_mail_migrations")).rows[0].n }));
    } else {
      const r = await runMailMigrations(pool, actor ? { attestUndigestedRows: { actor } } : {}).then(() => "ACCEPTED", (e) => `REFUSED: ${String(e.message).slice(0, 170)}`);
      const d = await pool.query(`SELECT sql_digest FROM aaliyah_mail_migrations WHERE id LIKE '055%'`).catch(() => ({ rows: [{ sql_digest: "(no column)" }] }));
      console.log(JSON.stringify({ mode, db, attested: actor ?? null, result: r, digest055: d.rows[0]?.sql_digest ?? null }));
    }
  } finally { await pool.end(); await admin.end(); }
})();
