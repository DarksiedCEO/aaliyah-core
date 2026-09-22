// R-04 premise: hold the ledger advisory lock longer than MIGRATION_BOUNDS.lockTimeoutMs;
// does a second runMailMigrations crash (55P03) at ~lockTimeoutMs?
import { Pool } from "pg";
import { runMailMigrations } from "../../../src/persistence/postgres/migrations";
import { MIGRATION_BOUNDS } from "../../../src/persistence/postgres/pool";
const ADMIN = "postgres://postgres:test@127.0.0.1:54610/postgres";
(async () => {
  const admin = new Pool({ connectionString: ADMIN, max: 1 });
  await admin.query("DROP DATABASE IF EXISTS r2_r04 WITH (FORCE)"); await admin.query("CREATE DATABASE r2_r04");
  const url = ADMIN.replace(/\/[^/]+$/, "/r2_r04");
  const holder = new Pool({ connectionString: url, max: 1 }); holder.on("error", () => {});
  const pool = new Pool({ connectionString: url, max: 2 }); pool.on("error", () => {});
  const h = await holder.connect();
  await h.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", ["aaliyah_mail_migrations"]);
  const started = Date.now();
  const outcome = runMailMigrations(pool).then(() => "FULFILLED", (e) => `REJECTED ${e.code} ${e.message}`);
  const release = setTimeout(() => h.query("SELECT pg_advisory_unlock_all()").catch(() => {}), MIGRATION_BOUNDS.lockTimeoutMs + 5_000);
  const r = await outcome; clearTimeout(release);
  console.log(JSON.stringify({ lockTimeoutMs: MIGRATION_BOUNDS.lockTimeoutMs, statementTimeoutMs: MIGRATION_BOUNDS.statementTimeoutMs, heldForMs: MIGRATION_BOUNDS.lockTimeoutMs + 5000, result: r, elapsedMs: Date.now() - started }));
  await h.query("SELECT pg_advisory_unlock_all()").catch(() => {}); h.release();
  await pool.end(); await holder.end(); await admin.query("DROP DATABASE IF EXISTS r2_r04 WITH (FORCE)"); await admin.end();
})();
