// R-04, extended: the second migrator on the PRODUCTION pool (createMailDbPool, as src/server.ts builds it),
// not a bare pg Pool. Which bound ends its wait, and when? Runs against the code at the commit it is run from.
import { Pool } from "pg";
import { runMailMigrations } from "../../../src/persistence/postgres/migrations";
import { createMailDbPool, MAIL_DB_POOL_BOUNDS } from "../../../src/persistence/postgres/pool";
const ADMIN = "postgres://postgres:test@127.0.0.1:54610/postgres";
(async () => {
  const admin = new Pool({ connectionString: ADMIN, max: 1 });
  await admin.query("DROP DATABASE IF EXISTS r2_r04p WITH (FORCE)"); await admin.query("CREATE DATABASE r2_r04p");
  const url = ADMIN.replace(/\/[^/]+$/, "/r2_r04p");
  const holder = new Pool({ connectionString: url, max: 1 }); holder.on("error", () => {});
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: url } as NodeJS.ProcessEnv, { name: "write", onError: () => {} });
  const h = await holder.connect();
  await h.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", ["aaliyah_mail_migrations"]);
  const started = Date.now();
  const holdMs = Number(process.argv[2] ?? 45_000);
  const release = setTimeout(() => h.query("SELECT pg_advisory_unlock_all()").catch(() => {}), holdMs);
  const r = await runMailMigrations(pool).then(() => "FULFILLED", (e) => `REJECTED ${e.code} ${e.message}`);
  clearTimeout(release);
  console.log(JSON.stringify({ poolStatementTimeoutMs: MAIL_DB_POOL_BOUNDS.statementTimeoutMs, heldForMs: holdMs, result: r, elapsedMs: Date.now() - started }));
  await h.query("SELECT pg_advisory_unlock_all()").catch(() => {}); h.release();
  await pool.end(); await holder.end(); await admin.query("DROP DATABASE IF EXISTS r2_r04p WITH (FORCE)"); await admin.end();
})();
