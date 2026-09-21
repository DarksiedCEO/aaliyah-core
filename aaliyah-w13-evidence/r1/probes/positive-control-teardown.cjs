// The replay file's POSITIVE CONTROL, its teardown exactly: 3 pools (max 1)
// race CREATE TABLE IF NOT EXISTS on a fresh DB, `await Promise.all(p.end())`,
// then withFreshDatabase's `DROP DATABASE ... WITH (FORCE)`. Counts how often a
// pool with NO 'error' listener (as the control is written) emits an error
// after end() resolved — in node:test that is an uncaught 57P01 attributed to
// whatever test is running.
const { Pool } = require("/Users/andrelove/aaliyah-w13/aaliyah-wave1-core/node_modules/pg");
const ADMIN = "postgres://postgres:test@127.0.0.1:54610/postgres";
const N = Number(process.argv[2] ?? 200);
let uncaught = 0; const codes = {};
process.on("uncaughtException", (e) => { uncaught += 1; codes[e.code] = (codes[e.code] ?? 0) + 1; });
(async () => {
  const admin = new Pool({ connectionString: ADMIN, max: 2 });
  for (let i = 0; i < N; i += 1) {
    const name = `r1_probe_control`;
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${name}`);
    const url = ADMIN.replace(/\/[^/]+$/, `/${name}`);
    const pools = Array.from({ length: 3 }, () => new Pool({ connectionString: url, max: 1 }));
    try {
      await Promise.allSettled(pools.map((p) => p.query(`CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`)));
    } finally {
      await Promise.all(pools.map((p) => p.end()));
    }
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await new Promise((r) => setTimeout(r, 20));
  }
  await admin.end();
  console.log(JSON.stringify({ N, uncaughtAfterEnd: uncaught, codes }));
})();
