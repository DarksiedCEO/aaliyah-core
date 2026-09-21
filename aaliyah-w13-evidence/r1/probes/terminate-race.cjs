// K-05's fixture sequence, isolated: BEGIN, read own pid, pg_terminate_backend
// from a second pool, then the next query on the terminated client. Counts how
// often the "terminated" backend still ANSWERS — the path that makes K-05's
// `assert.fail` fire and :515 throw before :516 releases.
const { Pool } = require("/Users/andrelove/aaliyah-w13/aaliyah-wave1-core/node_modules/pg");
const URL = "postgres://postgres:test@127.0.0.1:54610/aaliyah_test";
const N = Number(process.argv[2] ?? 500);
const WAIT = process.argv[3]; // undefined = K-05 as written; else ms for pg_terminate_backend(pid, ms)
(async () => {
  const admin = new Pool({ connectionString: URL, max: 2 });
  let answered = 0, rejected = 0, other = 0;
  for (let i = 0; i < N; i += 1) {
    const pool = new Pool({ connectionString: URL, max: 1 });
    pool.on("error", () => {});
    const c = await pool.connect();
    c.on("error", () => {});
    try {
      await c.query("BEGIN");
      const pid = (await c.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      await admin.query(WAIT ? "SELECT pg_terminate_backend($1, $2)" : "SELECT pg_terminate_backend($1)", WAIT ? [pid, Number(WAIT)] : [pid]);
      await c.query("SELECT 1");
      answered += 1;
    } catch (e) {
      if (e.code === "57P01" || /terminat/i.test(String(e.message))) rejected += 1; else { other += 1; (global.kinds ??= {})[`${e.code}|${String(e.message).slice(0,80)}`] = ((global.kinds ?? {})[`${e.code}|${String(e.message).slice(0,80)}`] ?? 0) + 1; }
    }
    c.release(true);
    await pool.end();
  }
  await admin.end();
  console.log(JSON.stringify({ N, wait: WAIT ?? null, answeredAfterTerminate: answered, rejected, other, kinds: global.kinds ?? {} }));
})();
