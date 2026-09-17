const { test } = require("node:test");
const { Client } = require("pg");
test("a deadlock surfaces as a failure, not a hang", async () => {
  const url = process.env.AALIYAH_TEST_DATABASE_URL;
  const a = new Client({ connectionString: url });
  const b = new Client({ connectionString: url });
  await a.connect();
  await b.connect();
  try {
    await a.query("BEGIN");
    await b.query("BEGIN");
    await a.query("SELECT pg_advisory_xact_lock(424242101)");
    await b.query("SELECT pg_advisory_xact_lock(424242102)");
    await Promise.all([
      a.query("SELECT pg_advisory_xact_lock(424242102)"),
      b.query("SELECT pg_advisory_xact_lock(424242101)"),
    ]);
  } finally {
    await a.query("ROLLBACK").catch(() => {});
    await b.query("ROLLBACK").catch(() => {});
    await a.end();
    await b.end();
  }
});
