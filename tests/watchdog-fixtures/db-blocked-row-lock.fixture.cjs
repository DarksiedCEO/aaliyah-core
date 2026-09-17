const { test } = require("node:test");
const { Client } = require("pg");
test("a row lock held by an open transaction is not waited on forever", async () => {
  const url = process.env.AALIYAH_TEST_DATABASE_URL;
  const holder = new Client({ connectionString: url });
  const waiter = new Client({ connectionString: url });
  await holder.connect();
  await waiter.connect();
  const table = `watchdog_fixture_${process.pid}`;
  try {
    await holder.query(`CREATE TABLE ${table} (id int PRIMARY KEY)`);
    await holder.query(`INSERT INTO ${table} VALUES (1)`);
    await holder.query("BEGIN");
    await holder.query(`UPDATE ${table} SET id = 1 WHERE id = 1`);
    await waiter.query(`UPDATE ${table} SET id = 1 WHERE id = 1`);
  } finally {
    await holder.query("ROLLBACK").catch(() => {});
    await holder.query(`DROP TABLE IF EXISTS ${table}`).catch(() => {});
    await holder.end();
    await waiter.end();
  }
});
