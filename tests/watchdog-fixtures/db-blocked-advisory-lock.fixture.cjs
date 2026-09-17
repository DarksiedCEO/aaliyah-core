const { test } = require("node:test");
const { Client } = require("pg");
test("an advisory lock held by another session is not waited on forever", async () => {
  const url = process.env.AALIYAH_TEST_DATABASE_URL;
  const holder = new Client({ connectionString: url });
  const waiter = new Client({ connectionString: url });
  await holder.connect();
  await waiter.connect();
  try {
    await holder.query("SELECT pg_advisory_lock(424242001)");
    await waiter.query("SELECT pg_advisory_lock(424242001)");
  } finally {
    await holder.end();
    await waiter.end();
  }
});
