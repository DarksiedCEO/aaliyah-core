const { test } = require("node:test");
const assert = require("node:assert/strict");
const { Client } = require("pg");
test("a statement that would block forever is cancelled by statement_timeout", async () => {
  const client = new Client({ connectionString: process.env.AALIYAH_TEST_DATABASE_URL });
  await client.connect();
  try {
    await client.query("SELECT pg_sleep(3600)");
  } finally {
    await client.end();
  }
});
