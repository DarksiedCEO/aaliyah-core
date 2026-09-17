/**
 * CHILD PROCESS FOR tests/wave1PoolResiliencePostgres.integration.test.ts.
 *
 * Opens one pooled client, releases it (so it sits IDLE in the pool, exactly as
 * src/server.ts leaves its pools after boot), prints that backend's pid, and
 * waits. The parent terminates the backend. If the pool has no `'error'`
 * listener, node-postgres re-emits the idle client's error on the pool and Node
 * throws it: this process dies. If it survives, the parent writes a line to
 * stdin and this process proves the pool is still usable.
 *
 * Mode `unguarded` builds a bare Pool with no listener. It is the POSITIVE
 * CONTROL: it must die, or the probe cannot detect the defect at all.
 */
import { Pool } from "pg";
import * as readline from "node:readline";

import { createMailDbPool } from "../../src/persistence/postgres/pool";
import { idempotencyStoreInternals } from "../../src/persistence/idempotencyStore";

async function main(): Promise<void> {
  const mode = process.argv[2];
  const url = process.env.AALIYAH_DATABASE_URL!;
  let pool: Pool;
  if (mode === "mail") {
    pool = createMailDbPool(process.env, {
      name: "probe",
      onError: (event) => process.stdout.write(`${JSON.stringify({ poolError: event })}\n`),
    });
  } else if (mode === "idempotency") {
    process.env.DATABASE_URL = url;
    pool = idempotencyStoreInternals.buildPool();
  } else if (mode === "unguarded") {
    pool = new Pool({ connectionString: url, max: 2 });
  } else {
    throw new Error(`unknown mode ${mode}`);
  }
  const client = await pool.connect();
  const pid = (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;
  client.release();
  process.stdout.write(`${JSON.stringify({ idleBackendPid: pid })}\n`);

  const lines = readline.createInterface({ input: process.stdin });
  for await (const line of lines) {
    if (line.trim() !== "check") continue;
    const answer = (await pool.query("SELECT 1 AS one")).rows[0].one as number;
    process.stdout.write(`${JSON.stringify({ recovered: answer === 1 })}\n`);
    await pool.end();
    process.exit(0);
  }
}

main().catch((error) => {
  process.stderr.write(`probe failed: ${error?.stack ?? error}\n`);
  process.exit(9);
});
