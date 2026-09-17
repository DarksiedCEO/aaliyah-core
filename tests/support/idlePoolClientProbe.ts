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
 *
 * A second argument `active` holds the client CHECKED OUT instead, inside a
 * transaction running `pg_sleep`, and prints that backend's pid while the
 * statement is in flight. The parent terminates it; the probe then does
 * exactly what every store does on failure — `ROLLBACK` with a `.catch`, then
 * release. Found by the 2b2e554 reliability review: pg-pool removes its idle
 * error listener at checkout, so the dead client's `'error'` event is thrown
 * outside every promise chain and no `.catch` can intercept it.
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
  if (process.argv[3] === "active") {
    await client.query("BEGIN");
    const inFlight = client.query("SELECT pg_sleep(30)");
    process.stdout.write(`${JSON.stringify({ activeBackendPid: pid })}\n`);
    try {
      await inFlight;
      throw new Error("the in-flight statement was never terminated");
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ statementRejected: (error as { code?: string }).code ?? String(error) })}\n`);
    }
    // The store cleanup pattern, verbatim.
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
    process.stdout.write(`${JSON.stringify({ cleanedUp: true })}\n`);
  } else {
    client.release();
    process.stdout.write(`${JSON.stringify({ idleBackendPid: pid })}\n`);
  }

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
