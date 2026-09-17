import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import * as path from "node:path";
import { Pool } from "pg";

import { createMailDbPool, MAIL_DB_POOL_BOUNDS } from "../src/persistence/postgres/pool";
import { createReadinessProbe } from "../src/http/readiness";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresWave1MemoryService } from "../src/persistence/postgres/wave1IdentityGraphStore";
import { TEST_PII_KEYS } from "./support/piiKeys";
import { lockSharedMemoryTables } from "./support/sharedMemoryTables";

/**
 * RELIABILITY FINDINGS AGAINST b3efc82, REPRODUCED AND PINNED.
 *
 *   CRITICAL — no `'error'` listener on any pool: an ordinary idle-connection
 *   disruption killed the process with an uncaught 57P01.
 *   HIGH — no statement/lock/connection bound anywhere.
 *   MEDIUM (integration) — /ready never probed the read-back pool.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";
const ROOT = path.resolve(__dirname, "..");

let adminPool: Pool;

before(() => {
  adminPool = new Pool({ connectionString: DB_URL, max: 2 });
});

after(async () => {
  await adminPool.end();
});

type ProbeOutcome = {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  terminatedPid: number;
};

/**
 * Start the probe, terminate its idle backend, give the error time to surface,
 * then ask the probe to prove its pool still works. Bounded throughout: a probe
 * that never reports a pid, or never exits, fails this test instead of hanging.
 */
function runProbe(
  mode: "mail" | "idempotency" | "unguarded",
  state: "idle" | "active" = "idle",
): Promise<ProbeOutcome> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--require", "ts-node/register", path.join("tests/support/idlePoolClientProbe.ts"), mode, state],
      {
        cwd: ROOT,
        env: { ...process.env, AALIYAH_DATABASE_URL: DB_URL, NODE_TEST_CONTEXT: "" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    let terminatedPid = -1;
    const watchdog = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`probe ${mode} did not finish: stdout=${stdout} stderr=${stderr}`));
    }, 60_000);
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.stdout.on("data", async (chunk) => {
      stdout += chunk;
      const match = /"(?:idle|active)BackendPid":(\d+)/.exec(stdout);
      if (match && terminatedPid === -1) {
        terminatedPid = Number(match[1]);
        await adminPool.query("SELECT pg_terminate_backend($1)", [terminatedPid]);
        // Long enough for the FATAL to reach the idle socket and be emitted.
        setTimeout(() => {
          if (child.exitCode === null) child.stdin.write("check\n");
        }, 1_500);
      }
    });
    child.on("exit", (exitCode) => {
      clearTimeout(watchdog);
      resolve({ exitCode, stdout, stderr, terminatedPid });
    });
  });
}

test("POSITIVE CONTROL: a pool with no error listener DIES when its idle backend is terminated", async () => {
  const outcome = await runProbe("unguarded");
  assert.ok(outcome.terminatedPid > 0);
  assert.notEqual(outcome.exitCode, 0, "the probe must be able to observe the crash");
  assert.match(outcome.stderr, /terminat/i);
  assert.doesNotMatch(outcome.stdout, /"recovered"/);
});

test("the mail pool SURVIVES a terminated idle backend, records it, and keeps serving", async () => {
  const outcome = await runProbe("mail");
  assert.equal(outcome.exitCode, 0, `stderr: ${outcome.stderr}`);
  assert.match(outcome.stdout, /"poolError":\{"pool":"probe","code":"57P01"/);
  assert.match(outcome.stdout, /"recovered":true/);
});

test("the idempotency store's pool SURVIVES a terminated idle backend and keeps serving", async () => {
  const outcome = await runProbe("idempotency");
  assert.equal(outcome.exitCode, 0, `stderr: ${outcome.stderr}`);
  assert.match(outcome.stderr, /"event":"postgres_idle_client_error","pool":"idempotency","code":"57P01"/);
  assert.match(outcome.stdout, /"recovered":true/);
});

test("POSITIVE CONTROL: a CHECKED-OUT client terminated mid-transaction kills an unguarded pool's process at ROLLBACK", async () => {
  const outcome = await runProbe("unguarded", "active");
  assert.ok(outcome.terminatedPid > 0);
  assert.match(outcome.stdout, /"statementRejected":"57P01"/, "the in-flight statement itself rejects catchably");
  assert.notEqual(outcome.exitCode, 0, "the probe must be able to observe the crash");
  assert.doesNotMatch(outcome.stdout, /"recovered"/);
});

test("the mail pool SURVIVES a backend terminated while its client is CHECKED OUT in a transaction", async () => {
  // 2b2e554 reliability CRITICAL: guardPoolErrors covered idle clients only.
  const outcome = await runProbe("mail", "active");
  assert.equal(outcome.exitCode, 0, `stderr: ${outcome.stderr}`);
  assert.match(outcome.stdout, /"statementRejected":"57P01"/);
  assert.match(outcome.stdout, /"cleanedUp":true/);
  assert.match(outcome.stdout, /"poolError":\{"pool":"probe"/);
  assert.match(outcome.stdout, /"recovered":true/);
});

test("the idempotency store's pool SURVIVES a backend terminated while its client is CHECKED OUT", async () => {
  const outcome = await runProbe("idempotency", "active");
  assert.equal(outcome.exitCode, 0, `stderr: ${outcome.stderr}`);
  assert.match(outcome.stdout, /"cleanedUp":true/);
  assert.match(outcome.stdout, /"recovered":true/);
});

test("every connection the mail pool opens carries its statement, lock and idle-transaction bounds", async () => {
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  try {
    // Read back from the SERVER, not from the config object: a bound that
    // never reached the session bounds nothing.
    const client = await pool.connect();
    try {
      const show = async (name: string) =>
        (await client.query(`SELECT current_setting($1) AS v`, [name])).rows[0].v as string;
      assert.equal(await show("statement_timeout"), `${MAIL_DB_POOL_BOUNDS.statementTimeoutMs / 1000}s`);
      assert.equal(await show("lock_timeout"), `${MAIL_DB_POOL_BOUNDS.lockTimeoutMs / 1000}s`);
      assert.equal(
        await show("idle_in_transaction_session_timeout"),
        `${MAIL_DB_POOL_BOUNDS.idleInTransactionSessionTimeoutMs / 60_000}min`,
      );
    } finally {
      client.release();
    }
    assert.equal(pool.options.connectionTimeoutMillis, MAIL_DB_POOL_BOUNDS.connectionTimeoutMillis);
    assert.ok(MAIL_DB_POOL_BOUNDS.connectionTimeoutMillis > 0);
  } finally {
    await pool.end();
  }
});

test("a lock held elsewhere is not waited on forever by a mail-pool connection", async () => {
  // PostgreSQL's own bound, observed: the waiter is refused with 55P03 rather
  // than pending indefinitely.
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  const holder = await adminPool.connect();
  try {
    await holder.query("SELECT pg_advisory_lock(728133777)");
    const started = Date.now();
    await assert.rejects(
      pool.query("SELECT pg_advisory_lock(728133777)"),
      (error: { code?: string }) => error.code === "55P03",
    );
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= MAIL_DB_POOL_BOUNDS.lockTimeoutMs - 500, `refused too early: ${elapsed}ms`);
    assert.ok(elapsed < MAIL_DB_POOL_BOUNDS.lockTimeoutMs + 5_000, `bound not applied: ${elapsed}ms`);
  } finally {
    await holder.query("SELECT pg_advisory_unlock(728133777)").catch(() => undefined);
    holder.release();
    await pool.end();
  }
});

test("readiness is NOT ready when the read-back pool is down, even though the write pool answers", async () => {
  const deadReadPool = new Pool({
    connectionString: "postgres://postgres:test@127.0.0.1:1/unreachable",
    max: 1,
    connectionTimeoutMillis: 500,
  });
  deadReadPool.on("error", () => undefined);
  try {
    const probe = createReadinessProbe({
      databaseConfigured: true,
      pool: adminPool,
      readPool: deadReadPool,
    });
    assert.deepEqual(await probe(), {
      ready: false,
      checks: { database: "ok", readDatabase: "unavailable" },
    });
    // Positive control: both pools healthy is ready.
    const healthy = createReadinessProbe({
      databaseConfigured: true,
      pool: adminPool,
      readPool: adminPool,
    });
    assert.deepEqual(await healthy(), {
      ready: true,
      checks: { database: "ok", readDatabase: "ok" },
    });
  } finally {
    await deadReadPool.end().catch(() => undefined);
  }
});

test("server.ts hands the read-back pool to readiness (wiring, not just capability)", async () => {
  const source = await import("node:fs").then((fs) =>
    fs.readFileSync(path.join(ROOT, "src/server.ts"), "utf8"),
  );
  assert.match(source, /createReadinessProbe\(\{[\s\S]*?readPool \? \{ readPool \}/);
  assert.match(source, /createMailDbPool\(process\.env, \{ name: "write" \}\)/);
  assert.match(source, /createMailDbPool\(process\.env, \{ name: "read" \}\)/);
});

test("boot's recovery passes against a reachable but WEDGED database are refused within their bounds, never hang", async () => {
  // Reliability gap named against 3ba769f: the boot composition in
  // src/server.ts (reconcilePending, then completePendingErasures) had been
  // verified only through its lock/timeout primitives. This drives the real
  // service, built exactly as server.ts builds it but with a key provider so
  // the erasure pass actually reads, while another session holds ACCESS
  // EXCLUSIVE locks on the tables each pass reads first.
  await runMailMigrations(adminPool);
  // It wedges tables other files TRUNCATE and write, so it holds the suite's
  // shared memory-table lock for its whole duration, like every such file.
  const sharedTableLock = await lockSharedMemoryTables(adminPool);
  const write = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv, { name: "boot-write", onError: () => undefined });
  const read = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv, { name: "boot-read", onError: () => undefined });
  const service = createPostgresWave1MemoryService(write, read, { piiKeys: TEST_PII_KEYS });
  const wedge = await adminPool.connect();
  const bound = MAIL_DB_POOL_BOUNDS.lockTimeoutMs + 10_000;
  const timed = async (label: string, run: () => Promise<unknown>) => {
    const started = Date.now();
    const outcome = await Promise.race([
      run().then(
        () => "resolved",
        (error: { code?: string; message?: string }) => `rejected:${error.code ?? error.message}`,
      ),
      new Promise<string>((resolve) => setTimeout(() => resolve("STILL_WAITING"), bound + 20_000)),
    ]);
    return { label, outcome, elapsed: Date.now() - started };
  };
  try {
    await wedge.query("BEGIN");
    await wedge.query("LOCK TABLE memory_mutation_receipts, memory_pii_key_erasures IN ACCESS EXCLUSIVE MODE");
    const reconcile = await timed("reconcilePending", () => service.reconcilePending());
    const erasures = await timed("completePendingErasures", () => service.completePendingErasures());
    for (const result of [reconcile, erasures]) {
      assert.notEqual(result.outcome, "STILL_WAITING", JSON.stringify(result));
      assert.match(result.outcome, /^rejected:55P03$/, JSON.stringify(result));
      assert.ok(result.elapsed < bound, JSON.stringify(result));
    }
    await wedge.query("ROLLBACK");
    // Positive control: with the wedge gone, both passes complete.
    assert.equal(typeof (await service.reconcilePending()), "number");
    assert.deepEqual(Object.keys(await service.completePendingErasures()).sort(), ["destroyed", "pending"]);
  } finally {
    await wedge.query("ROLLBACK").catch(() => undefined);
    wedge.release();
    await write.end();
    await read.end();
    await sharedTableLock.release();
  }
});
