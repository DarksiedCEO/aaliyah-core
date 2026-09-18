import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { Pool } from "pg";

import {
  createMailDbPool,
  isConnectionAmbiguous,
  MAIL_DB_POOL_BOUNDS,
  releaseClient,
} from "../src/persistence/postgres/pool";
import { createReadinessProbe } from "../src/http/readiness";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresWave1MemoryService } from "../src/persistence/postgres/wave1IdentityGraphStore";
import { createPostgresMemoryReconciler } from "../src/persistence/postgres/wave1MemoryReconciler";
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
    assert.deepEqual(Object.keys(await service.completePendingErasures()).sort(), [
      // `notProven` and its reasons are what make an unprovable key
      // distinguishable from a late one (founder decision, OPTION B), and
      // `repaired`/`contradictions` are what make a detected forged
      // `key_destroyed` row visible at all.
      "contradictions",
      "destroyed",
      "notProven",
      "notProvenReasons",
      "obligationsUnrecorded",
      "pending",
      "repaired",
    ]);
  } finally {
    await wedge.query("ROLLBACK").catch(() => undefined);
    wedge.release();
    await write.end();
    await read.end();
    await sharedTableLock.release();
  }
});

test("K-10: a FAILING reconciliation pass does not skip the erasure completion pass, and neither failure is silent", async () => {
  // ---- WHAT WAS OBSERVED AT 03581a3 ---------------------------------
  // Reliability review, MEDIUM: `src/server.ts` awaited `reconcilePending()`
  // and `completePendingErasures()` inside ONE try/catch, so a
  // `reconcilePending` rejection skipped the erasure pass ENTIRELY — and
  // skipped it silently, because the single catch printed a message about
  // reconciliation and said nothing about the pass that never ran. A database
  // briefly unreadable at boot therefore left alias data keys unconfirmed with
  // no trace that anything had been missed.
  //
  // Driven as a REAL PROCESS: both passes are made to fail by privilege, and
  // both failures must appear. At 8a0bf05 only the first could.
  await runMailMigrations(adminPool);
  const sharedTableLock = await lockSharedMemoryTables(adminPool);
  try {
    // `reconcilePending` reads mutation receipts as the reconciler;
    // `completePendingErasures` reads key-erasure evidence as the mutator.
    await adminPool.query(`REVOKE SELECT ON memory_mutation_receipts FROM aaliyah_memory_reconciler`);
    await adminPool.query(`REVOKE SELECT ON memory_pii_key_erasures FROM aaliyah_memory_mutator`);
    const boot = spawn(
      process.execPath,
      ["--require", "ts-node/register", path.join(ROOT, "src/server.ts")],
      {
        cwd: ROOT,
        env: {
          ...process.env,
          AALIYAH_DATABASE_URL: DB_URL,
          PORT: "0",
          NODE_ENV: "test",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let out = "";
    boot.stdout.on("data", (chunk) => {
      out += String(chunk);
    });
    boot.stderr.on("data", (chunk) => {
      out += String(chunk);
    });
    try {
      // Wait for the process to get past boot recovery: the readiness line is
      // printed after both passes have been attempted.
      const deadline = Date.now() + 25_000;
      while (!/Aaliyah core running on/.test(out) && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
      assert.match(out, /Aaliyah core running on/, `server never finished booting:\n${out}`);
      // BOTH failures reported, each naming its own pass.
      assert.match(out, /trusted memory: reconciliation pass failed/, out);
      assert.match(out, /trusted memory: alias key completion pass failed/, out);
      // And the process is alive: a failed recovery pass is not a failed boot.
      assert.equal(boot.exitCode, null);
    } finally {
      boot.kill("SIGKILL");
      await new Promise((resolve) => boot.once("exit", resolve));
    }
  } finally {
    await adminPool.query(`GRANT SELECT ON memory_mutation_receipts TO aaliyah_memory_reconciler`);
    await adminPool.query(`GRANT SELECT ON memory_pii_key_erasures TO aaliyah_memory_mutator`);
    await sharedTableLock.release();
  }
});

/**
 * K-05 — EVERY BOUND ABOVE IS THE SERVER'S, SO THE CLIENT NEEDS ITS OWN.
 *
 * 03581a3 reliability review, HIGH: `statement_timeout`, `lock_timeout` and
 * `idle_in_transaction_session_timeout` are enforced by the PostgreSQL
 * BACKEND. They bound a backend that is running its own timers. They bound
 * NOTHING when the backend has stopped answering — a SIGSTOPped backend held
 * boot 30 SECONDS past its 10s bound, waiting for bytes that were never
 * coming, and `grep query_timeout src/` returned nothing.
 *
 * Reproduced here without signalling anything, by wedging the TRANSPORT: a
 * pass-through TCP proxy completes the real handshake against the real
 * database, then stops relaying in both directions. From the client's side
 * this is indistinguishable from a stopped backend — and it is strictly
 * harsher than SIGSTOP, because the server's OWN `statement_timeout` does
 * fire here and its error still cannot arrive.
 */
function wedgeableProxy(target: { host: string; port: number }): {
  port: Promise<number>;
  wedge: () => void;
  close: () => Promise<void>;
} {
  const sockets: Array<{ destroy: () => void }> = [];
  let wedged = false;
  const server = net.createServer((incoming) => {
    const outgoing = net.connect(target.port, target.host);
    sockets.push(incoming, outgoing);
    const relay = (from: net.Socket, to: net.Socket) => {
      from.on("data", (chunk) => {
        // A wedged transport does not error and does not close. It is silent,
        // which is the whole point: a closed socket would be reported.
        if (!wedged) to.write(chunk);
      });
      from.on("error", () => to.destroy());
      from.on("close", () => to.destroy());
    };
    relay(incoming, outgoing);
    relay(outgoing, incoming);
  });
  const port = new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
  });
  return {
    port,
    wedge: () => {
      wedged = true;
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test("the mail pool carries a CLIENT-side query ceiling and TCP keepalives, not only the server's bounds", async () => {
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  try {
    const options = pool.options as unknown as {
      query_timeout?: number;
      keepAlive?: boolean;
      keepAliveInitialDelayMillis?: number;
    };
    assert.equal(options.query_timeout, MAIL_DB_POOL_BOUNDS.queryTimeoutMs);
    assert.equal(options.keepAlive, true);
    assert.equal(
      options.keepAliveInitialDelayMillis,
      MAIL_DB_POOL_BOUNDS.keepAliveInitialDelayMillis,
    );
    // Above the server's own statement bound ON PURPOSE: when the server is
    // alive its `57014` should win, because it says what happened.
    assert.ok(
      MAIL_DB_POOL_BOUNDS.queryTimeoutMs > MAIL_DB_POOL_BOUNDS.statementTimeoutMs,
      "a client ceiling at or below statement_timeout would mask the server's own error",
    );
  } finally {
    await pool.end();
  }
});

test("K-05: an AMBIGUOUS connection is DESTROYED, and an ordinary error's connection is not", async () => {
  // ---- A REAL MUTATION SURVIVOR, AND THE TEST THAT KILLS IT ---------
  // Found by this round's own sweep (M-29). `releaseClient` could be changed
  // to never destroy — `client.release(undefined)` for every error — and all
  // 14 tests in this file still passed.
  //
  // The reason: the wedged-transport test above goes through `pool.query()`,
  // and pg-pool ALREADY passes the error to `release()` on that path, so it
  // destroys the client whatever `releaseClient` decides. Every caller that
  // checks a client OUT explicitly — which is every transaction the memory
  // stores open — depends on `releaseClient` instead, and nothing drove it.
  //
  // The decision is about which argument is passed, so it is asserted
  // directly, on a client that records what it was told.
  const seen: Array<boolean | undefined> = [];
  const spy = { release: (destroy?: boolean) => seen.push(destroy) };

  // AMBIGUOUS: the outcome of the last query is unknown, so a later caller
  // could be handed a connection that answers with the previous caller's
  // result. Destroyed.
  const ambiguous: unknown[] = [
    new Error("Query read timeout"),
    new Error("Connection terminated unexpectedly"),
    Object.assign(new Error("terminating connection due to administrator command"), { code: "57P01" }),
    Object.assign(new Error("terminating connection due to idle-in-transaction timeout"), { code: "25P03" }),
    Object.assign(new Error("connection exception"), { code: "08006" }),
    Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" }),
  ];
  for (const error of ambiguous) {
    assert.equal(isConnectionAmbiguous(error), true, String((error as Error).message));
    seen.length = 0;
    releaseClient(spy, error);
    assert.deepEqual(seen, [true], `not destroyed: ${String((error as Error).message)}`);
  }

  // NOT AMBIGUOUS: the server answered, and its answer was a refusal. The
  // connection is perfectly good, and destroying it on every constraint
  // violation would turn ordinary refusals into connection churn.
  const ordinary: unknown[] = [
    Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" }),
    Object.assign(new Error("new row violates check constraint"), { code: "23514" }),
    Object.assign(new Error("canceling statement due to statement timeout"), { code: "57014" }),
    Object.assign(new Error("lock timeout"), { code: "55P03" }),
    new Error("aaliyah memory: a subject erasure may not complete"),
  ];
  for (const error of ordinary) {
    assert.equal(isConnectionAmbiguous(error), false, String((error as Error).message));
    seen.length = 0;
    releaseClient(spy, error);
    assert.deepEqual(seen, [undefined], `wrongly destroyed: ${String((error as Error).message)}`);
  }

  // No error at all: an ordinary release.
  seen.length = 0;
  releaseClient(spy);
  assert.deepEqual(seen, [undefined]);

  // AND THE SAME DECISION THROUGH A REAL CHECKED-OUT CLIENT. A backend killed
  // mid-transaction is the shape the memory stores actually meet.
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv, {
    name: "release-decision",
    onError: () => undefined,
  });
  try {
    const client = await pool.connect();
    let failure: unknown;
    try {
      await client.query("BEGIN");
      const pid = (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;
      await adminPool.query("SELECT pg_terminate_backend($1)", [pid]);
      await client.query("SELECT 1");
      assert.fail("the terminated backend must reject the next query");
    } catch (error) {
      failure = error;
    }
    assert.equal(isConnectionAmbiguous(failure), true, String(failure));
    releaseClient(client, failure);
    // Destroyed, so the pool holds no idle client that might answer with a
    // dead session's result.
    assert.equal(pool.idleCount, 0, `a destroyed client was kept: idle=${pool.idleCount}`);
    // Positive control: the pool still serves.
    assert.equal((await pool.query("SELECT 1 AS ok")).rows[0].ok, 1);
  } finally {
    await pool.end().catch(() => undefined);
  }
});

test("NO pooled client in src/ is released without the ambiguity guard — structural, so the class cannot come back", () => {
  // ---- WHY THIS IS STRUCTURAL AND NOT BEHAVIOURAL ---------------------
  //
  // The reliability review of a9d203d found SIX persistence modules releasing
  // pooled clients with a bare `client.release()`, across twelve call sites,
  // none of them reached by any test. Auditing by hand then found MORE than
  // the review had listed: `wave1TrustedMemoryStore.ts` — the file the review
  // called correctly guarded — held eleven guarded sites and SIX unguarded
  // ones, and `idempotencyStore.ts` and `wave1LifecycleStore.ts` had one each
  // that the review's list did not include. Twenty sites in total.
  //
  // The behavioural test above proves the MECHANISM works, on one real store
  // path. It cannot prove no site was MISSED, and a wedge test per site would
  // cost seventy seconds each. This is the defence that scales: one assertion
  // over the whole tree, which fails the moment a new raw release appears.
  //
  // It is the same move the register records for trigger enablement — when a
  // class of defect keeps recurring, the guard belongs in a structural check
  // that no individual omission can slip past, not in N more behavioural
  // tests that each cover one instance.
  const root = path.join(ROOT, "src");
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".ts")) files.push(full);
    }
  };
  walk(root);
  assert.ok(files.length > 20, `only ${files.length} source files walked; the walk is wrong`);

  const offenders: string[] = [];
  for (const file of files) {
    // `pool.ts` DEFINES the guard, so it is the one place a raw release is
    // correct — and it is named explicitly rather than skipped by pattern, so
    // a second "exception" cannot be added quietly.
    const relative = path.relative(ROOT, file);
    if (relative === "src/persistence/postgres/pool.ts") continue;
    const lines = fs.readFileSync(file, "utf8").split("\n");
    lines.forEach((line, index) => {
      // A release that is not `releaseClient(...)`. Matches `client.release()`,
      // `readClient.release()`, `x.release(true)` — anything that hands a
      // client back without deciding whether it is safe to reuse.
      if (/\breleaseClient\s*\(/.test(line)) return;
      if (/\b[A-Za-z_$][\w$]*\.release\s*\(/.test(line)) {
        offenders.push(`${relative}:${index + 1}: ${line.trim()}`);
      }
    });
  }
  assert.deepEqual(
    offenders,
    [],
    `pooled clients released without the ambiguity guard:\n${offenders.join("\n")}`,
  );
});

test("a STORE that connects and releases by hand destroys an ambiguous client too, not just pool.query", async () => {
  // ---- RELIABILITY REVIEW OF a9d203d, CRITICAL, REPRODUCED -----------
  //
  // The K-05 test below proves the POOL's own path: `pool.query()` hands the
  // error to `release()` internally, so pg-pool destroys the client. It proves
  // NOTHING about the many store functions that call `pool.connect()` and
  // `client.release()` themselves — and SIX persistence modules did exactly
  // that with a bare `client.release()`, across twelve call sites:
  //
  //   memoryMutationAttempts, wave1IdentityGraphStore, wave1LifecycleStore,
  //   wave1AliasRegistryStore, wave1MemoryReconciler, wave1LegalHoldStore
  //
  // pg-pool evicts a client only when an error is PASSED to release(), or when
  // the client's own `_queryable` flag has already flipped — and pg sets that
  // flag only from `_handleErrorEvent`, a real socket error. A client-side
  // `Query read timeout` does neither: it rejects the query, stubs the
  // callback, and leaves a connected socket with an abandoned query still on
  // the wire. A bare `release()` then returns that client to the idle pool,
  // where the next caller can be answered with the previous caller's result.
  //
  // `wave1MemoryReconciler.findUnresolved()` is the one `src/server.ts` calls
  // at BOOT, which is why it is the subject here.
  const url = new URL(DB_URL);
  const proxy = wedgeableProxy({ host: url.hostname, port: Number(url.port || 5432) });
  const proxyPort = await proxy.port;
  const proxied = new URL(DB_URL);
  proxied.port = String(proxyPort);
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: proxied.href } as NodeJS.ProcessEnv);
  try {
    const reconciler = createPostgresMemoryReconciler(pool);
    // POSITIVE CONTROL: through the relaying proxy the real store call works,
    // so the refusal below is the wedge and not the proxy or the role.
    await reconciler.findUnresolved(1);
    assert.equal(pool.idleCount, 1, "fixture precondition: the client should be pooled here");

    proxy.wedge();
    await assert.rejects(
      reconciler.findUnresolved(1),
      (error: { message?: string }) => /Query read timeout/i.test(String(error.message)),
      "the wedge must surface as the client-side read timeout",
    );

    // THE ASSERTION. The store released by hand; the client must be GONE.
    assert.equal(
      pool.idleCount,
      0,
      `an ambiguous client was returned to the pool by a hand-written release (idle=${pool.idleCount})`,
    );
    assert.ok(isConnectionAmbiguous(new Error("Query read timeout")));
  } finally {
    await pool.end().catch(() => undefined);
    await proxy.close();
  }
});

test("a WEDGED transport is abandoned by the client within its own bound, and the connection is not reused", async () => {
  const url = new URL(DB_URL);
  const proxy = wedgeableProxy({ host: url.hostname, port: Number(url.port || 5432) });
  const proxyPort = await proxy.port;
  const proxied = new URL(DB_URL);
  proxied.port = String(proxyPort);
  const pool = createMailDbPool({ AALIYAH_DATABASE_URL: proxied.href } as NodeJS.ProcessEnv);
  try {
    // POSITIVE CONTROL: through the proxy, while it relays, everything works —
    // so the refusal below is the wedge and not the proxy.
    assert.equal((await pool.query("SELECT 1 AS ok")).rows[0].ok, 1);
    const wedgedPid = (await pool.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;

    proxy.wedge();
    const started = Date.now();
    await assert.rejects(
      pool.query("SELECT pg_sleep(600)"),
      (error: { message?: string }) => /Query read timeout/i.test(String(error.message)),
      "a wedged transport must be abandoned by the CLIENT; the server's bounds cannot reach it",
    );
    const elapsed = Date.now() - started;
    assert.ok(
      elapsed >= MAIL_DB_POOL_BOUNDS.queryTimeoutMs - 1_000,
      `abandoned too early to be this bound: ${elapsed}ms`,
    );
    assert.ok(
      elapsed < MAIL_DB_POOL_BOUNDS.queryTimeoutMs + 10_000,
      `the client ceiling did not apply: ${elapsed}ms`,
    );

    // The abandoned connection is AMBIGUOUS — node-postgres stopped listening
    // without cancelling the backend, so a result for that query can still
    // arrive on it. It must not be handed to the next caller.
    assert.ok(isConnectionAmbiguous(new Error("Query read timeout")));
    const survivors = await adminPool.query(
      `SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid = $1`,
      [wedgedPid],
    );
    // Whether the backend is already gone or still winding down, what matters
    // is that the POOL no longer holds that client.
    assert.ok(
      pool.idleCount === 0,
      `the abandoned client was returned to the pool (idle=${pool.idleCount}, backend rows=${survivors.rows[0].n})`,
    );
  } finally {
    await pool.end().catch(() => undefined);
    await proxy.close();
  }
});
