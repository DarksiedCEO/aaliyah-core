#!/usr/bin/env node
/**
 * THE TEST SUITE CANNOT PASS BY HANGING.
 *
 * Found by the mutation sweep against b3efc82: `node --test` ran with Node's
 * default `--test-timeout=0`, and 20 mutants produced no verdict at all — the
 * suite hung until something outside it was killed. One was root-caused: a test
 * held the only client of a one-connection pool, an assertion threw before the
 * release, and `finally { await pool.end() }` waited forever for that client.
 * From CI output, "the suite went green" and "the suite hung and someone killed
 * it" were indistinguishable.
 *
 * Measured on Node 24 while building this, each of which this runner closes:
 *
 *   - a timed-out test is counted `cancelled`, NOT `failed` — a check of
 *     `fail 0` alone would read a hang as a pass;
 *   - an `after` hook that never settles, with no live handle, exits 0 with
 *     every test passed (tests/support/hookSentinel.cjs);
 *   - a file whose timeout fires while a handle is live is reported failed,
 *     and the parent runner then waits for that child FOREVER;
 *   - killing the parent leaves the per-file child running, reparented to
 *     init — a hung worker silently dropped rather than stopped.
 *
 * So the verdict is computed here, from the event stream and the exit, never
 * from the runner's exit code alone:
 *
 *   PASS                    exit 0, every expected file reported, a summary
 *                           exists, passed === tests > 0, and failed,
 *                           cancelled, skipped and todo are all 0.
 *   FAIL                    anything else, including every timeout the
 *                           database is still reachable for.
 *   BLOCKED_BY_ENVIRONMENT  the database the suite requires was unreachable,
 *                           before the run (nothing executed) or after a
 *                           failed/timed-out run (the cause was environmental).
 *
 * A timeout is never PASS. Every run kills its whole process group on the way
 * out and proves nothing in it survived.
 *
 * Exit: 0 PASS · 1 FAIL · 3 BLOCKED_BY_ENVIRONMENT · 2 watchdog usage error.
 */
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(ROOT, "package.json"));

const DEFAULTS = {
  // Per test AND per file: in process isolation, a file's own wrapper test
  // inherits this, so it also bounds a file waiting on the shared-table lock.
  testTimeoutMs: 240_000,
  // The whole run.
  deadlineMs: 900_000,
  // After every expected file has reported, how long the runner may take to
  // exit before it is treated as hung.
  exitGraceMs: 15_000,
  statementTimeoutMs: 60_000,
  lockTimeoutMs: 60_000,
  idleInTransactionTimeoutMs: 120_000,
  dbProbeTimeoutMs: 5_000,
};

function usage(message) {
  process.stderr.write(`test-watchdog: ${message}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  const options = { ...DEFAULTS, requireDb: true, evidence: null, files: [] };
  const numeric = {
    "--test-timeout-ms": "testTimeoutMs",
    "--deadline-ms": "deadlineMs",
    "--exit-grace-ms": "exitGraceMs",
    "--statement-timeout-ms": "statementTimeoutMs",
    "--lock-timeout-ms": "lockTimeoutMs",
    "--idle-in-transaction-timeout-ms": "idleInTransactionTimeoutMs",
    "--db-probe-timeout-ms": "dbProbeTimeoutMs",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--") {
      options.files.push(...argv.slice(i + 1));
      break;
    }
    if (arg === "--no-db") {
      options.requireDb = false;
    } else if (arg === "--evidence") {
      options.evidence = argv[++i] ?? usage("--evidence needs a path");
    } else if (arg in numeric) {
      const value = Number(argv[++i]);
      if (!Number.isSafeInteger(value) || value <= 0) {
        usage(`${arg} needs a positive integer`);
      }
      options[numeric[arg]] = value;
    } else if (arg.startsWith("-")) {
      usage(`unknown option ${arg}`);
    } else {
      options.files.push(arg);
    }
  }
  return options;
}

/** Exactly the old `tests/*.test.ts tests/*\/*.test.ts` glob, without a shell. */
function fullSuiteFiles() {
  const tests = path.join(ROOT, "tests");
  const found = [];
  for (const entry of fs.readdirSync(tests, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".test.ts")) {
      found.push(path.join("tests", entry.name));
    } else if (entry.isDirectory()) {
      for (const inner of fs.readdirSync(path.join(tests, entry.name), {
        withFileTypes: true,
      })) {
        if (inner.isFile() && inner.name.endsWith(".test.ts")) {
          found.push(path.join("tests", entry.name, inner.name));
        }
      }
    }
  }
  return found.sort();
}

function pgOptions(options) {
  const ours = {
    statement_timeout: options.statementTimeoutMs,
    lock_timeout: options.lockTimeoutMs,
    idle_in_transaction_session_timeout: options.idleInTransactionTimeoutMs,
  };
  // THE WATCHDOG'S BOUNDS ARE AUTHORITATIVE. Any setting of the same three keys
  // inherited through PGOPTIONS — including from an outer watchdog run — is
  // removed, so a bound can never be silently widened (or left unbounded) by
  // the environment. Other inherited options pass through untouched.
  let inherited = process.env.PGOPTIONS ?? "";
  for (const key of Object.keys(ours)) {
    inherited = inherited.replace(new RegExp(`(?:-c\\s*|--)${key}\\s*=\\s*\\S+`, "g"), "");
  }
  const parts = inherited.trim() ? [inherited.trim().replace(/\s+/g, " ")] : [];
  for (const [key, value] of Object.entries(ours)) {
    parts.push(`-c ${key}=${value}`);
  }
  return parts.join(" ");
}

function childEnv(options) {
  const env = { ...process.env, PGOPTIONS: pgOptions(options) };
  // Set by node:test inside every test worker. Inherited by a runner started
  // from within a test, it makes that runner behave as a WORKER — streaming
  // serialized events to its parent instead of running its reporters — so it
  // would report nothing at all. Removed so a watchdog run is always a root run.
  delete env.NODE_TEST_CONTEXT;
  // NOTHING INHERITED MAY CHOOSE WHICH TESTS RUN. Red team M1 against
  // 2b2e554: NODE_OPTIONS="--test-skip-pattern=..." deselected 68 destroyer,
  // PII, race and receipt tests and the run was still PASS on a clean tree;
  // on a fixture it turned a failing test into PASS. NODE_OPTIONS can also
  // preload code (--require/--import) that rewrites node:test. Every flag the
  // runner needs is on its own argv, so the variable is dropped entirely and
  // what was dropped is recorded in the evidence.
  delete env.NODE_OPTIONS;
  // The same holds for the compiler every worker is started with. Red team F1
  // against 3ba769f: an inherited TS_NODE_PROJECT pointed ts-node at a
  // tsconfig whose "ts-node".require preloaded code that swallowed test
  // failures, and a failing fixture was PASS. The runner's own tsconfig is the
  // only one it compiles with; every inherited TS_NODE_* is dropped and
  // recorded.
  for (const key of Object.keys(env)) {
    if (key.startsWith("TS_NODE_")) delete env[key];
  }
  return env;
}

async function probeDatabase(url, timeoutMs) {
  if (!url) return { reachable: false, reason: "AALIYAH_TEST_DATABASE_URL is not set" };
  const { Client } = require("pg");
  const client = new Client({
    connectionString: url,
    connectionTimeoutMillis: timeoutMs,
    query_timeout: timeoutMs,
  });
  try {
    await client.connect();
    await client.query("SELECT 1");
    return { reachable: true, reason: null };
  } catch (error) {
    return {
      reachable: false,
      reason: `${error?.code ?? "ERROR"}: ${String(error?.message ?? error).slice(0, 300)}`,
    };
  } finally {
    await client.end().catch(() => {});
  }
}

function groupAlive(pgid) {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

async function killGroup(pgid) {
  if (!groupAlive(pgid)) return { hadSurvivors: false, survivedSigkill: false };
  try {
    process.kill(-pgid, "SIGTERM");
  } catch {}
  for (let i = 0; i < 30 && groupAlive(pgid); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (groupAlive(pgid)) {
    try {
      process.kill(-pgid, "SIGKILL");
    } catch {}
    for (let i = 0; i < 50 && groupAlive(pgid); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  return { hadSurvivors: true, survivedSigkill: groupAlive(pgid) };
}

function readEvents(file) {
  if (!fs.existsSync(file)) return [];
  const events = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      // A line torn by a kill mid-write is not evidence of anything.
    }
  }
  return events;
}

function gitIdentity() {
  try {
    const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
    const dirty = execFileSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf8" }).trim() !== "";
    return { head, dirty };
  } catch {
    return { head: null, dirty: null };
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const scope = options.files.length === 0 ? "FULL_SUITE" : "FOCUSED";
  const files = scope === "FULL_SUITE" ? fullSuiteFiles() : options.files;
  if (files.length === 0) usage("no test files");
  for (const file of files) {
    if (!fs.existsSync(path.resolve(ROOT, file))) usage(`no such test file: ${file}`);
  }
  const absoluteFiles = new Set(files.map((file) => path.resolve(ROOT, file)));

  const startedAt = new Date();
  const runDir = fs.mkdtempSync(path.join(ROOT, ".test-evidence-run-"));
  const eventsFile = path.join(runDir, "events.jsonl");
  const evidencePath = path.resolve(
    ROOT,
    options.evidence ?? path.join(".test-evidence", "last-run.json"),
  );
  const dbUrl = process.env.AALIYAH_TEST_DATABASE_URL;

  const evidence = {
    watchdog: "aaliyah-core/scripts/test-watchdog.mjs",
    scope,
    git: gitIdentity(),
    node: process.version,
    startedAt: startedAt.toISOString(),
    finishedAt: null,
    durationMs: null,
    environment: {
      nodeOptionsIgnored: process.env.NODE_OPTIONS ?? null,
      tsNodeIgnored: Object.fromEntries(
        Object.entries(process.env).filter(([key]) => key.startsWith("TS_NODE_")),
      ),
    },
    bounds: {
      testTimeoutMs: options.testTimeoutMs,
      deadlineMs: options.deadlineMs,
      exitGraceMs: options.exitGraceMs,
      pgOptions: pgOptions(options),
    },
    files: files.length,
    verdict: null,
    reasons: [],
    counts: null,
    exit: null,
    timedOut: [],
    failures: [],
    filesWithoutResult: [],
    filesWithoutTests: [],
    filesWithoutSummary: [],
    testsNeverFinished: [],
    processGroup: null,
    database: { required: options.requireDb, before: null, after: null },
  };

  const finish = (verdict) => {
    evidence.verdict = verdict;
    evidence.finishedAt = new Date().toISOString();
    evidence.durationMs = Date.now() - startedAt.getTime();
    fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
    fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
    fs.rmSync(runDir, { recursive: true, force: true });
    const counts = evidence.counts;
    process.stdout.write(
      `\nWATCHDOG VERDICT: ${verdict} scope=${scope}` +
        (counts
          ? ` tests=${counts.tests} pass=${counts.passed} fail=${counts.failed} cancelled=${counts.cancelled} skipped=${counts.skipped} todo=${counts.todo}`
          : "") +
        `\n` +
        evidence.reasons.map((reason) => `  reason: ${reason}\n`).join("") +
        `  evidence: ${path.relative(ROOT, evidencePath)}\n`,
    );
    process.exit(verdict === "PASS" ? 0 : verdict === "BLOCKED_BY_ENVIRONMENT" ? 3 : 1);
  };

  if (options.requireDb) {
    evidence.database.before = await probeDatabase(dbUrl, options.dbProbeTimeoutMs);
    if (!evidence.database.before.reachable) {
      evidence.reasons.push(
        `database unreachable before the run, nothing executed: ${evidence.database.before.reason}`,
      );
      finish("BLOCKED_BY_ENVIRONMENT");
      return;
    }
  }

  const args = [
    "--require",
    "ts-node/register",
    "--require",
    path.join(ROOT, "tests/support/hookSentinel.cjs"),
    "--test",
    `--test-timeout=${options.testTimeoutMs}`,
    "--test-reporter=spec",
    "--test-reporter-destination=stdout",
    `--test-reporter=${path.join(ROOT, "scripts/test-watchdog-reporter.mjs")}`,
    `--test-reporter-destination=${eventsFile}`,
    ...files,
  ];
  const child = spawn(process.execPath, args, {
    cwd: ROOT,
    detached: true,
    stdio: ["ignore", "inherit", "inherit"],
    env: childEnv(options),
  });
  const pgid = child.pid;

  let stopReason = null;
  const onSignal = (signal) => {
    stopReason ??= `watchdog received ${signal}`;
    killGroup(pgid).finally(() => {});
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  const exited = new Promise((resolve) => {
    child.on("exit", (code, signal) => resolve({ code, signal }));
  });

  const deadlineAt = Date.now() + options.deadlineMs;
  let allReportedAt = null;
  let lastEventCount = -1;
  let lastEventAt = Date.now();
  let exit = null;
  while (exit === null) {
    exit = await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(() => resolve(null), 250)),
    ]);
    if (exit !== null || stopReason) break;
    if (Date.now() >= deadlineAt) {
      stopReason = `DEADLINE_EXCEEDED: the run did not finish within ${options.deadlineMs}ms`;
      break;
    }
    const live = readEvents(eventsFile);
    const reported = new Set(
      live
        .filter((e) => (e.type === "test:complete" || e.type === "test:fail") && e.nesting === 0)
        .map((e) => path.resolve(ROOT, e.name ?? ""))
        .filter((name) => absoluteFiles.has(name)),
    );
    // ONCE ANYTHING HAS TIMED OUT, THE RUN HAS ALREADY FAILED. What remains is
    // possibly a worker that will never exit — a timed-out hook's failure is
    // even attributed to the sentinel's wrapper, not to its file, so "every
    // file reported" cannot be relied on to notice it. If a timeout has been
    // seen and the event stream has been silent for the grace period, stop:
    // waiting out the whole deadline adds no evidence to a verdict already FAIL.
    const timeoutSeen = live.some(
      (e) => e.type === "test:fail" && /timed out/i.test(e.message ?? ""),
    );
    if (live.length !== lastEventCount) {
      lastEventCount = live.length;
      lastEventAt = Date.now();
    }
    if (timeoutSeen && Date.now() - lastEventAt >= options.exitGraceMs) {
      stopReason = `HUNG_WORKER: a timeout occurred and the run produced no further events for ${options.exitGraceMs}ms`;
      break;
    }
    if ([...absoluteFiles].every((file) => reported.has(file))) {
      allReportedAt ??= Date.now();
      if (Date.now() - allReportedAt >= options.exitGraceMs) {
        stopReason = `HUNG_WORKER: every file reported, and the runner had not exited ${options.exitGraceMs}ms later`;
        break;
      }
    }
  }

  // Always, on every path: nothing started by this run outlives it.
  const groupKill = await killGroup(pgid);
  if (exit === null) {
    exit = await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(() => resolve({ code: null, signal: "UNREAPED" }), 5_000)),
    ]);
  }
  evidence.exit = exit;
  evidence.processGroup = {
    pgid,
    killedSurvivors: groupKill.hadSurvivors,
    survivedSigkill: groupKill.survivedSigkill,
  };

  const events = readEvents(eventsFile);
  const summary = [...events].reverse().find((e) => e.type === "test:summary" && e.file === null);
  evidence.counts = summary?.counts ?? null;

  const fileResults = new Map();
  const testsPerFile = new Map();
  const enqueuedPerFile = new Map();
  const outcomesPerFile = new Map();
  const fileSummaries = new Set();
  const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1);
  for (const event of events) {
    const name = path.resolve(ROOT, event.name ?? "");
    const isFileLevel = event.nesting === 0 && absoluteFiles.has(name);
    if (event.type === "test:summary" && event.file) {
      fileSummaries.add(path.resolve(ROOT, event.file));
    }
    if (!isFileLevel && event.file && event.type === "test:enqueue") {
      bump(enqueuedPerFile, path.resolve(ROOT, event.file));
    }
    if (!isFileLevel && event.file && (event.type === "test:pass" || event.type === "test:fail")) {
      bump(outcomesPerFile, path.resolve(ROOT, event.file));
    }
    if (isFileLevel && (event.type === "test:complete" || event.type === "test:fail")) {
      fileResults.set(name, event);
    }
    if (!isFileLevel && event.type === "test:pass" && event.file) {
      const file = path.resolve(ROOT, event.file);
      testsPerFile.set(file, (testsPerFile.get(file) ?? 0) + 1);
    }
    if (event.type === "test:fail") {
      const record = {
        name: event.name,
        file: event.file ? path.relative(ROOT, event.file) : null,
        failureType: event.failureType,
        message: event.message,
        code: event.code,
      };
      if (
        event.failureType === "testTimeoutFailure" ||
        event.failureType === "cancelledByParent" ||
        /timed out/i.test(event.message ?? "")
      ) {
        evidence.timedOut.push(record);
      } else {
        evidence.failures.push(record);
      }
    }
  }
  evidence.filesWithoutResult = [...absoluteFiles]
    .filter((file) => !fileResults.has(file))
    .map((file) => path.relative(ROOT, file));
  evidence.filesWithoutTests = [...absoluteFiles]
    .filter((file) => fileResults.has(file) && !testsPerFile.has(file))
    .map((file) => path.relative(ROOT, file));
  evidence.filesWithoutSummary = [...absoluteFiles]
    .filter((file) => !fileSummaries.has(file))
    .map((file) => path.relative(ROOT, file));
  evidence.testsNeverFinished = [...enqueuedPerFile]
    .filter(([file, queued]) => queued > (outcomesPerFile.get(file) ?? 0))
    .map(([file, queued]) => ({
      file: path.relative(ROOT, file),
      queued,
      finished: outcomesPerFile.get(file) ?? 0,
    }));

  const reasons = evidence.reasons;
  if (stopReason) reasons.push(stopReason);
  if (groupKill.hadSurvivors) {
    reasons.push("ORPHANED_PROCESSES: processes from this run were still alive and were killed");
  }
  if (groupKill.survivedSigkill) {
    reasons.push("UNKILLABLE_PROCESSES: processes from this run survived SIGKILL");
  }
  if (exit.code !== 0) reasons.push(`NONZERO_EXIT: code=${exit.code} signal=${exit.signal}`);
  if (!summary) {
    reasons.push("NO_SUMMARY: the runner never reported final counts");
  } else {
    const c = summary.counts;
    if (c.failed !== 0) reasons.push(`FAILED_TESTS: ${c.failed}`);
    if (c.cancelled !== 0) reasons.push(`CANCELLED_TESTS: ${c.cancelled} (a timeout is cancelled, and cancelled is never a pass)`);
    if (c.skipped !== 0) reasons.push(`SKIPPED_TESTS: ${c.skipped}`);
    if (c.todo !== 0) reasons.push(`TODO_TESTS: ${c.todo}`);
    if (c.tests === 0) reasons.push("ZERO_TESTS");
    if (c.passed !== c.tests) reasons.push(`PASSED_NOT_EQUAL_TESTS: ${c.passed} of ${c.tests}`);
    if (summary.success !== true) reasons.push("RUNNER_REPORTED_UNSUCCESSFUL");
  }
  if (evidence.timedOut.length > 0) {
    reasons.push(`TIMED_OUT: ${evidence.timedOut.map((t) => `${t.file ?? "?"} :: ${t.name}`).join(" | ")}`);
  }
  if (evidence.filesWithoutResult.length > 0) {
    reasons.push(`FILES_WITHOUT_RESULT: ${evidence.filesWithoutResult.join(", ")}`);
  }
  if (evidence.filesWithoutSummary.length > 0) {
    reasons.push(`FILES_WITHOUT_SUMMARY: ${evidence.filesWithoutSummary.join(", ")}`);
  }
  if (evidence.testsNeverFinished.length > 0) {
    reasons.push(
      `TESTS_NEVER_FINISHED: ${evidence.testsNeverFinished
        .map((f) => `${f.file} queued=${f.queued} finished=${f.finished}`)
        .join(" | ")}`,
    );
  }
  if (evidence.filesWithoutTests.length > 0) {
    reasons.push(`FILES_WITHOUT_TESTS: ${evidence.filesWithoutTests.join(", ")}`);
  }

  if (reasons.length === 0) {
    finish("PASS");
    return;
  }
  if (options.requireDb) {
    evidence.database.after = await probeDatabase(dbUrl, options.dbProbeTimeoutMs);
    if (!evidence.database.after.reachable) {
      reasons.push(`database unreachable after the run: ${evidence.database.after.reason}`);
      finish("BLOCKED_BY_ENVIRONMENT");
      return;
    }
  }
  finish("FAIL");
}

main().catch((error) => {
  process.stderr.write(`test-watchdog internal error: ${error?.stack ?? error}\n`);
  process.exit(2);
});
