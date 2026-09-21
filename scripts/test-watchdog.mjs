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
  const options = {
    ...DEFAULTS,
    requireDb: true,
    evidence: null,
    verifyDiscoveryOnly: false,
    writeManifest: false,
    files: [],
  };
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
    } else if (arg === "--verify-discovery") {
      // Answers ONE question — is the full suite the commit's suite? — and
      // runs nothing. A release guard can ask it without paying for a suite.
      options.verifyDiscoveryOnly = true;
    } else if (arg === "--write-manifest") {
      // Records this FULL_SUITE run's executed set as scripts/test-manifest.tsv.
      // Only from an otherwise-clean run, and the run is then NOT a verdict:
      // a run that defines its own denominator cannot also be measured by it.
      options.writeManifest = true;
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

/**
 * THE EXECUTED SET IS BOUND TO THE COMMIT, NOT TO THE FILESYSTEM.
 *
 * Found by the red team against 8a0bf05 (K-19): `fullSuiteFiles()` walks the
 * filesystem, and `.gitignore` excludes `coverage`, so a `tests/coverage/
 * *.test.ts` file is DISCOVERED AND EXECUTED while `git status --porcelain`
 * stays empty and the evidence records `git.dirty: false`. Reproduced: 84
 * files discovered where the commit has 83, dirty=false. A PASS was therefore
 * a claim about a set of files nobody could reconstruct from the SHA — the
 * evidence named a commit it did not actually describe.
 *
 * Nothing here decides which tests run. It decides whether the set that ran
 * is the set the SHA contains, and refuses the verdict when it is not:
 *
 *   - an IGNORED discovered file is refused outright. It cannot appear in
 *     `git status`, so it is invisible in exactly the way that matters;
 *   - an UNTRACKED-but-not-ignored file is allowed, because `git status`
 *     already reports it and `git.dirty` then honestly reads true;
 *   - if git cannot answer at all, a FULL_SUITE verdict is refused: the
 *     binding is the whole point of the scope, and an unverifiable binding is
 *     not a weaker binding, it is none.
 *
 * FOCUSED runs are exempt: their files are named on argv, by a human or a
 * probe, and routinely live outside the repository.
 */
function discoveryBinding(files) {
  const relative = files.filter((file) => !path.isAbsolute(file));
  if (relative.length === 0) {
    // A BINDING OVER THE EMPTY SET IS UNDEFINED, NOT SATISFIED (R1.6, red team
    // RT4-5 against e71b51e). This returned `verified: true`, so zero
    // discovered files affirmed "the executed set is bound to the commit" —
    // every property holds of the empty set. `vacuous` is recorded as its own
    // answer and refused, never folded into `verified`.
    return {
      verified: false,
      vacuous: true,
      ignored: [],
      untracked: [],
      missing: [],
      reason:
        "DISCOVERY_VACUOUS: no test files were discovered, so there is no executed set to bind to the commit — an empty binding is undefined, not satisfied",
    };
  }
  let ignored = [];
  let untracked = [];
  let tracked = new Set();
  try {
    // `check-ignore --stdin` exits 1 when nothing matches, which is the
    // ordinary, healthy case — so the exit code is not the answer, stdout is.
    const answer = execFileSync("git", ["check-ignore", "--stdin"], {
      cwd: ROOT,
      encoding: "utf8",
      input: `${relative.join("\n")}\n`,
    });
    ignored = answer.split("\n").filter((line) => line.trim() !== "");
  } catch (error) {
    if (error?.status === 1 && typeof error.stdout === "string") {
      ignored = error.stdout.split("\n").filter((line) => line.trim() !== "");
    } else {
      return {
        verified: false,
        ignored: [],
        untracked: [],
        missing: [],
        reason: `DISCOVERY_UNVERIFIABLE: git could not be asked which discovered files the commit contains: ${String(error?.message ?? error).slice(0, 200)}`,
      };
    }
  }
  try {
    tracked = new Set(
      execFileSync("git", ["ls-files", "-z", "--", "tests"], {
        cwd: ROOT,
        encoding: "utf8",
      })
        .split("\0")
        .filter((line) => line !== ""),
    );
    untracked = relative.filter((file) => !tracked.has(file));
  } catch (error) {
    return {
      verified: false,
      ignored,
      untracked: [],
      missing: [],
      reason: `DISCOVERY_UNVERIFIABLE: git could not list the commit's test files: ${String(error?.message ?? error).slice(0, 200)}`,
    };
  }
  // ---- AND THE OTHER DIRECTION -----------------------------------------
  // Red team B5: this only asked whether everything DISCOVERED is in the
  // commit. A tracked test file the walk MISSES is the same defect pointing
  // the other way — a test in the commit that silently did not run — and the
  // walk goes only two levels deep, so `tests/a/b/c.test.ts` is invisible to
  // it. No such file exists at this SHA (83 tracked, 83 discovered, measured),
  // which is exactly why it needs checking rather than assuming.
  const discovered = new Set(relative);
  const missing = [...tracked]
    .filter((file) => file.endsWith(".test.ts") && !discovered.has(file))
    .sort();
  const reasons = [];
  if (ignored.length > 0) {
    reasons.push(
      `DISCOVERY_NOT_BOUND_TO_COMMIT: ${ignored.length} discovered test file(s) are git-ignored, so they executed without ever appearing in git status: ${ignored.join(", ")}`,
    );
  }
  if (missing.length > 0) {
    reasons.push(
      `DISCOVERY_MISSED_TRACKED_TESTS: ${missing.length} test file(s) are in the commit and were NOT discovered, so they did not run: ${missing.join(", ")}`,
    );
  }
  return {
    verified: true,
    vacuous: false,
    ignored,
    untracked,
    missing,
    reason: reasons.length > 0 ? reasons.join(" | ") : null,
  };
}

/**
 * THE DENOMINATOR IS PINNED TO THE COMMIT (R1.3).
 *
 * Candidate-4's review saw 1086, 1087, 1088, 1091 and 1093 tests at ONE SHA,
 * and nothing in the repository said which was right: a moving count could be
 * noticed, never refused. `scripts/test-manifest.tsv` is the commit's executed
 * set, one line per test — file, nesting, name — and a FULL_SUITE run whose
 * executed set differs from it in EITHER direction is FAIL, naming each
 * test added or lost.
 *
 * The executed set is every `test:pass` / `test:fail` that is not a FILE-level
 * entry. File-level entries are counted separately: node:test synthesizes one,
 * and counts it in `tests`, whenever a worker exits non-zero after its tests
 * passed (gate 1 F2, the repository's own hookSentinel does exactly that) or
 * dies at file level (gate 5 I-10). So the summary's `tests` must ALSO equal
 * the manifest's length — a synthetic entry is then a named delta, not a
 * silent +1.
 *
 * Lines beginning with `#` are comments. Duplicate lines are meaningful: two
 * tests may share a name, and the comparison is of multisets.
 */
const MANIFEST = path.join(ROOT, "scripts", "test-manifest.tsv");

function manifestKey(file, nesting, name) {
  return `${file}\t${nesting}\t${String(name).replace(/[\t\n\r]/g, " ")}`;
}

function readManifest() {
  if (!fs.existsSync(MANIFEST)) return null;
  return fs
    .readFileSync(MANIFEST, "utf8")
    .split("\n")
    .filter((line) => line !== "" && !line.startsWith("#"));
}

/** Multiset difference, both ways: what ran and is not pinned, what is pinned and did not run. */
function multisetDelta(executed, expected) {
  const remaining = new Map();
  for (const key of expected) remaining.set(key, (remaining.get(key) ?? 0) + 1);
  const added = [];
  for (const key of executed) {
    const left = remaining.get(key) ?? 0;
    if (left > 0) remaining.set(key, left - 1);
    else added.push(key);
  }
  const lost = [];
  for (const [key, left] of remaining) for (let i = 0; i < left; i += 1) lost.push(key);
  return { added: added.sort(), lost: lost.sort() };
}

/**
 * `--verify-discovery` answers from the manifest too: it must exist, be
 * non-empty, and name exactly the discovered FILE set. It still runs nothing,
 * so it cannot vouch for the test NAMES — only a run can, and a FULL_SUITE run
 * does.
 */
function manifestFileBinding(files) {
  const lines = readManifest();
  if (lines === null) {
    return `MANIFEST_MISSING: ${path.relative(ROOT, MANIFEST)} does not exist, so nothing pins what the full suite executes`;
  }
  if (lines.length === 0) {
    return `MANIFEST_EMPTY: ${path.relative(ROOT, MANIFEST)} pins no tests — a denominator of zero is not a pin`;
  }
  const pinned = new Set(lines.map((line) => line.split("\t")[0]));
  const discovered = new Set(files);
  const unpinned = [...discovered].filter((file) => !pinned.has(file)).sort();
  const vanished = [...pinned].filter((file) => !discovered.has(file)).sort();
  const reasons = [];
  if (unpinned.length > 0) {
    reasons.push(`MANIFEST_FILE_DELTA: ${unpinned.length} discovered test file(s) have no pinned tests: ${unpinned.join(", ")}`);
  }
  if (vanished.length > 0) {
    reasons.push(`MANIFEST_FILE_DELTA: ${vanished.length} pinned test file(s) were not discovered: ${vanished.join(", ")}`);
  }
  return reasons.length > 0 ? reasons.join(" | ") : null;
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
  // FULL_SUITE with nothing discovered is not a usage error: it is refused
  // below as DISCOVERY_VACUOUS, so guard 8 FAILS on it rather than erroring.
  if (scope === "FOCUSED" && files.length === 0) usage("no test files");
  if (options.writeManifest && scope !== "FULL_SUITE") usage("--write-manifest records the FULL suite only");
  if (options.writeManifest && options.verifyDiscoveryOnly) usage("--write-manifest needs a run; --verify-discovery runs nothing");
  for (const file of files) {
    if (!fs.existsSync(path.resolve(ROOT, file))) usage(`no such test file: ${file}`);
  }
  const absoluteFiles = new Set(files.map((file) => path.resolve(ROOT, file)));
  // FULL_SUITE only: a verdict over "the suite" must name the suite the commit
  // contains. FOCUSED files are named on argv and routinely sit outside the
  // repository, so there is nothing to bind them to.
  const discovery =
    scope === "FULL_SUITE"
      ? discoveryBinding(files)
      : // NOT `verified: true`. Red team against 86d33c9, MEDIUM (B5): a
        // FOCUSED run on a git-ignored file recorded
        // `{ boundToCommit: true, ignored: [] }` — a positive assertion about
        // a binding that was never checked, in the evidence file a reviewer
        // reads. A FOCUSED run's files are named on argv and routinely live
        // outside the repository, so there is nothing to bind them to; the
        // honest record is that nobody looked.
        { verified: null, vacuous: null, ignored: [], untracked: [], reason: null };

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
    discovery: {
      scope,
      // `null` for FOCUSED: not checked, and not claimed either way.
      //
      // BOTH directions, or this field contradicts the verdict beside it. It
      // read `verified && ignored.length === 0`, so a run refused for
      // DISCOVERY_MISSED_TRACKED_TESTS recorded `boundToCommit: true` — the
      // executed set declared bound to the commit in the very evidence file
      // saying a committed test never ran. Found by the M-51 test below, which
      // was written for the refusal and caught the claim.
      boundToCommit:
        discovery.verified === null
          ? null
          : discovery.verified &&
            discovery.ignored.length === 0 &&
            (discovery.missing ?? []).length === 0,
      vacuous: discovery.vacuous,
      ignored: discovery.ignored,
      untracked: discovery.untracked,
      missing: discovery.missing ?? [],
    },
    // FULL_SUITE only (R1.3). `null` for FOCUSED: nothing is pinned for an
    // arbitrary file list, and nothing is claimed.
    manifest:
      scope === "FULL_SUITE"
        ? {
            path: path.relative(ROOT, MANIFEST),
            mode: options.writeManifest ? "write" : "enforce",
            expected: null,
            executed: null,
            syntheticFileEntries: [],
            added: [],
            lost: [],
          }
        : null,
    discoveryOnly: options.verifyDiscoveryOnly,
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
        (evidence.discoveryOnly ? " tests=NOT_RUN(discovery-only)" : "") +
        (counts
          ? ` tests=${counts.tests} pass=${counts.passed} fail=${counts.failed} cancelled=${counts.cancelled} skipped=${counts.skipped} todo=${counts.todo}`
          : "") +
        `\n` +
        evidence.reasons.map((reason) => `  reason: ${reason}\n`).join("") +
        `  evidence: ${path.relative(ROOT, evidencePath)}\n`,
    );
    process.exit(verdict === "PASS" ? 0 : verdict === "BLOCKED_BY_ENVIRONMENT" ? 3 : 1);
  };

  // REFUSED BEFORE ANYTHING RUNS. A verdict whose executed set is not the
  // commit's set is not a weaker verdict, it is not a verdict — so this is
  // decided before a single test file is spawned, not weighed afterwards.
  if (discovery.reason !== null) {
    evidence.reasons.push(discovery.reason);
    finish("FAIL");
    return;
  }
  // The pinned FILE set is checked before anything runs, like discovery: a
  // suite whose files the manifest does not name cannot match it by running.
  if (scope === "FULL_SUITE" && !options.writeManifest) {
    const manifestRefusal = manifestFileBinding(files);
    if (manifestRefusal !== null) {
      evidence.reasons.push(manifestRefusal);
      finish("FAIL");
      return;
    }
  }
  if (options.verifyDiscoveryOnly) {
    finish("PASS");
    return;
  }

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

  // ---- THE EXECUTED SET AGAINST THE PINNED ONE (R1.3) -------------------
  if (evidence.manifest !== null) {
    const executed = [];
    const synthetic = [];
    for (const event of events) {
      if (event.type !== "test:pass" && event.type !== "test:fail") continue;
      const isFileLevel = event.nesting === 0 && absoluteFiles.has(path.resolve(ROOT, event.name ?? ""));
      if (isFileLevel) {
        synthetic.push(path.relative(ROOT, path.resolve(ROOT, event.name)));
        continue;
      }
      const file = event.file ? path.relative(ROOT, path.resolve(ROOT, event.file)) : "?";
      executed.push(manifestKey(file, event.nesting, event.name));
    }
    evidence.manifest.executed = executed.length;
    evidence.manifest.syntheticFileEntries = synthetic.sort();
    if (synthetic.length > 0) {
      reasons.push(
        `SYNTHETIC_FILE_ENTRIES: ${synthetic.length} file-level entr${synthetic.length === 1 ? "y was" : "ies were"} counted as tests — a worker exited non-zero or died at file level: ${synthetic.join(", ")}`,
      );
    }
    if (options.writeManifest) {
      if (reasons.length > 0) {
        reasons.push("MANIFEST_NOT_WRITTEN: only an otherwise-clean run may define the denominator");
      } else {
        const header = [
          "# THE COMMIT'S EXECUTED TEST SET — scripts/test-watchdog.mjs fails a FULL_SUITE run on any delta.",
          "# One line per test: file<TAB>nesting<TAB>name. Duplicates are meaningful (multiset).",
          "# Regenerate ONLY by `node scripts/test-watchdog.mjs --write-manifest` from a clean run,",
          "# and review the diff: every added or removed line is a test the commit gained or lost.",
        ];
        fs.writeFileSync(MANIFEST, `${[...header, ...executed.sort()].join("\n")}\n`);
        evidence.manifest.expected = executed.length;
        reasons.push(
          `MANIFEST_WRITTEN: ${executed.length} tests recorded to ${path.relative(ROOT, MANIFEST)}; a run that defines its own denominator is not a verdict`,
        );
      }
    } else {
      const expected = readManifest() ?? [];
      evidence.manifest.expected = expected.length;
      const { added, lost } = multisetDelta(executed, expected);
      evidence.manifest.added = added;
      evidence.manifest.lost = lost;
      if (added.length > 0 || lost.length > 0) {
        const show = (list) => list.slice(0, 20).map((key) => key.replace(/\t/g, " :: ")).join(" | ") + (list.length > 20 ? ` | … ${list.length - 20} more (evidence manifest.*)` : "");
        reasons.push(
          `MANIFEST_DELTA: executed ${executed.length}, pinned ${expected.length}; ${added.length} not pinned, ${lost.length} pinned and not executed` +
            (added.length > 0 ? ` — NOT PINNED: ${show(added)}` : "") +
            (lost.length > 0 ? ` — NOT EXECUTED: ${show(lost)}` : ""),
        );
      }
      if (summary && summary.counts.tests !== expected.length) {
        reasons.push(`DENOMINATOR_NOT_PINNED: the runner counted tests=${summary.counts.tests}, the manifest pins ${expected.length}`);
      }
    }
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
