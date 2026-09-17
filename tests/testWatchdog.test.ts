import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/**
 * THE SUITE CANNOT PASS BY HANGING, BY BEING CANCELLED, OR BY NOT RUNNING.
 *
 * Every case below drives scripts/test-watchdog.mjs — the runner `npm test`
 * uses — against a fixture that reproduces one way a run can look green
 * without being green, and asserts the verdict, the recorded reason, and that
 * the verdict is never PASS. The fixtures live in tests/watchdog-fixtures/ and
 * are named `*.fixture.cjs` so the suite's own glob never collects them.
 *
 * Origin: the b3efc82 mutation sweep. 20 mutants produced no verdict because
 * the suite hung under Node's default `--test-timeout=0`; one was root-caused to
 * `pool.end()` waiting forever on a client an assertion never released.
 */

const ROOT = path.resolve(__dirname, "..");
const WATCHDOG = path.join(ROOT, "scripts/test-watchdog.mjs");
const FIXTURES = "tests/watchdog-fixtures";
const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

type Evidence = {
  verdict: "PASS" | "FAIL" | "BLOCKED_BY_ENVIRONMENT";
  reasons: string[];
  counts: { tests: number; passed: number; cancelled: number } | null;
  failures: Array<{ code: string | null; message: string | null }>;
  timedOut: Array<{ name: string; message: string | null }>;
  processGroup: { killedSurvivors: boolean; survivedSigkill: boolean } | null;
  database: { before: { reachable: boolean } | null };
  discovery?: { boundToCommit: boolean; ignored: string[]; untracked: string[] };
};

function runWatchdog(
  fixtures: string[],
  flags: string[],
  env: Record<string, string> = {},
): { status: number | null; evidence: Evidence; elapsedMs: number } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "watchdog-evidence-"));
  const evidencePath = path.join(dir, "evidence.json");
  const started = Date.now();
  const result = spawnSync(
    process.execPath,
    [
      WATCHDOG,
      "--evidence",
      evidencePath,
      ...flags,
      "--",
      ...fixtures.map((f) => path.join(FIXTURES, f)),
    ],
    {
      cwd: ROOT,
      encoding: "utf8",
      // The OUTER bound. If the watchdog itself ever hung, this test fails
      // rather than hanging the suite that is supposed to catch hangs.
      timeout: 120_000,
      killSignal: "SIGKILL",
      env: { ...process.env, AALIYAH_TEST_DATABASE_URL: DB_URL, ...env },
    },
  );
  const elapsedMs = Date.now() - started;
  assert.equal(result.error, undefined, `watchdog did not complete: ${result.error}`);
  const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8")) as Evidence;
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: result.status, evidence, elapsedMs };
}

const FAST = ["--no-db", "--test-timeout-ms", "2000", "--deadline-ms", "20000", "--exit-grace-ms", "2000"];

function assertFail(
  run: ReturnType<typeof runWatchdog>,
  reason: RegExp,
): void {
  assert.equal(run.evidence.verdict, "FAIL", JSON.stringify(run.evidence.reasons));
  assert.equal(run.status, 1);
  assert.ok(
    run.evidence.reasons.some((r) => reason.test(r)),
    `expected a reason matching ${reason}; got ${JSON.stringify(run.evidence.reasons)}`,
  );
}

// The positive control's bounds are deliberately NOT tight. Under the CPU
// contention of concurrent reviewers and a mutation sweep, the FAST profile's
// two-second test timeout and exit grace judged this passing fixture hung
// (2b2e554 security review, one run in two). Only the refusals need FAST; a
// PASS must not depend on how busy the machine is.
const RELAXED = ["--no-db", "--test-timeout-ms", "60000", "--deadline-ms", "110000", "--exit-grace-ms", "15000"];

test("POSITIVE CONTROL: a genuinely passing fixture is PASS, so every refusal below is specific", () => {
  const run = runWatchdog(["pass.fixture.cjs"], RELAXED);
  assert.equal(run.evidence.verdict, "PASS", JSON.stringify(run.evidence.reasons));
  assert.equal(run.status, 0);
  assert.deepEqual(run.evidence.reasons, []);
  assert.equal(run.evidence.counts?.tests, 1);
  assert.equal(run.evidence.counts?.passed, 1);
});

test("a promise that never settles is FAIL, and the timeout is counted, not dropped", () => {
  const run = runWatchdog(["never-resolves.fixture.cjs", "pass.fixture.cjs"], FAST);
  assertFail(run, /^CANCELLED_TESTS: 1 /);
  assert.ok(run.evidence.reasons.some((r) => /^TIMED_OUT: .*a promise that never settles/.test(r)));
  assert.equal(run.evidence.counts?.cancelled, 1);
});

test("a teardown hook that never settles, with no live handle, is FAIL — Node alone reports it as passed", () => {
  const run = runWatchdog(["teardown-never-settles.fixture.cjs"], FAST);
  assertFail(run, /^FAILED_TESTS: 1$/);
});

test("a teardown hook that hangs a live worker is FAIL within the grace period, not at the deadline", () => {
  const run = runWatchdog(["teardown-hangs-with-handle.fixture.cjs"], FAST);
  assertFail(run, /^HUNG_WORKER: /);
  assert.ok(run.evidence.reasons.some((r) => /^ORPHANED_PROCESSES: /.test(r)));
  assert.ok(run.elapsedMs < 15_000, `took ${run.elapsedMs}ms`);
  assert.equal(run.evidence.processGroup?.survivedSigkill, false);
});

test("a leaked handle that keeps a passing worker alive is FAIL at the deadline, and the worker is killed", () => {
  const run = runWatchdog(["leaked-handle.fixture.cjs"], [
    "--no-db", "--test-timeout-ms", "2000", "--deadline-ms", "6000", "--exit-grace-ms", "2000",
  ]);
  assertFail(run, /^DEADLINE_EXCEEDED: /);
  assert.equal(run.evidence.processGroup?.killedSurvivors, true);
  assert.equal(run.evidence.processGroup?.survivedSigkill, false);
});

test("a child process that never exits is FAIL, and the child itself does not outlive the run", () => {
  const pidFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "watchdog-pid-")), "pid");
  const run = runWatchdog(["child-never-exits.fixture.cjs"], FAST, {
    WATCHDOG_FIXTURE_PID_FILE: pidFile,
  });
  assertFail(run, /^TIMED_OUT: .*child process that never exits/);
  const pid = Number(fs.readFileSync(pidFile, "utf8"));
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" }, "the orphaned child is still alive");
});

test("a worker exceeding the whole-run deadline is FAIL (a hung mutant or reviewer worker)", () => {
  const run = runWatchdog(["slow.fixture.cjs"], [
    "--no-db", "--test-timeout-ms", "120000", "--deadline-ms", "3000",
  ]);
  assertFail(run, /^DEADLINE_EXCEEDED: the run did not finish within 3000ms$/);
  assert.ok(run.elapsedMs < 20_000, `took ${run.elapsedMs}ms`);
});

test("a skipped test is FAIL", () => {
  assertFail(runWatchdog(["skipped.fixture.cjs"], FAST), /^SKIPPED_TESTS: 1$/);
});

test("a todo test is FAIL", () => {
  assertFail(runWatchdog(["todo.fixture.cjs"], FAST), /^TODO_TESTS: 1$/);
});

test("a file that registers no tests is FAIL, not a silent zero", () => {
  assertFail(
    runWatchdog(["no-tests.fixture.cjs", "pass.fixture.cjs"], FAST),
    /^FILES_WITHOUT_TESTS: tests\/watchdog-fixtures\/no-tests\.fixture\.cjs$/,
  );
});

test("a file that exits the process mid-run with status 0 is FAIL — the dropped tests are counted", () => {
  // Measured before this control: exit 0, `tests 1 pass 1`, and two queued
  // tests that never ran appeared nowhere in the summary.
  const run = runWatchdog(["exits-early.fixture.cjs"], FAST);
  assertFail(run, /^TESTS_NEVER_FINISHED: tests\/watchdog-fixtures\/exits-early\.fixture\.cjs queued=3 finished=1$/);
  assert.ok(run.evidence.reasons.some((r) => /^FILES_WITHOUT_SUMMARY: /.test(r)));
});

const DB_FLAGS = ["--test-timeout-ms", "20000", "--deadline-ms", "60000", "--exit-grace-ms", "2000"];

test("a blocked database statement is cancelled by statement_timeout and is FAIL", () => {
  const run = runWatchdog(["db-blocked-statement.fixture.cjs"], [
    ...DB_FLAGS, "--statement-timeout-ms", "1000", "--lock-timeout-ms", "8000",
  ]);
  assertFail(run, /^FAILED_TESTS: 1$/);
  assert.equal(run.evidence.failures[0]?.code, "57014");
});

test("a blocked advisory lock is refused by lock_timeout and is FAIL", () => {
  const run = runWatchdog(["db-blocked-advisory-lock.fixture.cjs"], [
    ...DB_FLAGS, "--statement-timeout-ms", "8000", "--lock-timeout-ms", "1000",
  ]);
  assertFail(run, /^FAILED_TESTS: 1$/);
  assert.equal(run.evidence.failures[0]?.code, "55P03");
});

test("a blocked row lock is refused by lock_timeout and is FAIL", () => {
  const run = runWatchdog(["db-blocked-row-lock.fixture.cjs"], [
    ...DB_FLAGS, "--statement-timeout-ms", "8000", "--lock-timeout-ms", "1000",
  ]);
  assertFail(run, /^FAILED_TESTS: 1$/);
  assert.equal(run.evidence.failures[0]?.code, "55P03");
});

test("a deadlock surfaces as FAIL with the database's deadlock code, not as a hang", () => {
  const run = runWatchdog(["db-deadlock.fixture.cjs"], [
    ...DB_FLAGS, "--statement-timeout-ms", "10000", "--lock-timeout-ms", "10000",
  ]);
  assertFail(run, /^FAILED_TESTS: 1$/);
  assert.equal(run.evidence.failures[0]?.code, "40P01");
});

test("an unreachable database is BLOCKED_BY_ENVIRONMENT, executes nothing, and is never PASS", () => {
  const run = runWatchdog(["pass.fixture.cjs"], ["--db-probe-timeout-ms", "2000"], {
    AALIYAH_TEST_DATABASE_URL: "postgres://postgres:test@127.0.0.1:1/unreachable",
  });
  assert.equal(run.evidence.verdict, "BLOCKED_BY_ENVIRONMENT");
  assert.equal(run.status, 3);
  assert.equal(run.evidence.database.before?.reachable, false);
  assert.equal(run.evidence.counts, null, "nothing may execute against a database that is not there");
});

test("`npm test` IS the watchdog, so a hang cannot be reintroduced by editing the script", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  assert.equal(pkg.scripts.test, "node scripts/test-watchdog.mjs");
});

test("the watchdog's full-suite file set is exactly the old `tests/*.test.ts tests/*/*.test.ts` glob", () => {
  const expected: string[] = [];
  for (const entry of fs.readdirSync(path.join(ROOT, "tests"), { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".test.ts")) expected.push(`tests/${entry.name}`);
    if (entry.isDirectory()) {
      for (const inner of fs.readdirSync(path.join(ROOT, "tests", entry.name))) {
        if (inner.endsWith(".test.ts")) expected.push(`tests/${entry.name}/${inner}`);
      }
    }
  }
  // Nothing deeper than the glob reaches, so no file is silently outside it.
  const deeper = spawnSync("find", ["tests", "-mindepth", "3", "-name", "*.test.ts"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  assert.equal(deeper.stdout.trim(), "");
  assert.ok(expected.includes("tests/testWatchdog.test.ts"));
  assert.ok(!expected.some((f) => f.includes("watchdog-fixtures")));
});

test("no hook in the suite is callback-style, which the hook sentinel deliberately leaves unwrapped", () => {
  const offenders: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".ts")) {
        const source = fs.readFileSync(full, "utf8");
        const pattern = /\b(before|after|beforeEach|afterEach)\(\s*(?:async\s*)?(?:function\s*\w*\s*)?\(\s*\w+\s*,\s*\w+/g;
        for (const match of source.matchAll(pattern)) {
          offenders.push(`${path.relative(ROOT, full)}: ${match[0]}`);
        }
      }
    }
  };
  walk(path.join(ROOT, "tests"));
  assert.deepEqual(offenders, []);
});

test("an inherited NODE_OPTIONS cannot deselect a failing test: it is dropped, recorded, and the run is FAIL", () => {
  const run = runWatchdog(["one-failing-among-two.fixture.cjs"], FAST, {
    NODE_OPTIONS: "--test-skip-pattern=failing",
  });
  assertFail(run, /^FAILED_TESTS: 1$/);
  assert.equal(run.evidence.counts?.tests, 2);
  assert.equal(
    (run.evidence as unknown as { environment: { nodeOptionsIgnored: string | null } }).environment
      .nodeOptionsIgnored,
    "--test-skip-pattern=failing",
  );
});

test("an inherited TS_NODE_PROJECT cannot preload code into the workers: it is dropped, recorded, and the run is FAIL", () => {
  // Red team F1 against 3ba769f.
  const hostile = path.join(ROOT, FIXTURES, "hostile-ts-node/tsconfig.json");
  // POSITIVE CONTROL: the fixture really is hostile — a bare runner that honours
  // the inherited variable reports the failing test as passed.
  const bare = spawnSync(
    process.execPath,
    ["--require", "ts-node/register", "--test", path.join(FIXTURES, "one-failing-among-two.fixture.cjs")],
    {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 60_000,
      killSignal: "SIGKILL",
      env: Object.fromEntries(
        Object.entries({ ...process.env, TS_NODE_PROJECT: hostile }).filter(([key]) => key !== "NODE_TEST_CONTEXT"),
      ),
    },
  );
  assert.match(bare.stdout, /ℹ fail 0/, bare.stdout + bare.stderr);
  const run = runWatchdog(["one-failing-among-two.fixture.cjs"], FAST, { TS_NODE_PROJECT: hostile });
  assertFail(run, /^FAILED_TESTS: 1$/);
  assert.deepEqual(
    (run.evidence as unknown as { environment: { tsNodeIgnored: Record<string, string> } }).environment
      .tsNodeIgnored,
    { TS_NODE_PROJECT: hostile },
  );
});

/**
 * THE EXECUTED SET IS THE COMMIT'S SET.
 *
 * Red team K-19 against 8a0bf05: `.gitignore` excludes `coverage`, and the
 * full-suite glob walks the filesystem, so `tests/coverage/*.test.ts` was
 * discovered and EXECUTED while `git status --porcelain` stayed empty and the
 * evidence recorded `git.dirty: false`. Reproduced at that SHA: 84 files
 * discovered where the commit contains 83. A PASS was a claim about a file set
 * nobody could rebuild from the SHA.
 *
 * Both cases below run the REAL entrypoint at FULL_SUITE scope, not a helper,
 * because the refusal has to happen in the path `npm test` actually takes. The
 * refusal is decided before anything is spawned, so the negative control costs
 * well under a second — and that is asserted, because a mutant that removes the
 * refusal would instead start the whole suite from inside it.
 */
function runFullSuiteDiscovery(flags: string[]): {
  status: number | null;
  evidence: Evidence & {
    discovery: { boundToCommit: boolean; ignored: string[]; untracked: string[] };
  };
  elapsedMs: number;
} {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "watchdog-discovery-"));
  const evidencePath = path.join(dir, "evidence.json");
  const started = Date.now();
  const result = spawnSync(process.execPath, [WATCHDOG, "--evidence", evidencePath, ...flags], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 60_000,
    killSignal: "SIGKILL",
    env: { ...process.env, AALIYAH_TEST_DATABASE_URL: DB_URL },
  });
  const elapsedMs = Date.now() - started;
  assert.equal(result.error, undefined, `watchdog did not complete: ${result.error}`);
  const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: result.status, evidence, elapsedMs };
}

test("POSITIVE CONTROL: on a clean tree the full suite is bound to the commit, so the refusal below is specific", () => {
  const run = runFullSuiteDiscovery(["--verify-discovery"]);
  assert.equal(run.evidence.verdict, "PASS", JSON.stringify(run.evidence.reasons));
  assert.equal(run.status, 0);
  assert.equal(run.evidence.discovery.boundToCommit, true);
  assert.deepEqual(run.evidence.discovery.ignored, []);
});

test("a git-ignored test file in tests/ is FAIL: it would execute while git status stays clean", () => {
  const dir = path.join(ROOT, "tests/coverage");
  const probe = path.join(dir, "discoveryBinding.probe.test.ts");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(probe, 'import { test } from "node:test";\ntest("invisible", () => {});\n');
  try {
    // The file really is invisible to git — that is the whole defect.
    const ignored = spawnSync("git", ["check-ignore", "tests/coverage/discoveryBinding.probe.test.ts"], {
      cwd: ROOT,
      encoding: "utf8",
    });
    assert.equal(ignored.status, 0, "fixture precondition: the probe must be git-ignored");
    const status = spawnSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf8" });
    assert.ok(
      !status.stdout.includes("tests/coverage"),
      `fixture precondition: git status must not mention the probe; got ${status.stdout}`,
    );

    const run = runFullSuiteDiscovery(["--no-db", "--deadline-ms", "20000"]);
    assert.equal(run.evidence.verdict, "FAIL", JSON.stringify(run.evidence.reasons));
    assert.equal(run.status, 1);
    assert.ok(
      run.evidence.reasons.some((r) => /^DISCOVERY_NOT_BOUND_TO_COMMIT:/.test(r)),
      `expected a discovery refusal; got ${JSON.stringify(run.evidence.reasons)}`,
    );
    assert.deepEqual(run.evidence.discovery.ignored, ["tests/coverage/discoveryBinding.probe.test.ts"]);
    assert.equal(run.evidence.discovery.boundToCommit, false);
    // Refused BEFORE the suite was spawned: no counts, no exit, and fast.
    assert.equal(run.evidence.counts, null);
    assert.ok(run.elapsedMs < 10_000, `refusal took ${run.elapsedMs}ms — it did not short-circuit`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
