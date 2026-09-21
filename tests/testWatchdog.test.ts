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
  discovery?: {
    boundToCommit: boolean | null;
    vacuous?: boolean | null;
    ignored: string[];
    untracked: string[];
    missing: string[];
  };
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

test("the watchdog cannot report a PASS it failed to RECORD", () => {
  // ---- PRIORITY TWO: "MONITOR FAILURE REPORTING GREEN" ----------------
  // Every other case here asks whether the watchdog judges the SUITE
  // correctly. This one asks what happens when the watchdog's own recording
  // fails — an unwritable evidence path, which in practice means a full disk,
  // a read-only mount, or an evidence directory somebody chmod'd. A runner
  // that has just watched a passing suite and then cannot write its evidence
  // must NOT exit 0: the caller would read a green exit code with no artifact
  // behind it, which is the same defect as a timeout reported as PASS.
  //
  // The fixture passes, so a green exit is exactly what a naive implementation
  // would produce.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "watchdog-unwritable-"));
  const readOnly = path.join(dir, "ro");
  fs.mkdirSync(readOnly);
  fs.chmodSync(readOnly, 0o500);
  try {
    const result = spawnSync(
      process.execPath,
      [
        WATCHDOG,
        "--evidence",
        path.join(readOnly, "evidence.json"),
        ...RELAXED,
        "--",
        path.join(FIXTURES, "pass.fixture.cjs"),
      ],
      {
        cwd: ROOT,
        encoding: "utf8",
        timeout: 120_000,
        killSignal: "SIGKILL",
        env: { ...process.env, AALIYAH_TEST_DATABASE_URL: DB_URL },
      },
    );
    assert.equal(result.error, undefined, `watchdog did not complete: ${result.error}`);
    // The suite itself really did pass — that is what makes this specific.
    assert.match(`${result.stdout}`, /pass 1/);
    assert.notEqual(result.status, 0, "a PASS that could not be recorded exited 0");
    assert.equal(result.status, 2, `expected the watchdog's own-failure code 2; got ${result.status}`);
    assert.match(
      `${result.stdout}${result.stderr}`,
      /test-watchdog internal error/,
      "the failure to record was not named",
    );
    assert.ok(
      !fs.existsSync(path.join(readOnly, "evidence.json")),
      "fixture precondition: the evidence file must not be writable",
    );
  } finally {
    fs.chmodSync(readOnly, 0o700);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a FOCUSED run records NO binding claim, because it checked none (mutation M-50)", () => {
  // ---- RED TEAM B5, AND THEN THE SWEEP -------------------------------
  // A FOCUSED run on a git-ignored file recorded `{boundToCommit: true,
  // ignored: []}` — a positive assertion about a property nobody had checked,
  // in the one field a reviewer reads to decide whether the executed set was
  // the commit's. The fix records `null` instead. The 54-mutant sweep then put
  // `true` back and NOTHING failed, because no test read this field on a
  // FOCUSED run: the only discovery assertions ran the full suite.
  //
  // `null` is the whole finding. It is not a weaker `true`.
  // An ordinary FOCUSED run — discovery evidence is recorded on every run, so
  // this is the shape a reviewer actually reads. (`--verify-discovery` is not
  // used: it answers the full-suite question and runs nothing.)
  const run = runWatchdog(["pass.fixture.cjs"], RELAXED);
  assert.equal(run.evidence.verdict, "PASS", JSON.stringify(run.evidence.reasons));
  const discovery = run.evidence.discovery;
  assert.ok(discovery !== undefined, "a --verify-discovery run recorded no discovery evidence");
  assert.equal(discovery.boundToCommit, null);
  assert.notEqual(
    discovery.boundToCommit,
    true,
    "a FOCUSED run claimed a commit binding it never verified",
  );
});

test("a test file in the commit that discovery MISSES is FAIL, not a silently smaller suite (mutation M-51)", () => {
  // ---- THE OTHER DIRECTION OF B5, WHICH HAD NO TEST AT ALL ------------
  // `discoveryBinding` originally asked only whether everything DISCOVERED is
  // in the commit. The reverse — a tracked test file the two-level walk never
  // finds — is the same defect with worse consequences: a test that is in the
  // commit, that a reviewer counts, and that did not run. The
  // DISCOVERY_MISSED_TRACKED_TESTS refusal was added for it and the sweep
  // deleted it with every test still green, because no fixture had ever put a
  // tracked file out of the walk's reach.
  //
  // The probe is INTENT-TO-ADD (`git add -N`): that is enough to make
  // `git ls-files` report it — which is what the watchdog asks — while writing
  // no blob, and `git rm --cached` plus the unlink below restore the tree
  // exactly. It sits three levels deep, where `tests/*/*.test.ts` cannot see
  // it.
  const dir = path.join(ROOT, "tests/deep/nested");
  const rel = "tests/deep/nested/discoveryMissed.probe.test.ts";
  const probe = path.join(ROOT, rel);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(probe, 'import { test } from "node:test";\ntest("never runs", () => {});\n');
  const git = (args: string[]) => spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  try {
    assert.equal(git(["add", "-N", rel]).status, 0, "fixture precondition: could not stage the probe");
    // It really is in the commit's file list...
    assert.ok(
      git(["ls-files", "--", "tests"]).stdout.split("\n").includes(rel),
      "fixture precondition: the probe must be tracked",
    );
    // ...and it really is NOT ignored, so DISCOVERY_NOT_BOUND_TO_COMMIT is not
    // what refuses this. Only the missing-tracked check can.
    assert.equal(
      git(["check-ignore", rel]).status,
      1,
      "fixture precondition: the probe must not be git-ignored",
    );

    const run = runFullSuiteDiscovery(["--no-db", "--deadline-ms", "20000"]);
    assert.equal(run.evidence.verdict, "FAIL", JSON.stringify(run.evidence.reasons));
    assert.equal(run.status, 1);
    assert.ok(
      run.evidence.reasons.some((r) => /^DISCOVERY_MISSED_TRACKED_TESTS:/.test(r)),
      `expected a missed-tracked refusal; got ${JSON.stringify(run.evidence.reasons)}`,
    );
    assert.deepEqual(run.evidence.discovery.missing, [rel]);
    assert.deepEqual(run.evidence.discovery.ignored, []);
    assert.equal(run.evidence.discovery.boundToCommit, false);
    // Refused before anything was spawned.
    assert.equal(run.evidence.counts, null);
    assert.ok(run.elapsedMs < 10_000, `refusal took ${run.elapsedMs}ms — it did not short-circuit`);
  } finally {
    git(["rm", "--cached", "--force", "--quiet", rel]);
    fs.rmSync(path.join(ROOT, "tests/deep"), { recursive: true, force: true });
    const left = git(["status", "--porcelain", "--", "tests/deep"]).stdout.trim();
    assert.equal(left, "", `the probe was not fully removed: ${left}`);
  }
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

/**
 * R1.3 / R1.6 — THE DENOMINATOR IS PINNED, AND AN EMPTY BINDING IS REFUSED.
 *
 * These drive the REAL watchdog at FULL_SUITE scope, which walks `tests/`
 * beside the script and binds it to git. Doing that in this repository would
 * mean rewriting its own manifest or emptying its own tests directory mid-run,
 * so each case builds a throwaway git repository holding a copy of the
 * watchdog, its reporter and the hook sentinel — the same files, byte for
 * byte — plus exactly the tests and manifest the case needs.
 */
const MANIFEST_HEADER = "# test manifest fixture\n";

function manifestLine(file: string, name: string, nesting = 0): string {
  return `${file}\t${nesting}\t${name}`;
}

function miniRepo(
  tests: Record<string, string>,
  manifest: string[] | null,
  untracked: Record<string, string> = {},
): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "watchdog-minirepo-"));
  fs.mkdirSync(path.join(dir, "scripts"));
  fs.mkdirSync(path.join(dir, "tests/support"), { recursive: true });
  for (const rel of ["scripts/test-watchdog.mjs", "scripts/test-watchdog-reporter.mjs", "tests/support/hookSentinel.cjs", "tsconfig.json"]) {
    fs.copyFileSync(path.join(ROOT, rel), path.join(dir, rel));
  }
  fs.symlinkSync(path.join(ROOT, "node_modules"), path.join(dir, "node_modules"));
  fs.writeFileSync(path.join(dir, ".gitignore"), "node_modules\n.test-evidence-run-*/\n");
  for (const [rel, body] of Object.entries(tests)) fs.writeFileSync(path.join(dir, rel), body);
  if (manifest !== null) {
    fs.writeFileSync(path.join(dir, "scripts/test-manifest.tsv"), MANIFEST_HEADER + manifest.map((l) => `${l}\n`).join(""));
  }
  const git = (args: string[]) => {
    const r = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 0, `fixture precondition: git ${args.join(" ")}: ${r.stderr}`);
  };
  git(["init", "-q"]);
  git(["add", "-A"]);
  git(["-c", "user.name=fixture", "-c", "user.email=fixture@invalid", "commit", "-q", "-m", "fixture"]);
  for (const [rel, body] of Object.entries(untracked)) fs.writeFileSync(path.join(dir, rel), body);
  return dir;
}

function runMiniRepo(dir: string, flags: string[]): { status: number | null; evidence: Evidence & Record<string, any>; elapsedMs: number; stdout: string } {
  const evidencePath = path.join(dir, "evidence.json");
  const started = Date.now();
  const result = spawnSync(process.execPath, [path.join(dir, "scripts/test-watchdog.mjs"), "--evidence", evidencePath, ...flags], {
    cwd: dir,
    encoding: "utf8",
    timeout: 120_000,
    killSignal: "SIGKILL",
    env: { ...process.env, AALIYAH_TEST_DATABASE_URL: DB_URL },
  });
  const elapsedMs = Date.now() - started;
  assert.equal(result.error, undefined, `watchdog did not complete: ${result.error}`);
  const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
  return { status: result.status, evidence, elapsedMs, stdout: `${result.stdout}${result.stderr}` };
}

const TWO_TESTS = 'import { test } from "node:test";\ntest("alpha", () => {});\ntest("beta", () => {});\n';
const PINNED_TWO = [manifestLine("tests/two.test.ts", "alpha"), manifestLine("tests/two.test.ts", "beta")];
const MINI_FLAGS = ["--no-db", "--test-timeout-ms", "60000", "--deadline-ms", "110000", "--exit-grace-ms", "15000"];

test("R1.3 POSITIVE CONTROL: an executed set EQUAL to the manifest is PASS, so the refusals below are specific", () => {
  const dir = miniRepo({ "tests/two.test.ts": TWO_TESTS }, PINNED_TWO);
  try {
    const run = runMiniRepo(dir, MINI_FLAGS);
    assert.equal(run.evidence.verdict, "PASS", JSON.stringify(run.evidence.reasons));
    assert.equal(run.status, 0);
    assert.equal(run.evidence.manifest.executed, 2);
    assert.equal(run.evidence.manifest.expected, 2);
    assert.deepEqual([run.evidence.manifest.added, run.evidence.manifest.lost], [[], []]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.3: a test the manifest does NOT pin is FAIL, named — the denominator cannot grow silently", () => {
  const dir = miniRepo({ "tests/two.test.ts": TWO_TESTS }, [PINNED_TWO[0]!]);
  try {
    const run = runMiniRepo(dir, MINI_FLAGS);
    assertFail(run, /^MANIFEST_DELTA: executed 2, pinned 1; 1 not pinned, 0 pinned and not executed — NOT PINNED: tests\/two\.test\.ts :: 0 :: beta$/);
    assert.ok(run.evidence.reasons.some((r: string) => /^DENOMINATOR_NOT_PINNED: the runner counted tests=2, the manifest pins 1$/.test(r)));
    assert.deepEqual(run.evidence.manifest.added, [PINNED_TWO[1]]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.3: a pinned test that did NOT execute is FAIL, named — the denominator cannot shrink silently", () => {
  const dir = miniRepo(
    { "tests/two.test.ts": TWO_TESTS },
    [...PINNED_TWO, manifestLine("tests/two.test.ts", "gamma, which was deleted")],
  );
  try {
    const run = runMiniRepo(dir, MINI_FLAGS);
    assertFail(run, /NOT EXECUTED: tests\/two\.test\.ts :: 0 :: gamma, which was deleted$/);
    assert.deepEqual(run.evidence.manifest.lost, [manifestLine("tests/two.test.ts", "gamma, which was deleted")]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.3 / F2: a worker that exits non-zero after its tests passed adds a SYNTHETIC entry, and it is named, not counted", () => {
  // Gate 1's F2 mechanism, reproduced under the pinned denominator: the
  // hook sentinel's own `process.exitCode = 70` shape. Every REAL test is
  // pinned and passes, so the only thing that can refuse this run is the
  // synthetic file-level entry node:test adds to `tests`.
  const exits = 'import { test } from "node:test";\ntest("passes", () => {});\nprocess.on("exit", () => { process.exitCode = 70; });\n';
  const dir = miniRepo(
    { "tests/two.test.ts": TWO_TESTS, "tests/exits.test.ts": exits },
    [...PINNED_TWO, manifestLine("tests/exits.test.ts", "passes")],
  );
  try {
    const run = runMiniRepo(dir, MINI_FLAGS);
    assertFail(run, /^SYNTHETIC_FILE_ENTRIES: 1 file-level entry was counted as tests — .*: tests\/exits\.test\.ts$/);
    assert.ok(run.evidence.reasons.some((r: string) => /^DENOMINATOR_NOT_PINNED: the runner counted tests=4, the manifest pins 3$/.test(r)));
    // The executed set itself matched: the +1 is the synthetic entry alone.
    assert.deepEqual([run.evidence.manifest.added, run.evidence.manifest.lost], [[], []]);
    assert.deepEqual(run.evidence.manifest.syntheticFileEntries, ["tests/exits.test.ts"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.3: with NO committed manifest a full-suite run is refused before anything runs", () => {
  const dir = miniRepo({ "tests/two.test.ts": TWO_TESTS }, null);
  try {
    const run = runMiniRepo(dir, MINI_FLAGS);
    assertFail(run, /^MANIFEST_MISSING: scripts\/test-manifest\.tsv does not exist/);
    assert.equal(run.evidence.counts, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.3 / RT4-5: an UNTRACKED extra test file is refused before it runs — it is in no manifest", () => {
  // The red team's exact attack against e71b51e: a not-ignored, untracked
  // test file ran, the suite reported PASS at 1090 against a commit of 1088,
  // `boundToCommit: true`, and guard 8 was green. Now it cannot run at all.
  const dir = miniRepo({ "tests/two.test.ts": TWO_TESTS }, PINNED_TWO, {
    "tests/zzRedTeamExtra.test.ts": 'import { test } from "node:test";\ntest("extra", () => {});\n',
  });
  try {
    const run = runMiniRepo(dir, MINI_FLAGS);
    assertFail(run, /^MANIFEST_FILE_DELTA: 1 discovered test file\(s\) have no pinned tests: tests\/zzRedTeamExtra\.test\.ts$/);
    assert.equal(run.evidence.counts, null);
    const discovery = runMiniRepo(dir, ["--verify-discovery"]);
    assertFail(discovery, /^MANIFEST_FILE_DELTA:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.6: --verify-discovery over an EMPTY discovered set is FAIL, not a vacuous PASS", () => {
  const dir = miniRepo({ "tests/README.md": "no tests here\n" }, PINNED_TWO);
  try {
    const run = runMiniRepo(dir, ["--verify-discovery"]);
    assertFail(run, /^DISCOVERY_VACUOUS: no test files were discovered/);
    assert.equal(run.evidence.discovery!.boundToCommit, false);
    assert.equal(run.evidence.discovery!.vacuous, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.6 POSITIVE CONTROL: --verify-discovery on a bound, pinned set is PASS — and says it ran nothing", () => {
  const dir = miniRepo({ "tests/two.test.ts": TWO_TESTS }, PINNED_TWO);
  try {
    const run = runMiniRepo(dir, ["--verify-discovery"]);
    assert.equal(run.evidence.verdict, "PASS", JSON.stringify(run.evidence.reasons));
    assert.equal(run.evidence.discovery!.vacuous, false);
    assert.equal(run.evidence.discoveryOnly, true);
    assert.equal(run.evidence.counts, null);
    assert.match(run.stdout, /WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=NOT_RUN\(discovery-only\)/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("R1.3: a manifest that pins NOTHING is refused — a denominator of zero is not a pin (mutation M7)", () => {
  // Found by R1's own sweep: the MANIFEST_EMPTY refusal could be deleted and
  // nothing failed. An empty manifest would otherwise be caught only later, as
  // a delta — after the whole suite had been paid for.
  const dir = miniRepo({ "tests/two.test.ts": TWO_TESTS }, []);
  try {
    const run = runMiniRepo(dir, ["--verify-discovery"]);
    assertFail(run, /^MANIFEST_EMPTY: scripts\/test-manifest\.tsv pins no tests/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
