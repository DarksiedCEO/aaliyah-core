import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as path from "node:path";

/**
 * THE SWEEP MUST BE ABLE TO SEE.
 *
 * `scripts/assertion-reachability.mjs` reports assertions whose line never
 * executes. Two earlier implementations of it reported confident nonsense —
 * one declared a file CLEAN while it contained a deliberately unreachable
 * assertion, the other declared 67 of 75 assertions unexecuted in a file whose
 * tests all pass — both because they worked in COMPILED coordinates while
 * matching against TypeScript source lines.
 *
 * A sweep that cannot demonstrate it detects a known-unreachable assertion is
 * indistinguishable from one that is blind, and a blind sweep reporting CLEAN
 * is worse than no sweep: it is a false all-clear from the tool whose entire
 * purpose is catching false all-clears.
 *
 * So the negative control runs in the suite, not by hand, against a fixture
 * carrying exactly one unreachable assertion and one that always runs.
 */
const ROOT = path.resolve(__dirname, "..");
const FIXTURE = "tests/reachability-fixtures/probe.fixture.ts";

function sweep(target: string): { status: number | null; stdout: string; stderr: string } {
  const run = spawnSync(
    process.execPath,
    [path.join(ROOT, "scripts/assertion-reachability.mjs"), target],
    { cwd: ROOT, encoding: "utf8", timeout: 300_000 },
  );
  assert.equal(run.error, undefined, `sweep did not complete: ${run.error}`);
  return { status: run.status, stdout: run.stdout ?? "", stderr: run.stderr ?? "" };
}

test("the reachability sweep REPORTS an assertion that can never run", () => {
  const run = sweep(FIXTURE);

  // Exit 1 means "found something", which is the whole point.
  assert.equal(run.status, 1, `expected a finding; got ${run.status}\n${run.stdout}${run.stderr}`);
  assert.match(run.stdout, /1 NEVER EXECUTED/, run.stdout);
  assert.match(run.stdout, /UNREACHABLE: this line must be reported/, run.stdout);
  assert.match(run.stdout, /never executed      : 1/, run.stdout);
});

test("the reachability sweep does NOT report an assertion that runs", () => {
  // The other half of the control. A tool that reports EVERYTHING is equally
  // useless, and the second failed implementation did exactly that.
  const run = sweep(FIXTURE);

  assert.doesNotMatch(
    run.stdout,
    /REACHABLE: this line must not be reported/,
    `an executed assertion was reported as unreachable:\n${run.stdout}`,
  );
  assert.match(run.stdout, /assertions examined : 2/, run.stdout);
});

test("the reachability sweep REFUSES to report when the run had failures", () => {
  // An unexecuted assertion in a FAILING run may simply be one the thrown
  // error skipped past. Reporting that as "unreachable" would manufacture
  // findings, so the tool must refuse the measurement rather than guess.
  const run = sweep("tests/reachability-fixtures/failing.fixture.ts");

  assert.equal(run.status, 2, `expected a refusal; got ${run.status}\n${run.stdout}${run.stderr}`);
  assert.match(run.stderr, /REFUSING to report/, run.stderr);
});
