#!/usr/bin/env node
/**
 * ASSERTION-REACHABILITY SWEEP.
 *
 * Reports every `assert.*` in the given test files whose LINE NEVER EXECUTES.
 * An assertion that cannot run cannot fail, and is therefore not a control —
 * however much its surrounding comment claims otherwise.
 *
 *   node scripts/assertion-reachability.mjs tests/a.test.ts tests/b.test.ts
 *
 * Exit 0 if none found, 1 if any are, 2 on a usage or harness error.
 *
 * ---- WHAT THIS FINDS, AND WHAT IT DOES NOT --------------------------------
 *
 * FINDS: an assertion stranded behind an earlier one that always fails first,
 * behind a branch nothing takes, or after a `return`/`throw`. Three of these
 * were found by hand in ONE test (K-07) on three consecutive candidates —
 * specific assertions stranded behind an equality, their ordering hiding which
 * protection broke, and a locality assertion every path reached only through
 * ROLLBACK.
 *
 * DOES NOT FIND: an assertion that executes, passes, and would pass equally in
 * a broken world. Only mutating the production code it guards finds that; that
 * is the destroyer step's job, not this tool's. Do not read a clean sweep as
 * "the assertions are meaningful" — it means only "they run".
 *
 * ---- WHY IT WORKS THE WAY IT DOES -----------------------------------------
 *
 * Two earlier implementations reported confident nonsense, both for the same
 * reason — TypeScript source coordinates versus the JavaScript that actually
 * runs:
 *
 *   V8 coverage (NODE_V8_COVERAGE): ranges are byte offsets into the COMPILED
 *   output. Mapped onto .ts offsets it reported CLEAN on a file containing a
 *   deliberately unreachable assertion.
 *
 *   A stack hook (Error.prepareStackTrace): ts-node's source-map support works
 *   by overriding that very hook, so installing one returns COMPILED line
 *   numbers. It reported 67 of 75 assertions unexecuted in a file whose tests
 *   all pass.
 *
 * So the tracer reads the STRING stack, which source-map support has already
 * translated, and matches on file:line in source coordinates.
 *
 * The negative control in tests/assertionReachability.test.ts is not optional
 * decoration: a sweep that cannot demonstrate it detects a known-unreachable
 * assertion is indistinguishable from one that is simply blind.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const files = process.argv.slice(2);
if (files.length === 0) {
  process.stderr.write("usage: assertion-reachability.mjs <test file> [...]\n");
  process.exit(2);
}

const ASSERT =
  /\bassert\.(equal|deepEqual|notEqual|strictEqual|deepStrictEqual|match|doesNotMatch|ok|rejects|throws|fail|notDeepEqual)\b/;

const traceDir = mkdtempSync(path.join(tmpdir(), "assert-trace-"));
mkdirSync(traceDir, { recursive: true });

const run = spawnSync(
  process.execPath,
  [
    "--require",
    "ts-node/register",
    "--require",
    path.join(ROOT, "scripts/assert-tracer.cjs"),
    "--test",
    ...files,
  ],
  {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 3_600_000,
    // ---- THE INHERITED ENVIRONMENT IS PART OF THE HARNESS -------------
    //
    // `node --test` exports NODE_TEST_CONTEXT=child-v8 to everything it
    // spawns. A nested `node --test` that sees it switches into child-reporter
    // mode and never runs the `--require` preloads, so the tracer silently
    // does not load and every assertion looks unexecuted. That is how this
    // tool's own negative control first failed: correct standalone, blind when
    // run from inside the suite.
    //
    // Stripped for the same reason scripts/test-watchdog.mjs strips
    // NODE_OPTIONS and TS_NODE_*: an inherited variable must never be able to
    // change what a measurement means.
    env: (() => {
      const clean = { ...process.env, ASSERT_TRACE_DIR: traceDir };
      delete clean.NODE_TEST_CONTEXT;
      delete clean.NODE_OPTIONS;
      for (const key of Object.keys(clean)) {
        if (key.startsWith("TS_NODE_")) delete clean[key];
      }
      return clean;
    })(),
  },
);

if (run.error) {
  process.stderr.write(`assertion-reachability: run failed: ${run.error}\n`);
  process.exit(2);
}

// A FAILING run is not a usable measurement: a test that threw early leaves
// its later assertions unexecuted for a reason that has nothing to do with
// reachability. Refuse rather than report a contaminated result.
const failed = /^ℹ fail (\d+)$/m.exec(run.stdout ?? "");
if (failed && failed[1] !== "0") {
  process.stderr.write(
    `assertion-reachability: REFUSING to report — ${failed[1]} test(s) failed, ` +
      `so unexecuted assertions cannot be distinguished from skipped ones.\n`,
  );
  process.exit(2);
}

const executed = new Set();
for (const name of readdirSync(traceDir)) {
  if (!name.endsWith(".json")) continue;
  try {
    for (const site of JSON.parse(readFileSync(path.join(traceDir, name), "utf8"))) {
      executed.add(site);
    }
  } catch {
    /* a crashed worker may leave a partial file; the union is what matters */
  }
}
rmSync(traceDir, { recursive: true, force: true });

if (executed.size === 0) {
  process.stderr.write("assertion-reachability: no call sites recorded — the tracer did not load\n");
  process.exit(2);
}

let examined = 0;
let dead = 0;
process.stdout.write(`trace sites recorded: ${executed.size}\n\n`);
for (const rel of files) {
  const abs = path.resolve(ROOT, rel);
  const lines = readFileSync(abs, "utf8").split("\n");
  const found = [];
  let inBlock = false;
  lines.forEach((line, index) => {
    const text = line.trimStart();
    if (text.startsWith("/*")) {
      inBlock = !text.trimEnd().endsWith("*/");
      return;
    }
    if (inBlock) {
      if (text.trimEnd().endsWith("*/")) inBlock = false;
      return;
    }
    // Comment lines that merely MENTION an assertion are not assertions.
    if (text.startsWith("//") || text.startsWith("*")) return;
    if (!ASSERT.test(line)) return;
    examined += 1;
    if (!executed.has(`${abs}:${index + 1}`)) found.push([index + 1, text.slice(0, 100)]);
  });
  dead += found.length;
  const label = path.basename(rel).padEnd(56);
  process.stdout.write(
    `${label}${String(found.length === 0 ? "CLEAN" : `${found.length} NEVER EXECUTED`)}\n`,
  );
  for (const [line, text] of found) process.stdout.write(`    :${line}  ${text}\n`);
}

process.stdout.write(`\nassertions examined : ${examined}\nnever executed      : ${dead}\n`);
process.exit(dead === 0 ? 0 : 1);
