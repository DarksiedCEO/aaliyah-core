/**
 * Records which assertion CALL SITES actually execute.
 *
 * Preloaded with `--require`. Wraps every method on `node:assert/strict` so
 * each call records its own `file:line` from the stack. Works at the language
 * level, so it needs no mapping between TypeScript source offsets and the
 * JavaScript ts-node actually runs — which is exactly what defeated the first
 * attempt at this sweep: V8 coverage ranges are in COMPILED space, and mapping
 * them onto .ts offsets produced a confident, wrong "everything is reachable".
 *
 * Output: one JSON file per process into ASSERT_TRACE_DIR, each a list of
 * "<abs path>:<line>" strings for sites that ran at least once.
 */
const fs = require("node:fs");
const path = require("node:path");
const assertStrict = require("node:assert/strict");
const assertLoose = require("node:assert");

const OUT = process.env.ASSERT_TRACE_DIR;
if (!OUT) throw new Error("assert-tracer: ASSERT_TRACE_DIR is required");
fs.mkdirSync(OUT, { recursive: true });

const executed = new Set();

/**
 * The first stack frame that is NOT this file and not node internals.
 *
 * Deliberately parses the STRING stack rather than installing a
 * `prepareStackTrace` hook. ts-node's source-map support works by overriding
 * that same hook, so overriding it here silently returns COMPILED line numbers
 * and every TypeScript assertion looks unexecuted. That produced a confident
 * 67-of-75 "never executed" on a file whose tests all pass — the second time
 * this sweep was defeated by compiled-versus-source coordinates.
 */
function callSite() {
  const lines = String(new Error().stack || "").split("\n").slice(1);
  for (const line of lines) {
    const match = line.match(/\(?((?:\/|[A-Za-z]:\\)[^()]+?):(\d+):(\d+)\)?\s*$/);
    if (!match) continue;
    const file = match[1];
    if (file === __filename) continue;
    if (file.includes("/node_modules/")) continue;
    if (file.startsWith("node:")) continue;
    return `${file}:${match[2]}`;
  }
  return null;
}

function wrap(target) {
  for (const key of Object.keys(target)) {
    const value = target[key];
    if (typeof value !== "function") continue;
    const wrapped = function (...args) {
      const site = callSite();
      if (site) executed.add(site);
      return value.apply(this, args);
    };
    Object.defineProperty(wrapped, "name", { value: key });
    try {
      target[key] = wrapped;
    } catch {
      /* non-writable: skip rather than fail the run */
    }
  }
}

wrap(assertStrict);
wrap(assertLoose);

const file = path.join(OUT, `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
const flush = () => {
  try {
    fs.writeFileSync(file, JSON.stringify([...executed]));
  } catch {
    /* nothing useful to do during exit */
  }
};
process.on("exit", flush);
process.on("SIGTERM", flush);
process.on("SIGINT", flush);
