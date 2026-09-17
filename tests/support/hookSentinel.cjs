/**
 * A HOOK THAT NEVER FINISHES IS A FAILURE, NOT A PASS.
 *
 * Preloaded into every test process by scripts/test-watchdog.mjs.
 *
 * Measured on Node 24 before this existed: an `after` hook returning a promise
 * that never settles, in a process with nothing else keeping the event loop
 * alive, lets the process exit 0 with every test reported as passed. The
 * teardown simply never ran to completion, and nothing said so. (With a live
 * handle — an unended pool, a socket — the same hook hangs the worker instead;
 * the watchdog's deadline catches that case. This file catches the silent one.)
 *
 * Every `before` / `after` / `beforeEach` / `afterEach` registered through
 * `node:test` is wrapped to count invocations still in flight. If the process
 * reaches `exit` with any in flight, the exit code is forced non-zero and the
 * reason is written to stderr, so the runner reports the file as failed.
 *
 * Callback-style hooks (arity >= 2) are left unwrapped: wrapping would change
 * their arity and with it how node:test invokes them. None exist in this suite;
 * tests/testWatchdog.test.ts pins that.
 */
"use strict";

const nodeTest = require("node:test");
const { syncBuiltinESMExports } = require("node:module");

const HOOKS = ["before", "after", "beforeEach", "afterEach"];
const inFlight = new Map();
let serial = 0;

for (const name of HOOKS) {
  const original = nodeTest[name];
  if (typeof original !== "function") {
    throw new Error(`hookSentinel: node:test.${name} is not a function`);
  }
  nodeTest[name] = function sentinelHook(fn, options) {
    if (typeof fn !== "function" || fn.length >= 2) {
      return original.call(this, fn, options);
    }
    const site = new Error().stack?.split("\n")[2]?.trim() ?? "unknown site";
    const wrapped = async function (...args) {
      const id = (serial += 1);
      inFlight.set(id, `${name} ${site}`);
      try {
        return await fn.apply(this, args);
      } finally {
        inFlight.delete(id);
      }
    };
    return original.call(this, wrapped, options);
  };
}
syncBuiltinESMExports();

process.on("exit", () => {
  if (inFlight.size === 0) return;
  for (const where of inFlight.values()) {
    process.stderr.write(`HOOK_NEVER_COMPLETED ${where}\n`);
  }
  process.exitCode = 70;
});
