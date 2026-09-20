/**
 * A fixture whose test FAILS, so the sweep must refuse to report rather than
 * mistake assertions the thrown error skipped past for unreachable ones.
 */
import test from "node:test";
import assert from "node:assert/strict";

test("reachability fixture that fails", () => {
  assert.equal(1, 2, "this fixture fails on purpose");
  assert.ok(true, "never reached because the line above throws");
});
