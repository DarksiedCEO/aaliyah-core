/**
 * NEGATIVE CONTROL FIXTURE for scripts/assertion-reachability.mjs.
 *
 * Named `.fixture.ts` so the suite's own `tests/*.test.ts` glob never collects
 * it. Holds one assertion that ALWAYS runs and one that NEVER can. The sweep
 * must report exactly the second.
 *
 * `Number("0") === 1` rather than a literal `false` so no compiler or bundler
 * can elide the branch before the tracer ever sees it.
 */
import test from "node:test";
import assert from "node:assert/strict";

test("reachability fixture", () => {
  if (Number("0") === 1) {
    assert.equal(1, 2, "UNREACHABLE: this line must be reported");
  }
  assert.ok(true, "REACHABLE: this line must not be reported");
});
