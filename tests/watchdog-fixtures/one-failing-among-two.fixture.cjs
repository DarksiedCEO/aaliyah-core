const { test } = require("node:test");

// Red team M1 against 2b2e554: with NODE_OPTIONS="--test-skip-pattern=failing"
// inherited, this file ran one test, passed it, and the verdict was PASS.
test("kept", () => {});
test("the failing destroyer", () => {
  throw new Error("real failure");
});
