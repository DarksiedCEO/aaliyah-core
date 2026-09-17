const { test, after } = require("node:test");
// No live handle: before the sentinel, this exited 0 with every test passed.
after(() => new Promise(() => {}));
test("a passing test whose teardown never finishes", () => {});
