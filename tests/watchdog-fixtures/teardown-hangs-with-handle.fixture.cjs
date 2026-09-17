const { test, after } = require("node:test");
// A live handle plus a teardown that never settles: the worker cannot exit.
setInterval(() => {}, 1000);
after(() => new Promise(() => {}));
test("a passing test whose worker can never exit", () => {});
