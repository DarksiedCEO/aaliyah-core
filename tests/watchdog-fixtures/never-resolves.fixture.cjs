const { test } = require("node:test");
test("a passing sibling", () => {});
test("a promise that never settles", () => new Promise(() => {}));
