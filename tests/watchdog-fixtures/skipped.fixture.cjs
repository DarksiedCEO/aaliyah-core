const { test } = require("node:test");
test("a passing test", () => {});
test("a skipped test", { skip: true }, () => {});
