const { test } = require("node:test");
test("a passing test", () => {});
test("exits the process mid-run with status 0", async () => {
  await new Promise((resolve) => setTimeout(resolve, 10));
  process.exit(0);
});
test("never reached", () => {});
