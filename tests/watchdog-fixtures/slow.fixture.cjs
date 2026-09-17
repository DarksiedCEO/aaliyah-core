const { test } = require("node:test");
test("longer than the watchdog deadline", () => new Promise((resolve) => setTimeout(resolve, 60_000)));
