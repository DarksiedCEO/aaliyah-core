const { test } = require("node:test");
test("passes, and leaves a handle that keeps the worker alive", () => {
  setInterval(() => {}, 1000);
});
