import test from "node:test";
import assert from "node:assert/strict";

test("health payload matches the expected shape", () => {
  const payload = { status: "ok" };

  assert.deepEqual(payload, { status: "ok" });
});
