import assert from "node:assert/strict";
import test from "node:test";
import { extractMailSignals } from "../../local-runner/gmailReader";

test("detects List-Unsubscribe and Precedence: bulk", () => {
  const s = extractMailSignals([{ name: "List-Unsubscribe", value: "<mailto:x>" }, { name: "Precedence", value: "bulk" }]);
  assert.equal(s.listUnsubscribe, true);
  assert.equal(s.precedenceBulk, true);
});

test("absent headers -> false", () => {
  const s = extractMailSignals([{ name: "From", value: "a@b.com" }]);
  assert.equal(s.listUnsubscribe, false);
  assert.equal(s.precedenceBulk, false);
});

test("undefined headers -> false", () => {
  const s = extractMailSignals(undefined);
  assert.equal(s.listUnsubscribe, false);
  assert.equal(s.precedenceBulk, false);
});
