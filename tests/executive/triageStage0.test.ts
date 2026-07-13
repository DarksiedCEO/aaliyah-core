import assert from "node:assert/strict";
import test from "node:test";
import { stage0SystemFilter } from "../../src/application/executive/triage";

const base = { messageId: "m", threadId: "t", subject: "hi", body: "hello", receivedAt: "2026-07-12T00:00:00.000Z" };
const noSignals = { listUnsubscribe: false, precedenceBulk: false };

test("noreply sender is short-circuited to notification_system", () => {
  const r = stage0SystemFilter({ ...base, fromEmail: "no-reply@accounts.google.com" }, noSignals);
  assert.equal(r?.category, "notification_system");
  assert.equal(r?.risk, "green");
});

test("bulk headers PLUS a digest subject signal short-circuit", () => {
  const r = stage0SystemFilter(
    { ...base, fromEmail: "stories-recap@mail.instagram.com", subject: "See your stories digest" },
    { listUnsubscribe: true, precedenceBulk: false },
  );
  assert.equal(r?.category, "notification_system");
});

test("bulk header alone on human-looking correspondence does NOT short-circuit", () => {
  const r = stage0SystemFilter(
    { ...base, fromEmail: "jane@acmecorp.com", subject: "Following up on our call" },
    { listUnsubscribe: true, precedenceBulk: false },
  );
  assert.equal(r, null); // must go to Haiku
});

test("ordinary human email returns null (goes to Stage 1)", () => {
  const r = stage0SystemFilter({ ...base, fromEmail: "jane@acmecorp.com" }, noSignals);
  assert.equal(r, null);
});
