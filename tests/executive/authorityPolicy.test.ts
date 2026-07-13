import assert from "node:assert/strict";
import test from "node:test";
import { decideAuthority, CONFIDENCE_FLOOR } from "../../src/application/executive/authorityPolicy";
import type { TriageResult } from "../../src/application/executive/triage";

const t = (over: Partial<TriageResult>): TriageResult =>
  ({ category: "real_lead", risk: "green", reason: "r", confidence: 0.9, ...over });

test("red risk never drafts, even for a real lead", () => {
  const d = decideAuthority(t({ category: "real_lead", risk: "red" }));
  assert.equal(d.action, "escalate");
  assert.equal(d.draftable, false);
});

test("confidence below floor -> review_only even at green", () => {
  const d = decideAuthority(t({ category: "real_lead", risk: "green", confidence: CONFIDENCE_FLOOR - 0.01 }));
  assert.equal(d.action, "review_only");
  assert.equal(d.draftable, false);
});

test("green real_lead drafts", () => {
  const d = decideAuthority(t({ category: "real_lead", risk: "green" }));
  assert.equal(d.action, "draft");
  assert.equal(d.draftable, true);
  assert.equal(d.cautionMarker, false);
});

test("green vendor drafts a decline", () => {
  assert.equal(decideAuthority(t({ category: "vendor_solicitation", risk: "green" })).action, "draft");
});

test("yellow lead drafts WITH caution marker", () => {
  const d = decideAuthority(t({ category: "real_lead", risk: "yellow" }));
  assert.equal(d.action, "draft");
  assert.equal(d.cautionMarker, true);
});

test("notification_system -> no_action", () => {
  assert.equal(decideAuthority(t({ category: "notification_system", risk: "green" })).action, "no_action");
});

test("sensitive_escalation -> escalate, no draft", () => {
  const d = decideAuthority(t({ category: "sensitive_escalation", risk: "red" }));
  assert.equal(d.action, "escalate");
  assert.equal(d.draftable, false);
});

test("unknown -> review_only", () => {
  assert.equal(decideAuthority(t({ category: "unknown", risk: "yellow" })).action, "review_only");
});
