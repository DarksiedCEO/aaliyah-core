import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

import {
  issueSendApproval,
  beginSend,
  markSent,
  markFailed,
  reconcileSend,
  approvalsNeedingReconciliation,
  getApproval,
  RECONCILE_AFTER_MS,
} from "../src/mail/security/sendApproval";

beforeEach(() => {
  // Each test issues fresh approvals; ids are unique so no reset needed, but
  // clear to keep the reconciliation query scoped.
});

function issue(over: Record<string, unknown> = {}) {
  return issueSendApproval({
    tenantId: "t", workspaceId: "w", connectionId: "c1",
    to: [{ email: "c@e.com" }], subject: "Re: Hi", body: "Thanks!",
    approvedByUserId: "boss", ...over,
  });
}

function sendInput(approvalId: string, over: Record<string, unknown> = {}) {
  return { connectionId: "c1", approvalId, to: [{ email: "c@e.com" }], subject: "Re: Hi", body: "Thanks!", ...over };
}

test("happy path: issued -> sending -> sent", () => {
  const a = issue();
  assert.equal(a.status, "issued");
  const claimed = beginSend(sendInput(a.approvalId));
  assert.equal(claimed.status, "sending");
  assert.ok(claimed.operationId); // stable op id assigned
  markSent(a.approvalId, "gmail_msg_1");
  assert.equal(getApproval(a.approvalId)!.status, "sent");
});

test("a claimed (sending) approval cannot be claimed again — no double-send", () => {
  const a = issue();
  beginSend(sendInput(a.approvalId));
  assert.throws(() => beginSend(sendInput(a.approvalId)), /in flight — reconcile first/);
});

test("a sent approval cannot be replayed", () => {
  const a = issue();
  beginSend(sendInput(a.approvalId));
  markSent(a.approvalId, "m1");
  assert.throws(() => beginSend(sendInput(a.approvalId)), /already sent/);
});

test("content tamper is refused at claim time", () => {
  const a = issue();
  assert.throws(
    () => beginSend(sendInput(a.approvalId, { body: "Your refund has been issued." })),
    /content mismatch/,
  );
  // Still issued — a refused claim does not consume it.
  assert.equal(getApproval(a.approvalId)!.status, "issued");
});

test("ambiguous timeout stays sending and blocks retry until reconciled", () => {
  const a = issue();
  beginSend(sendInput(a.approvalId));
  // Simulate an ambiguous provider timeout: NOT settled -> stays sending.
  assert.equal(getApproval(a.approvalId)!.status, "sending");
  assert.throws(() => beginSend(sendInput(a.approvalId)), /in flight/);

  // Reconcile: provider confirms NOT delivered -> failed_retryable -> claimable.
  reconcileSend(a.approvalId, false);
  assert.equal(getApproval(a.approvalId)!.status, "failed_retryable");
  const reclaim = beginSend(sendInput(a.approvalId));
  assert.equal(reclaim.status, "sending");
});

test("reconcile can confirm delivery of an ambiguous send", () => {
  const a = issue();
  beginSend(sendInput(a.approvalId));
  reconcileSend(a.approvalId, true, "gmail_msg_2");
  const rec = getApproval(a.approvalId)!;
  assert.equal(rec.status, "sent");
  assert.equal(rec.providerMessageId, "gmail_msg_2");
});

test("unambiguous failure -> failed_retryable is safely re-claimable", () => {
  const a = issue();
  beginSend(sendInput(a.approvalId));
  markFailed(a.approvalId, true);
  assert.equal(getApproval(a.approvalId)!.status, "failed_retryable");
  assert.doesNotThrow(() => beginSend(sendInput(a.approvalId)));
});

test("expired approvals cannot be claimed", () => {
  let clock = 1_000_000;
  const a = issueSendApproval({
    tenantId: "t", workspaceId: "w", connectionId: "c1",
    to: [{ email: "c@e.com" }], subject: "Re: Hi", body: "Thanks!",
    approvedByUserId: "boss", ttlMs: 1000, now: () => clock,
  });
  clock += 2000; // past expiry
  assert.throws(() => beginSend(sendInput(a.approvalId), { now: () => clock } as never), /expired/);
});

test("stuck-sending approvals surface for reconciliation after the window", () => {
  let clock = 5_000_000;
  const a = issue();
  beginSend(sendInput(a.approvalId), { now: () => clock });
  // Just after claim: not yet due.
  assert.equal(approvalsNeedingReconciliation(() => clock).some((x) => x.approvalId === a.approvalId), false);
  // Past the reconcile window: surfaces.
  clock += RECONCILE_AFTER_MS + 1000;
  assert.equal(approvalsNeedingReconciliation(() => clock).some((x) => x.approvalId === a.approvalId), true);
});
