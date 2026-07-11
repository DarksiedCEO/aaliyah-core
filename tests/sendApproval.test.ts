import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

import {
  issueSendApproval,
  createBeginSend,
  createSendSettler,
  reconcileSend,
  approvalsNeedingReconciliation,
  getApproval,
  invalidateApprovalsForConnection,
  RECONCILE_AFTER_MS,
} from "../src/mail/security/sendApproval";
import { createInMemoryMailState } from "../src/mail/mailState";

const SCOPE = { tenantId: "t", workspaceId: "w" };

let state: ReturnType<typeof createInMemoryMailState>;

beforeEach(() => {
  state = createInMemoryMailState();
});

const deps = () => ({ state });

async function issue(over: Record<string, unknown> = {}) {
  return issueSendApproval(
    {
      tenantId: "t", workspaceId: "w", connectionId: "c1",
      to: [{ email: "c@e.com" }], subject: "Re: Hi", body: "Thanks!",
      approvedByUserId: "boss", ...over,
    },
    deps(),
  );
}

function sendInput(approvalId: string, over: Record<string, unknown> = {}) {
  return { connectionId: "c1", approvalId, to: [{ email: "c@e.com" }], subject: "Re: Hi", body: "Thanks!", ...over };
}

test("happy path: issued -> sending -> sent, operation id persisted before provider execution", async () => {
  const a = await issue();
  assert.equal(a.status, "issued");

  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  const claimed = await beginSend(sendInput(a.approvalId));
  assert.equal(claimed.status, "sending");
  assert.ok(claimed.operationId); // stable op id assigned at claim
  // The op id is durable BEFORE any provider call — visible to other readers.
  assert.equal((await getApproval(a.approvalId, deps()))!.operationId, claimed.operationId);

  const settle = createSendSettler(deps());
  await settle({
    approvalId: a.approvalId,
    operationId: claimed.operationId!,
    outcome: { sent: true, providerMessageId: "gmail_msg_1" },
  });
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "sent");

  // Issuance, claim, and settlement are all durably audited.
  const audit = await state.audit.read(SCOPE);
  for (const action of ["mail.approval.issued", "mail.approval.claimed", "mail.send.settled"]) {
    assert.ok(audit.some((e) => e.action === action), action);
  }
});

test("a claimed (sending) approval cannot be claimed again — no double-send", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  await beginSend(sendInput(a.approvalId));
  await assert.rejects(() => beginSend(sendInput(a.approvalId)), /in flight — reconcile first/);
});

test("a sent approval cannot be replayed", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  const claimed = await beginSend(sendInput(a.approvalId));
  await createSendSettler(deps())({
    approvalId: a.approvalId,
    operationId: claimed.operationId!,
    outcome: { sent: true, providerMessageId: "m1" },
  });
  await assert.rejects(() => beginSend(sendInput(a.approvalId)), /already sent/);
});

test("tampered recipient, subject, or body is refused at claim time", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });

  await assert.rejects(
    () => beginSend(sendInput(a.approvalId, { to: [{ email: "attacker@evil.com" }] })),
    /recipient mismatch/,
  );
  await assert.rejects(
    () => beginSend(sendInput(a.approvalId, { subject: "URGENT: wire funds" })),
    /content mismatch/,
  );
  await assert.rejects(
    () => beginSend(sendInput(a.approvalId, { body: "Your refund has been issued." })),
    /content mismatch/,
  );
  // Still issued — a refused claim does not consume it.
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "issued");
});

test("wrong tenant, workspace, or connection is refused", async () => {
  const a = await issue();

  const wrongTenant = createBeginSend(deps(), { scope: { tenantId: "t_evil", workspaceId: "w" } });
  await assert.rejects(() => wrongTenant(sendInput(a.approvalId)), /tenant|scope/);

  const wrongWorkspace = createBeginSend(deps(), { scope: { tenantId: "t", workspaceId: "w_other" } });
  await assert.rejects(() => wrongWorkspace(sendInput(a.approvalId)), /workspace|scope/);

  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  await assert.rejects(
    () => beginSend(sendInput(a.approvalId, { connectionId: "c_OTHER" })),
    /connection mismatch/,
  );
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "issued");
});

test("settlement requires the matching operation id; duplicates are rejected", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  const claimed = await beginSend(sendInput(a.approvalId));
  const settle = createSendSettler(deps());

  await assert.rejects(
    () =>
      settle({
        approvalId: a.approvalId,
        operationId: "op_FORGED",
        outcome: { sent: true, providerMessageId: "m1" },
      }),
    /operation id mismatch/,
  );
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "sending");

  await settle({
    approvalId: a.approvalId,
    operationId: claimed.operationId!,
    outcome: { sent: true, providerMessageId: "m1" },
  });
  await assert.rejects(
    () =>
      settle({
        approvalId: a.approvalId,
        operationId: claimed.operationId!,
        outcome: { sent: true, providerMessageId: "m1" },
      }),
    /not sending/,
  );
});

test("ambiguous timeout stays sending, blocks retry, and is reconcilable", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  await beginSend(sendInput(a.approvalId));
  // Simulate an ambiguous provider timeout: NOT settled -> stays sending.
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "sending");
  await assert.rejects(() => beginSend(sendInput(a.approvalId)), /in flight/);

  // Reconcile: provider confirms NOT delivered -> failed_retryable -> claimable.
  await reconcileSend(a.approvalId, false, undefined, deps());
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "failed_retryable");
  const reclaim = await beginSend(sendInput(a.approvalId));
  assert.equal(reclaim.status, "sending");

  // The reconciliation decision is durably recorded and audited.
  const records = await state.reconciliation.listForApproval(a.approvalId);
  assert.equal(records.length, 1);
  assert.equal(records[0]!.outcome, "confirmed_not_delivered");
  assert.ok((await state.audit.read(SCOPE)).some((e) => e.action === "mail.reconciliation.decided"));
});

test("reconciliation can confirm delivery of an ambiguous send", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  await beginSend(sendInput(a.approvalId));
  await reconcileSend(a.approvalId, true, "gmail_msg_2", deps());
  const rec = (await getApproval(a.approvalId, deps()))!;
  assert.equal(rec.status, "sent");
  assert.equal(rec.providerMessageId, "gmail_msg_2");
  assert.equal(
    (await state.reconciliation.listForApproval(a.approvalId))[0]!.outcome,
    "confirmed_delivered",
  );
});

test("unambiguous failure -> failed_retryable is safely re-claimable", async () => {
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  const claimed = await beginSend(sendInput(a.approvalId));
  await createSendSettler(deps())({
    approvalId: a.approvalId,
    operationId: claimed.operationId!,
    outcome: { sent: false, retryable: true },
  });
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "failed_retryable");
  const reclaimed = await beginSend(sendInput(a.approvalId));
  assert.equal(reclaimed.status, "sending");
  assert.notEqual(reclaimed.operationId, claimed.operationId); // fresh op id per attempt
});

test("expired approvals cannot be claimed", async () => {
  let clock = 1_000_000;
  const a = await issueSendApproval(
    {
      tenantId: "t", workspaceId: "w", connectionId: "c1",
      to: [{ email: "c@e.com" }], subject: "Re: Hi", body: "Thanks!",
      approvedByUserId: "boss", ttlMs: 1000, now: () => clock,
    },
    deps(),
  );
  clock += 2000; // past expiry
  const beginSend = createBeginSend(deps(), { scope: SCOPE, now: () => clock });
  await assert.rejects(() => beginSend(sendInput(a.approvalId)), /expired/);
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "expired");
});

test("stuck-sending approvals surface for reconciliation after the window", async () => {
  let clock = 5_000_000;
  const a = await issue();
  const beginSend = createBeginSend(deps(), { scope: SCOPE, now: () => clock });
  await beginSend(sendInput(a.approvalId));
  // Just after claim: not yet due.
  assert.equal(
    (await approvalsNeedingReconciliation(deps(), () => clock)).some((x) => x.approvalId === a.approvalId),
    false,
  );
  // Past the reconcile window: surfaces.
  clock += RECONCILE_AFTER_MS + 1000;
  assert.equal(
    (await approvalsNeedingReconciliation(deps(), () => clock)).some((x) => x.approvalId === a.approvalId),
    true,
  );
});

test("disconnect durably invalidates approvals — later claims are refused", async () => {
  const a = await issue();
  await invalidateApprovalsForConnection("c1", deps());
  assert.equal((await getApproval(a.approvalId, deps()))!.status, "failed_terminal");
  const beginSend = createBeginSend(deps(), { scope: SCOPE });
  await assert.rejects(() => beginSend(sendInput(a.approvalId)), /terminally failed/);
});

test("issuance without an approver is refused; approvals never audit message content", async () => {
  await assert.rejects(() => issue({ approvedByUserId: "" }), /approver/);

  const a = await issue({ subject: "SECRET-SUBJECT", body: "SECRET-BODY" });
  assert.ok(a.approvalId);
  const auditText = JSON.stringify(await state.audit.read(SCOPE));
  assert.ok(!auditText.includes("SECRET-SUBJECT"));
  assert.ok(!auditText.includes("SECRET-BODY"));
});

test("claim fails closed when the audit record cannot be persisted — no send proceeds", async () => {
  const a = await issue();
  const brokenAudit = {
    ...state,
    audit: {
      ...state.audit,
      append: async () => {
        throw new Error("audit sink unavailable");
      },
    },
  };
  const beginSend = createBeginSend({ state: brokenAudit }, { scope: SCOPE });
  await assert.rejects(() => beginSend(sendInput(a.approvalId)), /audit/);
});
