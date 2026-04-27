import assert from "node:assert/strict";
import test from "node:test";

import type { FollowupDecision } from "@aaliyah/contracts/v1";

import { runFollowupExecution } from "../src/application/execution/runFollowupExecution";

function owedDecision(overrides: Partial<FollowupDecision> = {}): FollowupDecision {
  return {
    taskId: "task_1",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_1",
    followupOwed: true,
    urgency: "medium",
    owner: "ae.jordan@zbestmedia.com",
    rationale: "Explicit client ask remains unresolved.",
    evidenceSourceIds: ["gmail:tenant_1:thread_1:message_1"],
    escalationRequired: false,
    confidence: 87,
    ...overrides,
  };
}

test("runFollowupExecution returns no_action for non-followup threads", async () => {
  const result = await runFollowupExecution(
    {
      tenantId: "tenant_1",
      threadId: "thread_1",
      messageId: "message_1",
    },
    {
      accessToken: "token",
      readThread: async () => ({
        id: "thread_1",
        messages: [
          {
            id: "message_1",
            threadId: "thread_1",
            snippet: "Thanks, all set.",
            payload: {
              headers: [
                { name: "Subject", value: "All set" },
                { name: "From", value: "Client <client@example.com>" },
              ],
            },
          },
        ],
      }),
      resolveFollowupDecision: async () => ({
        decision: owedDecision({
          followupOwed: false,
          urgency: "medium",
          owner: "escalation:unassigned-review",
          escalationRequired: true,
        }),
      }),
    },
  );

  assert.deepEqual(result, {
    followupOwed: false,
    urgency: "low",
    owner: "none",
    escalationRequired: false,
    status: "no_action",
  });
});

test("runFollowupExecution creates a Gmail draft and awaits approval", async () => {
  let loggedDraftId = "";
  let rawDraft = "";

  const result = await runFollowupExecution(
    {
      tenantId: "tenant_1",
      threadId: "thread_2",
      messageId: "message_2",
    },
    {
      accessToken: "token",
      readThread: async () => ({
        id: "thread_2",
        messages: [
          {
            id: "message_2",
            threadId: "thread_2",
            snippet: "Can you send the revised pricing?",
            payload: {
              headers: [
                { name: "Subject", value: "Pricing follow-up" },
                { name: "From", value: "Taylor Client <taylor@example.com>" },
              ],
            },
          },
        ],
      }),
      resolveFollowupDecision: async () => ({
        decision: owedDecision({ urgency: "critical" }),
        draft: {
          taskId: "task_1",
          threadId: "thread_2",
          subject: "Pricing follow-up",
          body: "Hi Taylor,\n\nHere is the draft.\n\nThanks,\nAaliyah",
          tone: "executive",
          approvalRequired: true,
          draftConfidence: 82,
        },
      }),
      createDraft: async (inputRawDraft: string) => {
        rawDraft = inputRawDraft;
        return "draft_123";
      },
      logExecution: async ({ draftId }) => {
        loggedDraftId = draftId ?? "";
      },
    },
  );

  assert.equal(result.status, "awaiting_approval");
  assert.equal(result.draftId, "draft_123");
  assert.equal(result.urgency, "high");
  assert.equal(loggedDraftId, "draft_123");
  assert.match(rawDraft, /To: Taylor Client <taylor@example.com>/);
  assert.match(rawDraft, /Subject: Pricing follow-up/);
});
