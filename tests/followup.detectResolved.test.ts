import assert from "node:assert/strict";
import test from "node:test";

import type { EvidenceSource } from "@aaliyah/contracts/v1";

import { detectFollowup } from "../src/services/followup/detectFollowup";

function evidence(overrides: Partial<EvidenceSource>): EvidenceSource {
  return {
    sourceId: "source_1",
    sourceType: "gmail",
    title: "Client follow-up",
    excerpt: "Client asked for pricing yesterday.",
    trustLevel: "high",
    freshness: "current",
    relevanceScore: 88,
    authorityScore: 82,
    recencyScore: 90,
    contradictionFlags: [],
    tags: [],
    retrievedAt: "2026-04-19T12:00:00.000Z",
    ...overrides,
  };
}

test("detectFollowup suppresses owed follow-up when workflow state is resolved", async () => {
  const decision = await detectFollowup({
    taskId: "task_resolved_1",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_1",
    inboxEvidence: [evidence({ sourceId: "gmail:1" })],
    calendarEvidence: [],
    workflowStateEvidence: [
      evidence({
        sourceId: "workflow:1",
        sourceType: "workflow_state",
        title: "Workflow state",
        excerpt: "status:resolved owner:ae@company.com",
      }),
    ],
  });

  assert.equal(decision.followupOwed, false);
  assert.match(decision.rationale, /resolved/);
  assert.equal(decision.escalationRequired, false);
});

test("detectFollowup suppresses when outbound reply already happened after the ask", async () => {
  const decision = await detectFollowup({
    taskId: "task_resolved_2",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_2",
    inboxEvidence: [
      evidence({
        sourceId: "gmail:2",
        excerpt: "Client asked for pricing. latest_reply_sent:true",
      }),
    ],
    calendarEvidence: [],
    workflowStateEvidence: [],
  });

  assert.equal(decision.followupOwed, false);
  assert.match(decision.rationale, /outbound reply/);
});

test("detectFollowup normalizes truthy outbound reply markers", async () => {
  for (const excerpt of [
    "Client asked for pricing. latest_reply_sent:true",
    "Client asked for pricing. latest_reply_sent yes",
    "Client asked for pricing. latest_reply_sent=1",
    "Client asked for pricing. latest_reply_sent: YES",
    "Client asked for pricing. latest_reply_sent   true",
  ]) {
    const decision = await detectFollowup({
      taskId: `task_resolved_truthy_${excerpt.length}`,
      tenantId: "tenant_1",
      userId: "user_1",
      threadId: "thread_truthy",
      inboxEvidence: [
        evidence({
          sourceId: `gmail:truthy:${excerpt.length}`,
          excerpt,
        }),
      ],
      calendarEvidence: [],
      workflowStateEvidence: [],
    });

    assert.equal(decision.followupOwed, false);
    assert.match(decision.rationale, /outbound reply/);
  }
});

test("detectFollowup ignores falsey outbound reply markers", async () => {
  for (const excerpt of [
    "Client asked for pricing. latest_reply_sent:false",
    "Client asked for pricing. latest_reply_sent no",
  ]) {
    const decision = await detectFollowup({
      taskId: `task_resolved_falsey_${excerpt.length}`,
      tenantId: "tenant_1",
      userId: "user_1",
      threadId: "thread_falsey",
      inboxEvidence: [
        evidence({
          sourceId: `gmail:falsey:${excerpt.length}`,
          excerpt,
        }),
      ],
      calendarEvidence: [],
      workflowStateEvidence: [],
    });

    assert.equal(decision.followupOwed, true);
  }
});

test("detectFollowup suppresses when closure language is present", async () => {
  const decision = await detectFollowup({
    taskId: "task_resolved_3",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_3",
    inboxEvidence: [
      evidence({
        sourceId: "gmail:3",
        excerpt: "Thank you, we're all set on this request.",
      }),
    ],
    calendarEvidence: [],
    workflowStateEvidence: [],
  });

  assert.equal(decision.followupOwed, false);
  assert.match(decision.rationale, /closure language/);
});

test("detectFollowup suppresses when ask exists but later resolution evidence exists", async () => {
  const decision = await detectFollowup({
    taskId: "task_resolved_4",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_4",
    inboxEvidence: [
      evidence({
        sourceId: "gmail:4",
        excerpt: "Client asked for proposal and deadline details.",
      }),
    ],
    calendarEvidence: [
      evidence({
        sourceId: "calendar:4",
        sourceType: "calendar",
        title: "Post-call note",
        excerpt: "Recap sent and follow-up completed",
      }),
    ],
    workflowStateEvidence: [],
  });

  assert.equal(decision.followupOwed, false);
  assert.match(decision.rationale, /follow-up completion/);
});
