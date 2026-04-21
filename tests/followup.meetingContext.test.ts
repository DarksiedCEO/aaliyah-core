import assert from "node:assert/strict";
import test from "node:test";

import type { EvidenceSource } from "@aaliyah/contracts/v1";

import { detectFollowup } from "../src/services/followup/detectFollowup";

function evidence(overrides: Partial<EvidenceSource>): EvidenceSource {
  return {
    sourceId: "source_1",
    sourceType: "calendar",
    title: "Meeting context",
    excerpt: "",
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

test("missed meeting with no reply creates follow-up obligation", async () => {
  const decision = await detectFollowup({
    taskId: "meeting_1",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_1",
    inboxEvidence: [],
    calendarEvidence: [
      evidence({
        excerpt: "missed organizer:owner@company.com",
      }),
    ],
    workflowStateEvidence: [],
  });

  assert.equal(decision.followupOwed, true);
  assert.match(decision.rationale, /meeting-context follow-up obligation/);
});

test("meeting occurred with promised next step and no reply creates follow-up obligation", async () => {
  const decision = await detectFollowup({
    taskId: "meeting_2",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_2",
    inboxEvidence: [],
    calendarEvidence: [
      evidence({
        excerpt: "meeting completed organizer:owner@company.com",
      }),
    ],
    workflowStateEvidence: [
      evidence({
        sourceType: "workflow_state",
        excerpt: "recap promised next step send proposal",
      }),
    ],
  });

  assert.equal(decision.followupOwed, true);
});

test("meeting occurred with promised next step and follow-up sent is suppressed", async () => {
  const decision = await detectFollowup({
    taskId: "meeting_3",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_3",
    inboxEvidence: [
      evidence({
        sourceType: "gmail",
        excerpt: "post-meeting reply sent and next steps sent",
      }),
    ],
    calendarEvidence: [
      evidence({
        excerpt: "meeting completed organizer:owner@company.com",
      }),
    ],
    workflowStateEvidence: [
      evidence({
        sourceType: "workflow_state",
        excerpt: "recap promised",
      }),
    ],
  });

  assert.equal(decision.followupOwed, false);
});

test("missed meeting later resolved is suppressed", async () => {
  const decision = await detectFollowup({
    taskId: "meeting_4",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_4",
    inboxEvidence: [],
    calendarEvidence: [
      evidence({
        excerpt: "missed organizer:owner@company.com",
      }),
    ],
    workflowStateEvidence: [
      evidence({
        sourceType: "workflow_state",
        excerpt: "status:resolved follow-up completed",
      }),
    ],
  });

  assert.equal(decision.followupOwed, false);
});
