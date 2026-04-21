import assert from "node:assert/strict";
import test from "node:test";

import type { EvidenceSource } from "@aaliyah/contracts/v1";

import { selectFollowupOwner } from "../src/services/followup/selectFollowupOwner";

function evidence(overrides: Partial<EvidenceSource>): EvidenceSource {
  return {
    sourceId: "source_1",
    sourceType: "workflow_state",
    title: "Workflow state",
    excerpt: "",
    trustLevel: "high",
    freshness: "current",
    relevanceScore: 80,
    authorityScore: 80,
    recencyScore: 80,
    contradictionFlags: [],
    tags: [],
    retrievedAt: "2026-04-19T12:00:00.000Z",
    ...overrides,
  };
}

test("selectFollowupOwner prefers explicit workflow owner", () => {
  const result = selectFollowupOwner({
    workflowStateEvidence: [evidence({ excerpt: "owner:workflow@company.com status:prospect" })],
    inboxEvidence: [],
    calendarEvidence: [
      evidence({
        sourceType: "calendar",
        excerpt: "organizer:calendar@company.com",
      }),
    ],
  });

  assert.equal(result.owner, "workflow@company.com");
  assert.equal(result.escalationRequired, false);
});

test("selectFollowupOwner uses meeting organizer when no workflow owner exists", () => {
  const result = selectFollowupOwner({
    workflowStateEvidence: [evidence({ excerpt: "status:prospect" })],
    inboxEvidence: [],
    calendarEvidence: [
      evidence({
        sourceType: "calendar",
        excerpt: "organizer:meeting-owner@company.com",
      }),
    ],
  });

  assert.equal(result.owner, "meeting-owner@company.com");
});

test("selectFollowupOwner uses last responsible sender when explicit owner is absent", () => {
  const result = selectFollowupOwner({
    workflowStateEvidence: [evidence({ excerpt: "status:client" })],
    inboxEvidence: [
      evidence({
        sourceType: "gmail",
        excerpt: "internal_owner:sender@company.com",
      }),
    ],
    calendarEvidence: [],
  });

  assert.equal(result.owner, "sender@company.com");
});

test("selectFollowupOwner falls back to a specific escalation queue", () => {
  const prospectResult = selectFollowupOwner({
    workflowStateEvidence: [evidence({ excerpt: "status:prospect" })],
    inboxEvidence: [],
    calendarEvidence: [],
  });

  const clientResult = selectFollowupOwner({
    workflowStateEvidence: [evidence({ excerpt: "status:client" })],
    inboxEvidence: [],
    calendarEvidence: [],
  });

  assert.equal(prospectResult.owner, "escalation:sales");
  assert.equal(clientResult.owner, "escalation:client-success");
  assert.equal(prospectResult.escalationRequired, true);
  assert.doesNotMatch(prospectResult.owner, /unknown|team|general_owner|unassigned$/);
});

test("selectFollowupOwner ignores placeholder workflow owners", () => {
  const result = selectFollowupOwner({
    workflowStateEvidence: [evidence({ excerpt: "status:client owner:unknown" })],
    inboxEvidence: [],
    calendarEvidence: [],
  });

  assert.equal(result.owner, "escalation:client-success");
  assert.equal(result.escalationRequired, true);
});
