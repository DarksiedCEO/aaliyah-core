import assert from "node:assert/strict";
import test from "node:test";

import type { EvidenceSource } from "@aaliyah/contracts/v1";

import { detectFollowup } from "../src/services/followup/detectFollowup";

function evidence(overrides: Partial<EvidenceSource>): EvidenceSource {
  return {
    sourceId: overrides.sourceId ?? `source_${Math.random().toString(36).slice(2)}`,
    sourceType: overrides.sourceType ?? "workflow_state",
    title: overrides.title ?? "Evidence",
    excerpt: overrides.excerpt ?? "",
    trustLevel: overrides.trustLevel ?? "high",
    freshness: overrides.freshness ?? "current",
    relevanceScore: overrides.relevanceScore ?? 90,
    authorityScore: overrides.authorityScore ?? 88,
    recencyScore: overrides.recencyScore ?? 87,
    contradictionFlags: overrides.contradictionFlags ?? [],
    tags: overrides.tags ?? [],
    retrievedAt: overrides.retrievedAt ?? "2026-04-19T12:00:00.000Z",
  };
}

test("owner unknown plus vague client escalation does not force follow-up owed", async () => {
  const decision = await detectFollowup({
    taskId: "esc_1",
    tenantId: "tenant",
    userId: "user",
    threadId: "thread",
    inboxEvidence: [evidence({ sourceType: "gmail", excerpt: "Need someone to answer this client thread." })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({ excerpt: "status:client owner:unknown" })],
  });

  assert.equal(decision.followupOwed, false);
  assert.equal(decision.escalationRequired, true);
  assert.match(decision.rationale, /does not support that a follow-up is currently owed/i);
});

test("owner unknown plus prospect pricing escalation still marks follow-up owed", async () => {
  const decision = await detectFollowup({
    taskId: "esc_2",
    tenantId: "tenant",
    userId: "user",
    threadId: "thread",
    inboxEvidence: [evidence({ sourceType: "gmail", excerpt: "Prospect asked for pricing details." })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({ excerpt: "status:lead owner:unknown" })],
  });

  assert.equal(decision.followupOwed, true);
  assert.equal(decision.escalationRequired, true);
});

test("resolved threads still suppress escalated obligation", async () => {
  const decision = await detectFollowup({
    taskId: "esc_3",
    tenantId: "tenant",
    userId: "user",
    threadId: "thread",
    inboxEvidence: [evidence({ sourceType: "gmail", excerpt: "Need someone to answer this client thread." })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({ excerpt: "status:lead owner:unknown status:resolved" })],
  });

  assert.equal(decision.followupOwed, false);
});

test("owner unknown without obligation signal does not force follow-up owed", async () => {
  const decision = await detectFollowup({
    taskId: "esc_4",
    tenantId: "tenant",
    userId: "user",
    threadId: "thread",
    inboxEvidence: [evidence({ sourceType: "gmail", excerpt: "Internal note for the file." })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({ excerpt: "status:internal_review" })],
  });

  assert.equal(decision.followupOwed, false);
});

test("ambiguous client note does not force an escalated follow-up obligation", async () => {
  const decision = await detectFollowup({
    taskId: "esc_5",
    tenantId: "tenant",
    userId: "user",
    threadId: "thread",
    inboxEvidence: [evidence({ sourceType: "gmail", excerpt: "Just sharing a note from today's call." })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({ excerpt: "status:client" })],
  });

  assert.equal(decision.followupOwed, false);
});
