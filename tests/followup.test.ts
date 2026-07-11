import assert from "node:assert/strict";
import test, { afterEach } from "node:test";

import type { EvidenceSource } from "@aaliyah/contracts/v1";

import { detectFollowup } from "../src/services/followup/detectFollowup";
import { draftFollowup } from "../src/services/followup/draftFollowup";
import {
  clearApprovalReviews,
  listApprovalReviews,
  recordApprovalReview,
} from "../src/services/followup/recordApprovalReview";
import {
  clearReplyOutcomes,
  listReplyOutcomes,
  recordReplyOutcome,
} from "../src/services/followup/recordReplyOutcome";
import {
  clearShadowDivergences,
  listShadowDivergences,
  recordShadowDivergence,
} from "../src/services/followup/recordShadowDivergence";
import { scoreFollowupUrgency } from "../src/services/followup/scoreFollowupUrgency";
import { selectFollowupOwner } from "../src/services/followup/selectFollowupOwner";
import {
  clearTrackedFollowupOutcomes,
  getTrackedFollowupOutcome,
  trackFollowupOutcome,
} from "../src/services/followup/trackFollowupOutcome";

function evidence(overrides: Partial<EvidenceSource>): EvidenceSource {
  return {
    sourceId: "source_1",
    sourceType: "gmail",
    title: "Pricing follow-up",
    excerpt: "Client asked for pricing? internal_owner:andre@company.com",
    trustLevel: "high",
    freshness: "current",
    relevanceScore: 88,
    authorityScore: 82,
    recencyScore: 90,
    contradictionFlags: [],
    tags: [],
    retrievedAt: "2026-04-18T12:00:00.000Z",
    ...overrides,
  };
}

afterEach(async () => {
  clearTrackedFollowupOutcomes();
  clearShadowDivergences();
  await clearApprovalReviews();
  clearReplyOutcomes();
});

test("detectFollowup returns owed=true when evidence is strong", async () => {
  const decision = await detectFollowup({
    taskId: "task_1",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_1",
    inboxEvidence: [evidence({ sourceId: "gmail:1" })],
    calendarEvidence: [evidence({
      sourceId: "calendar:1",
      sourceType: "calendar",
      title: "Upcoming client meeting",
      excerpt: "Start: 2026-04-18T14:00:00.000Z",
    })],
    workflowStateEvidence: [evidence({
      sourceId: "workflow:1",
      sourceType: "workflow_state",
      title: "Workflow state",
      excerpt: "status:prospect owner:andre@company.com",
    })],
  });

  assert.equal(decision.followupOwed, true);
  assert.ok(decision.rationale.length > 0);
  assert.ok(decision.evidenceSourceIds.length > 0);
});

test("detectFollowup returns owed=false when evidence is weak", async () => {
  const decision = await detectFollowup({
    taskId: "task_2",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_2",
    inboxEvidence: [evidence({
      sourceId: "gmail:2",
      title: "FYI update",
      excerpt: "Sharing notes from the last meeting.",
      relevanceScore: 25,
    })],
    calendarEvidence: [],
    workflowStateEvidence: [],
  });

  assert.equal(decision.followupOwed, false);
});

test("detectFollowup returns owed=true when a client explicitly asks for a deliverable", async () => {
  const decision = await detectFollowup({
    taskId: "task_ask",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_ask",
    inboxEvidence: [evidence({
      sourceId: "gmail:ask",
      title: "Budget follow-up",
      excerpt: "Can you send the revised media budget we discussed yesterday?",
      relevanceScore: 92,
    })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({
      sourceId: "workflow:ask",
      sourceType: "workflow_state",
      title: "Account state",
      excerpt: "status:client owner:ae.jordan@company.com",
    })],
  });

  assert.equal(decision.followupOwed, true);
});

test("detectFollowup returns owed=true for a client status ask even without deadline pressure", async () => {
  const decision = await detectFollowup({
    taskId: "task_status_ask",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_status_ask",
    inboxEvidence: [evidence({
      sourceId: "gmail:status-ask",
      title: "Status update",
      excerpt: "Can someone give us a quick status update on where this stands?",
      relevanceScore: 91,
    })],
    calendarEvidence: [],
    workflowStateEvidence: [evidence({
      sourceId: "workflow:status-ask",
      sourceType: "workflow_state",
      title: "Account state",
      excerpt: "status:client owner:unknown",
    })],
  });

  assert.equal(decision.followupOwed, true);
});

test("detectFollowup suppresses a missed meeting that was already rescheduled", async () => {
  const decision = await detectFollowup({
    taskId: "task_rescheduled_meeting",
    tenantId: "tenant_1",
    userId: "user_1",
    threadId: "thread_rescheduled_meeting",
    inboxEvidence: [],
    calendarEvidence: [evidence({
      sourceId: "calendar:rescheduled",
      sourceType: "calendar",
      title: "Rescheduled onboarding",
      excerpt: "missed organizer:meetinghost@company.com later_resolved true",
    })],
    workflowStateEvidence: [evidence({
      sourceId: "workflow:rescheduled",
      sourceType: "workflow_state",
      title: "Rescheduled",
      excerpt: "status:client owner:meetinghost@company.com resolved rescheduled",
    })],
  });

  assert.equal(decision.followupOwed, false);
});

test("detectFollowup blocks on contradictory evidence", async () => {
  await assert.rejects(
    () =>
      detectFollowup({
        taskId: "task_3",
        tenantId: "tenant_1",
        userId: "user_1",
        threadId: "thread_3",
        inboxEvidence: [evidence({
          sourceId: "gmail:3",
          contradictionFlags: ["content_mismatch"],
        })],
        calendarEvidence: [],
        workflowStateEvidence: [],
      }),
    /Contradictory follow-up evidence detected/,
  );
});

test("scoreFollowupUrgency is deterministic and evidence-based", () => {
  assert.equal(
    scoreFollowupUrgency({
      threadAgeHours: 80,
      isProspect: true,
      explicitAskCount: 2,
      upcomingMeetingHours: 2,
    }),
    "critical",
  );

  assert.equal(
    scoreFollowupUrgency({
      threadAgeHours: 4,
      explicitAskCount: 0,
      upcomingMeetingHours: null,
    }),
    "low",
  );
});

test("selectFollowupOwner prefers workflow owner, then inbox owner, then escalation", () => {
  const explicit = selectFollowupOwner({
    workflowStateEvidence: [evidence({
      sourceType: "workflow_state",
      sourceId: "workflow:owner",
      title: "Workflow state",
      excerpt: "owner:sales@company.com status:prospect",
    })],
    inboxEvidence: [],
  });

  assert.equal(explicit.owner, "sales@company.com");

  const inferred = selectFollowupOwner({
    workflowStateEvidence: [],
    inboxEvidence: [evidence({
      sourceId: "gmail:owner",
      excerpt: "internal_owner:andre@company.com",
    })],
  });

  assert.equal(inferred.owner, "andre@company.com");

  const unknown = selectFollowupOwner({
    workflowStateEvidence: [],
    inboxEvidence: [],
    calendarEvidence: [],
  });

  assert.equal(unknown.owner, "escalation:unassigned-review");
  assert.equal(unknown.escalationRequired, true);
});

test("draftFollowup returns approval-gated draft shape", async () => {
  const draft = await draftFollowup({
    decision: {
      taskId: "task_4",
      tenantId: "tenant_1",
      userId: "user_1",
      threadId: "thread_4",
      followupOwed: true,
      urgency: "high",
      owner: "andre@company.com",
      rationale: "Client requested pricing and has not received a response.",
      evidenceSourceIds: ["gmail:1"],
      escalationRequired: false,
      confidence: 82,
    },
    inboxEvidence: [
      evidence({
        sourceId: "gmail:draft-shape",
        title: "Budget follow-up",
        excerpt: "Can you send the revised media budget we discussed yesterday?",
      }),
    ],
    recipientName: "Taylor",
  });

  assert.equal(draft.approvalRequired, true);
  assert.ok(draft.subject.length > 0);
  assert.ok(draft.body.includes("Taylor"));
});

test("draftFollowup includes a clear and low-friction CTA", async () => {
  const draft = await draftFollowup({
    decision: {
      taskId: "task_cta",
      tenantId: "tenant_1",
      userId: "user_1",
      threadId: "thread_cta",
      followupOwed: true,
      urgency: "medium",
      owner: "andre@company.com",
      rationale: "Client requested pricing and has not received a response.",
      evidenceSourceIds: ["gmail:1"],
      escalationRequired: false,
      confidence: 82,
    },
    inboxEvidence: [
      evidence({
        sourceId: "gmail:cta",
        title: "Pricing request",
        excerpt: "Can you resend the pricing proposal and confirm package options?",
      }),
    ],
    recipientName: "Taylor",
  });

  assert.match(draft.body, /pricing details and proposal/i);
  assert.match(draft.body, /package you want first/i);
  assert.match(draft.subject, /pricing/i);
});

test("draftFollowup grounds escalation drafts in the concrete request", async () => {
  const draft = await draftFollowup({
    decision: {
      taskId: "task_escalation_cta",
      tenantId: "tenant_1",
      userId: "user_1",
      threadId: "thread_escalation_cta",
      followupOwed: true,
      urgency: "medium",
      owner: "escalation:client-success",
      rationale: "Owner unresolved but a recap is still owed.",
      evidenceSourceIds: ["gmail:1", "workflow:1"],
      escalationRequired: true,
      confidence: 76,
    },
    inboxEvidence: [
      evidence({
        sourceId: "gmail:escalation",
        title: "Waiting on recap",
        excerpt: "We are still waiting on the implementation recap you promised last week.",
      }),
    ],
    workflowStateEvidence: [
      evidence({
        sourceId: "workflow:escalation",
        sourceType: "workflow_state",
        title: "Account state",
        excerpt: "status:client owner:unknown",
      }),
    ],
    recipientName: "Taylor",
  });

  assert.match(draft.body, /recap and next steps we promised/i);
  assert.match(draft.body, /client success lead/i);
  assert.match(draft.body, /point you need covered first/i);
});

test("trackFollowupOutcome rejects illegal state transitions", async () => {
  await trackFollowupOutcome({
    taskId: "task_5",
    threadId: "thread_5",
    status: "detected",
    outcomeNotes: [],
    shadowMode: true,
  });

  await assert.rejects(
    () =>
      trackFollowupOutcome({
        taskId: "task_5",
        threadId: "thread_5",
        status: "sent",
        sentAt: "2026-04-18T12:00:00.000Z",
        outcomeNotes: [],
        shadowMode: false,
      }),
    /Illegal follow-up outcome transition/,
  );
});

test("trackFollowupOutcome persists shadow-safe state transitions", async () => {
  await trackFollowupOutcome({
    taskId: "task_6",
    threadId: "thread_6",
    status: "detected",
    outcomeNotes: ["Prediction only"],
    shadowMode: true,
  });

  await trackFollowupOutcome({
    taskId: "task_6",
    threadId: "thread_6",
    status: "drafted",
    outcomeNotes: ["Approval-gated draft prepared"],
    shadowMode: true,
  });

  assert.equal(getTrackedFollowupOutcome("task_6", "thread_6")?.status, "drafted");
});

test("recordShadowDivergence records predicted vs actual outcomes without side effects", async () => {
  await recordShadowDivergence({
    taskId: "task_7",
    threadId: "thread_7",
    predicted: {
      followupOwed: true,
      urgency: "high",
      owner: "andre@company.com",
      escalationRequired: false,
    },
    actual: {
      followupOwed: false,
      actionTaken: "dismissed",
    },
    divergenceReason: "Human judged no follow-up was owed",
    severity: "medium",
    createdAt: "2026-04-18T12:00:00.000Z",
  });

  assert.equal(listShadowDivergences().length, 1);
  assert.equal(listShadowDivergences()[0]?.actual.actionTaken, "dismissed");
});

test("recordApprovalReview tracks reviewer decision and edit distance", async () => {
  await recordApprovalReview({
    taskId: "task_8",
    threadId: "thread_8",
    approved: true,
    edited: true,
    editDistance: 12,
    reviewerId: "manager@company.com",
    draftConfidence: 84,
    reviewedAt: "2026-04-18T12:15:00.000Z",
  });

  const stored = await listApprovalReviews();

  assert.equal(stored.length, 1);
  assert.equal(stored[0]?.editDistance, 12);
});

test("recordReplyOutcome captures downstream reply signal", async () => {
  await recordReplyOutcome({
    taskId: "task_9",
    threadId: "thread_9",
    replyReceived: true,
    replyTimeHours: 5,
    positiveSignal: true,
    conversionSignal: false,
    createdAt: "2026-04-18T18:00:00.000Z",
  });

  assert.equal((await listReplyOutcomes()).length, 1);
  assert.equal((await listReplyOutcomes())[0]?.replyReceived, true);
});
