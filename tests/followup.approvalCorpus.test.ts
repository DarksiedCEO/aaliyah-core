import assert from "node:assert/strict";
import test, { afterEach } from "node:test";

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
  clearTrackedFollowupOutcomes,
  listTrackedFollowupOutcomes,
  trackFollowupOutcome,
} from "../src/services/followup/trackFollowupOutcome";

afterEach(async () => {
  await clearApprovalReviews();
  clearReplyOutcomes();
  clearTrackedFollowupOutcomes();
  delete process.env.AALIYAH_APPROVAL_REVIEW_LOG_PATH;
  delete process.env.AALIYAH_REPLY_OUTCOME_LOG_PATH;
  delete process.env.AALIYAH_FOLLOWUP_OUTCOME_LOG_PATH;
});

test("approval review captures accepted draft with no edits", async () => {
  const review = await recordApprovalReview({
    taskId: "task_accept_1",
    threadId: "thread_accept_1",
    approved: true,
    edited: false,
    editDistance: 0,
    reviewerId: "reviewer@company.com",
    reviewerRole: "manager",
    draftConfidence: 88,
    reviewSource: "live_operator",
    category: "client-followup",
    liveOperatorPilot: true,
    reviewedAt: "2026-04-19T12:00:00.000Z",
  });

  assert.equal(review.approved, true);
  assert.equal(review.edited, false);
  assert.equal(review.draftConfidence, 88);
  assert.equal(review.reviewSource, "live_operator");
  assert.equal(review.category, "client-followup");
});

test("approval review captures accepted draft with edits", async () => {
  await recordApprovalReview({
    taskId: "task_accept_2",
    threadId: "thread_accept_2",
    approved: true,
    edited: true,
    editDistance: 14,
    reviewerId: "reviewer@company.com",
    reviewerRole: "founder",
    draftConfidence: 74,
    reviewedAt: "2026-04-19T12:05:00.000Z",
  });

  const stored = (await listApprovalReviews())[0];

  assert.equal(stored?.edited, true);
  assert.equal(stored?.editDistance, 14);
  assert.equal(stored?.reviewerRole, "founder");
});

test("approval review persistence still works in live mode with metadata", async () => {
  await recordApprovalReview({
    taskId: "task_live_1",
    threadId: "thread_live_1",
    approved: true,
    edited: false,
    editDistance: 0,
    reviewerId: "operator@company.com",
    reviewerRole: "client-success",
    draftConfidence: 82,
    reviewSource: "live_operator",
    category: "post-meeting",
    liveOperatorPilot: true,
    reviewedAt: "2026-04-19T12:06:00.000Z",
  });

  const stored = (await listApprovalReviews()).find(
    (review) => review.taskId === "task_live_1",
  );

  assert.equal(stored?.reviewSource, "live_operator");
  assert.equal(stored?.category, "post-meeting");
  assert.equal(stored?.liveOperatorPilot, true);
});

test("approval review captures rejection reason and reviewer metadata", async () => {
  await recordApprovalReview({
    taskId: "task_reject_1",
    threadId: "thread_reject_1",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Too generic for this client",
    reviewerId: "reviewer@company.com",
    reviewerRole: "client-success",
    draftConfidence: 61,
    reviewedAt: "2026-04-19T12:10:00.000Z",
  });

  const stored = (await listApprovalReviews())[0];

  assert.equal(stored?.approved, false);
  assert.equal(stored?.rejectionReason, "too_generic");
  assert.equal(stored?.reviewerRole, "client-success");
});

test("follow-up outcomes persist with task and thread linkage", async () => {
  await trackFollowupOutcome({
    taskId: "task_outcome_1",
    threadId: "thread_outcome_1",
    status: "detected",
    outcomeNotes: [],
    shadowMode: true,
  });
  await trackFollowupOutcome({
    taskId: "task_outcome_1",
    threadId: "thread_outcome_1",
    status: "drafted",
    outcomeNotes: [],
    shadowMode: true,
  });

  const stored = (await listTrackedFollowupOutcomes()).filter(
    (outcome) =>
      outcome.taskId === "task_outcome_1" &&
      outcome.threadId === "thread_outcome_1",
  );

  assert.equal(stored.length, 2);
});

test("reply outcomes persist downstream reply signals", async () => {
  await recordReplyOutcome({
    taskId: "task_reply_1",
    threadId: "thread_reply_1",
    replyReceived: true,
    replyTimeHours: 4,
    positiveSignal: true,
    conversionSignal: false,
    createdAt: "2026-04-19T18:00:00.000Z",
  });

  const stored = (await listReplyOutcomes())[0];

  assert.equal(stored?.replyReceived, true);
  assert.equal(stored?.replyTimeHours, 4);
  assert.equal(stored?.taskId, "task_reply_1");
  assert.equal(stored?.threadId, "thread_reply_1");
});
