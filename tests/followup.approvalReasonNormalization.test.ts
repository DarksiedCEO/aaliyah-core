import assert from "node:assert/strict";
import test from "node:test";

import {
  clearApprovalReviews,
  recordApprovalReview,
} from "../src/services/followup/recordApprovalReview";

test.beforeEach(async () => {
  await clearApprovalReviews();
});

test("generic rejection filler normalizes to other_unspecified", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_1",
    threadId: "thread_1",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Reviewer rejected follow-up draft.",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "other_unspecified");
});

test("genericity feedback normalizes to too_generic", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_2",
    threadId: "thread_2",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Too generic for this client",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "too_generic");
});

test("tone feedback normalizes to tone_off", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_3",
    threadId: "thread_3",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Tone is too aggressive for the relationship",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "tone_off");
});

test("missing context feedback normalizes to missing_context", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_4",
    threadId: "thread_4",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Missing context about the client's last ask",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "missing_context");
});

test("incorrect follow-up feedback normalizes to incorrect_followup", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_5",
    threadId: "thread_5",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Not needed, we shouldn't send this follow-up",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "incorrect_followup");
});

test("timing feedback normalizes to timing_wrong", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_6",
    threadId: "thread_6",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "Too early to send this",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "timing_wrong");
});

test("weak call to action normalizes to cta_weak", async () => {
  const review = await recordApprovalReview({
    taskId: "approval_norm_7",
    threadId: "thread_7",
    approved: false,
    edited: false,
    editDistance: 0,
    rejectionReason: "CTA is weak and the ask is unclear",
    reviewerId: "reviewer",
    reviewedAt: "2026-04-19T12:00:00.000Z",
    draftConfidence: 70,
  });

  assert.equal(review.rejectionReason, "cta_weak");
});
