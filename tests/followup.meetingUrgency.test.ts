import assert from "node:assert/strict";
import test from "node:test";

import { scoreFollowupUrgency } from "../src/services/followup/scoreFollowupUrgency";

test("meeting organizer with promised next step and no reply upgrades medium to high", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 24,
    explicitAskCount: 1,
    hasMeetingContext: true,
    ownerIsMeetingOrganizer: true,
    postMeetingReplySent: false,
    promisedNextStep: true,
  });

  assert.equal(urgency, "high");
});

test("missed meeting with organizer and no reply upgrades medium to high", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 2,
    hasMeetingContext: true,
    ownerIsMeetingOrganizer: true,
    postMeetingReplySent: false,
    missedMeeting: true,
  });

  assert.equal(urgency, "high");
});

test("meeting organizer with reply already sent gets no organizer boost", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 24,
    explicitAskCount: 1,
    hasMeetingContext: true,
    ownerIsMeetingOrganizer: true,
    postMeetingReplySent: true,
    promisedNextStep: true,
  });

  assert.equal(urgency, "medium");
});

test("non-meeting owner gets no organizer-specific boost", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 24,
    explicitAskCount: 1,
    hasMeetingContext: true,
    ownerIsMeetingOrganizer: false,
    postMeetingReplySent: false,
    promisedNextStep: true,
  });

  assert.equal(urgency, "medium");
});

test("critical still requires stronger evidence than organizer ownership alone", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 2,
    hasMeetingContext: true,
    ownerIsMeetingOrganizer: true,
    postMeetingReplySent: false,
    promisedNextStep: true,
  });

  assert.equal(urgency, "medium");
});
