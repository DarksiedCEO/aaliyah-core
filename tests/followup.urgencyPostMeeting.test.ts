import assert from "node:assert/strict";
import test from "node:test";

import { scoreFollowupUrgency } from "../src/services/followup/scoreFollowupUrgency";

test("post-meeting client recap due with no reply upgrades to high", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    hasMeetingContext: true,
    meetingOccurred: true,
    promisedNextStep: true,
    postMeetingReplySent: false,
    ownerKnown: true,
    ownerIsMeetingOrganizer: true,
  });

  assert.equal(urgency, "high");
});

test("post-meeting follow-up with reply already sent does not get the recap boost", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    hasMeetingContext: true,
    meetingOccurred: true,
    promisedNextStep: true,
    postMeetingReplySent: true,
    ownerKnown: true,
    ownerIsMeetingOrganizer: true,
  });

  assert.equal(urgency, "low");
});

test("non-client post-meeting context gets a smaller boost without jumping to high", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    hasMeetingContext: true,
    meetingOccurred: true,
    promisedNextStep: true,
    postMeetingReplySent: false,
    ownerKnown: true,
    ownerIsMeetingOrganizer: false,
  });

  assert.equal(urgency, "medium");
});
