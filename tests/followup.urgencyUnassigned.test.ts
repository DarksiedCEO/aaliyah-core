import assert from "node:assert/strict";
import test from "node:test";

import { scoreFollowupUrgency } from "../src/services/followup/scoreFollowupUrgency";

test("unassigned review with weak signal stays low", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 2,
    isClient: true,
    ownerMissing: true,
    escalationRequired: true,
    ownerLabel: "escalation:unassigned-review",
    explicitAskCount: 0,
    explicitAskPresent: false,
  });

  assert.equal(urgency, "low");
});

test("unassigned review with strong signal can rise", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 2,
    isClient: true,
    ownerMissing: true,
    escalationRequired: true,
    ownerLabel: "escalation:unassigned-review",
    explicitAskCount: 1,
    explicitAskPresent: true,
  });

  assert.equal(urgency, "medium");
});

test("meeting-owner and known-owner paths are not capped by unassigned-review softening", () => {
  const meetingUrgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    ownerKnown: true,
    ownerLabel: "meetinghost@company.com",
    hasMeetingContext: true,
    ownerIsMeetingOrganizer: true,
    meetingOccurred: true,
    promisedNextStep: true,
    postMeetingReplySent: false,
  });

  assert.equal(meetingUrgency, "high");
});
