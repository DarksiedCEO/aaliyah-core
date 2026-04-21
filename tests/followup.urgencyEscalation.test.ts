import assert from "node:assert/strict";
import test from "node:test";

import { scoreFollowupUrgency } from "../src/services/followup/scoreFollowupUrgency";

test("client escalation with missing owner boosts low urgency to medium", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    explicitAskCount: 1,
    explicitAskPresent: true,
    escalationRequired: true,
    ownerMissing: true,
  });

  assert.equal(urgency, "medium");
});

test("client escalation with missing owner and strong pressure boosts medium urgency to high", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 50,
    isClient: true,
    explicitAskCount: 1,
    explicitAskPresent: true,
    escalationRequired: true,
    ownerMissing: true,
  });

  assert.equal(urgency, "high");
});

test("client escalation with missing owner and only a basic ask stays medium", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    explicitAskCount: 1,
    explicitAskPresent: true,
    escalationRequired: true,
    ownerMissing: true,
  });

  assert.equal(urgency, "medium");
});

test("prospect escalation does not auto-boost the same way", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isProspect: true,
    explicitAskCount: 1,
    explicitAskPresent: true,
    escalationRequired: true,
    ownerMissing: true,
  });

  assert.equal(urgency, "medium");
});

test("already high urgency stays high without forced critical jump", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 30,
    isClient: true,
    explicitAskCount: 2,
    explicitAskPresent: true,
    missedMeeting: true,
    escalationRequired: true,
    ownerMissing: true,
  });

  assert.equal(urgency, "high");
});
