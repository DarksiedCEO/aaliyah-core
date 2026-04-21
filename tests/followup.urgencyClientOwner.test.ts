import assert from "node:assert/strict";
import test from "node:test";

import { scoreFollowupUrgency } from "../src/services/followup/scoreFollowupUrgency";

test("known-owner client follow-up with explicit ask upgrades low to medium", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    ownerKnown: true,
    explicitAskCount: 1,
    explicitAskPresent: true,
    followupOwed: true,
  });

  assert.equal(urgency, "medium");
});

test("known-owner client follow-up with aged thread upgrades low to medium", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 30,
    isClient: true,
    ownerKnown: true,
    explicitAskCount: 0,
    explicitAskPresent: false,
    followupOwed: true,
  });

  assert.equal(urgency, "medium");
});

test("unknown-owner client follow-up does not use the known-owner boost", () => {
  const urgency = scoreFollowupUrgency({
    threadAgeHours: 1,
    isClient: true,
    ownerKnown: false,
    explicitAskCount: 1,
    explicitAskPresent: true,
  });

  assert.equal(urgency, "low");
});
