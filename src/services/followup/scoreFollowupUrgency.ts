import { FollowupUrgencySchema, type FollowupUrgency } from "@aaliyah/contracts/v1";

import { adjustUrgencyForClientOwner } from "./adjustUrgencyForClientOwner";
import { adjustUrgencyForEscalation } from "./adjustUrgencyForEscalation";
import { adjustUrgencyForMeetingOwner } from "./adjustUrgencyForMeetingOwner";

export type FollowupUrgencyInput = {
  threadAgeHours: number;
  isClient?: boolean;
  isProspect?: boolean;
  explicitAskCount?: number;
  missedMeeting?: boolean;
  upcomingMeetingHours?: number | null;
  escalationRequired?: boolean;
  ownerMissing?: boolean;
  hasMeetingContext?: boolean;
  ownerIsMeetingOrganizer?: boolean;
  postMeetingReplySent?: boolean;
  promisedNextStep?: boolean;
  meetingOccurred?: boolean;
  ownerKnown?: boolean;
  explicitAskPresent?: boolean;
  ownerLabel?: string;
  followupOwed?: boolean;
  threadResolved?: boolean;
};

export function scoreFollowupUrgency(
  input: FollowupUrgencyInput,
): FollowupUrgency {
  let score = 0;

  if (input.threadAgeHours >= 72) {
    score += 25;
  } else if (input.threadAgeHours >= 24) {
    score += 15;
  } else if (input.threadAgeHours >= 8) {
    score += 8;
  }

  if (input.isClient) {
    score += 10;
  }

  if (input.isProspect) {
    score += 12;
  }

  score += Math.min(20, (input.explicitAskCount ?? 0) * 8);

  if (input.missedMeeting) {
    score += 25;
  }

  if (typeof input.upcomingMeetingHours === "number") {
    if (input.upcomingMeetingHours <= 4) {
      score += 30;
    } else if (input.upcomingMeetingHours <= 24) {
      score += 18;
    } else if (input.upcomingMeetingHours <= 72) {
      score += 10;
    }
  }

  if (
    input.meetingOccurred &&
    input.promisedNextStep &&
    !input.postMeetingReplySent
  ) {
    score += 20;
  }

  let urgency: FollowupUrgency;

  if (score >= 70) {
    urgency = FollowupUrgencySchema.parse("critical");
  } else if (score >= 45) {
    urgency = FollowupUrgencySchema.parse("high");
  } else if (score >= 20) {
    urgency = FollowupUrgencySchema.parse("medium");
  } else {
    urgency = FollowupUrgencySchema.parse("low");
  }

  const escalationAdjusted = adjustUrgencyForEscalation({
    currentUrgency: urgency,
    hasClientSignal: input.isClient,
    escalationRequired: input.escalationRequired,
    ownerMissing: input.ownerMissing,
    explicitAskPresent: input.explicitAskPresent,
    threadAgeHours: input.threadAgeHours,
    promisedNextStep: input.promisedNextStep,
    missedMeeting: input.missedMeeting,
    upcomingMeetingHours: input.upcomingMeetingHours,
  });

  const clientOwnerAdjusted = adjustUrgencyForClientOwner({
    currentUrgency: escalationAdjusted,
    hasClientSignal: input.isClient,
    ownerKnown: input.ownerKnown,
    explicitAskPresent: input.explicitAskPresent,
    threadAgeHours: input.threadAgeHours,
    escalationRequired: input.escalationRequired,
    followupOwed: input.followupOwed,
    threadResolved: input.threadResolved,
  });

  const meetingAdjusted = adjustUrgencyForMeetingOwner({
    currentUrgency: clientOwnerAdjusted,
    hasMeetingContext: input.hasMeetingContext,
    ownerIsMeetingOrganizer: input.ownerIsMeetingOrganizer,
    postMeetingReplySent: input.postMeetingReplySent,
    promisedNextStep: input.promisedNextStep,
    meetingMissed: input.missedMeeting,
  });

  const hasStrongSignal =
    Boolean(input.explicitAskPresent) ||
    Boolean(input.missedMeeting) ||
    Boolean(input.promisedNextStep) ||
    (typeof input.upcomingMeetingHours === "number" && input.upcomingMeetingHours <= 24);

  if (input.ownerLabel === "escalation:unassigned-review" && !hasStrongSignal) {
    if (meetingAdjusted === "high") {
      return FollowupUrgencySchema.parse("medium");
    }

    if (meetingAdjusted === "medium") {
      return FollowupUrgencySchema.parse("low");
    }
  }

  return FollowupUrgencySchema.parse(meetingAdjusted);
}
