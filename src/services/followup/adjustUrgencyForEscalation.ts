import type { FollowupUrgency } from "@aaliyah/contracts/v1";

type AdjustUrgencyForEscalationInput = {
  currentUrgency: FollowupUrgency;
  hasClientSignal: boolean | undefined;
  escalationRequired: boolean | undefined;
  ownerMissing: boolean | undefined;
  explicitAskPresent: boolean | undefined;
  threadAgeHours: number | undefined;
  promisedNextStep: boolean | undefined;
  missedMeeting: boolean | undefined;
  upcomingMeetingHours: number | null | undefined;
};

export function adjustUrgencyForEscalation(
  input: AdjustUrgencyForEscalationInput,
): FollowupUrgency {
  const {
    currentUrgency,
    hasClientSignal,
    escalationRequired,
    ownerMissing,
    explicitAskPresent,
    threadAgeHours,
    promisedNextStep,
    missedMeeting,
    upcomingMeetingHours,
  } = input;

  if (
    hasClientSignal &&
    escalationRequired &&
    ownerMissing &&
    (explicitAskPresent || (threadAgeHours ?? 0) >= 24)
  ) {
    if (currentUrgency === "low") {
      return "medium";
    }

    const hasHighPressureSignal =
      Boolean(missedMeeting) ||
      Boolean(promisedNextStep) ||
      (typeof upcomingMeetingHours === "number" && upcomingMeetingHours <= 24) ||
      ((threadAgeHours ?? 0) >= 48 && Boolean(explicitAskPresent));

    if (currentUrgency === "medium" && hasHighPressureSignal) {
      return "high";
    }
  }

  return currentUrgency;
}
