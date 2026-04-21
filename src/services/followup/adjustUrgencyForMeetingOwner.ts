import type { FollowupUrgency } from "@aaliyah/contracts/v1";

type MeetingUrgencyInput = {
  currentUrgency: FollowupUrgency;
  hasMeetingContext: boolean | undefined;
  ownerIsMeetingOrganizer: boolean | undefined;
  postMeetingReplySent: boolean | undefined;
  promisedNextStep: boolean | undefined;
  meetingMissed: boolean | undefined;
};

export function adjustUrgencyForMeetingOwner(
  input: MeetingUrgencyInput,
): FollowupUrgency {
  const {
    currentUrgency,
    hasMeetingContext,
    ownerIsMeetingOrganizer,
    postMeetingReplySent,
    promisedNextStep,
    meetingMissed,
  } = input;

  if (
    hasMeetingContext &&
    ownerIsMeetingOrganizer &&
    !postMeetingReplySent &&
    (promisedNextStep || meetingMissed)
  ) {
    if (currentUrgency === "low") {
      return "medium";
    }

    if (currentUrgency === "medium") {
      return "high";
    }
  }

  return currentUrgency;
}
