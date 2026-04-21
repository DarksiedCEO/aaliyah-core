import type { FollowupUrgency } from "@aaliyah/contracts/v1";

type ClientOwnerUrgencyInput = {
  currentUrgency: FollowupUrgency;
  hasClientSignal: boolean | undefined;
  ownerKnown: boolean | undefined;
  explicitAskPresent: boolean | undefined;
  threadAgeHours: number | undefined;
  escalationRequired?: boolean | undefined;
  followupOwed?: boolean | undefined;
  threadResolved?: boolean | undefined;
};

export function adjustUrgencyForClientOwner(
  input: ClientOwnerUrgencyInput,
): FollowupUrgency {
  if (
    input.hasClientSignal &&
    input.ownerKnown &&
    input.followupOwed &&
    !input.threadResolved &&
    (input.explicitAskPresent ||
      input.escalationRequired ||
      (input.threadAgeHours ?? 0) >= 24)
  ) {
    if (input.currentUrgency === "low") {
      return "medium";
    }

    if (input.currentUrgency === "medium" && input.escalationRequired) {
      return "high";
    }
  }

  return input.currentUrgency;
}
