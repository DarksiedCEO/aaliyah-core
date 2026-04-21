type MeetingFollowupEvidence = {
  meetingScheduled?: boolean;
  meetingOccurred?: boolean;
  meetingMissed?: boolean;
  promisedNextStep?: boolean;
  postMeetingReplySent?: boolean;
};

export function hasMeetingFollowupObligation(
  evidence: MeetingFollowupEvidence,
): boolean {
  if (evidence.meetingMissed && !evidence.postMeetingReplySent) {
    return true;
  }

  if (
    evidence.meetingOccurred &&
    evidence.promisedNextStep &&
    !evidence.postMeetingReplySent
  ) {
    return true;
  }

  return false;
}
