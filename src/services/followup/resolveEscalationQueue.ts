export function resolveEscalationQueue(context: {
  hasProspectSignal?: boolean;
  hasClientSignal?: boolean;
  hasMeetingContext?: boolean;
}): string {
  if (context.hasProspectSignal) {
    return "escalation:sales";
  }

  if (context.hasClientSignal) {
    return "escalation:client-success";
  }

  if (context.hasMeetingContext) {
    return "escalation:meeting-owner-review";
  }

  return "escalation:unassigned-review";
}
