type EscalatedFollowupInput = {
  ownerUnknown?: boolean;
  escalationRequired?: boolean;
  hasClientSignal?: boolean;
  hasProspectSignal?: boolean;
  activeObligationSignal?: boolean;
  threadResolved?: boolean;
  postReplyClosure?: boolean;
};

export function hasEscalatedFollowupObligation(
  input: EscalatedFollowupInput,
): boolean {
  const obligationSignal = input.hasClientSignal || input.hasProspectSignal;

  return Boolean(
      input.ownerUnknown &&
      input.escalationRequired &&
      obligationSignal &&
      input.activeObligationSignal &&
      !input.threadResolved &&
      !input.postReplyClosure,
  );
}
