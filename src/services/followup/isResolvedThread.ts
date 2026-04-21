type ResolutionEvidence = {
  workflowResolved?: boolean;
  outboundReplyAfterLatestInbound?: boolean;
  closureLanguageDetected?: boolean;
  followupCompleted?: boolean;
};

export function isResolvedThread(evidence: ResolutionEvidence): boolean {
  return Boolean(
    evidence.workflowResolved ||
      evidence.outboundReplyAfterLatestInbound ||
      evidence.closureLanguageDetected ||
      evidence.followupCompleted,
  );
}
