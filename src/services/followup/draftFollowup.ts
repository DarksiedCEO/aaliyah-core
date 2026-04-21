import {
  FollowupDraftSchema,
  type EvidenceSource,
  type FollowupDecision,
  type FollowupDraft,
} from "@aaliyah/contracts/v1";

function cleanupEvidenceText(text: string): string {
  return text
    .replace(/internal_owner:[^\s|;]+/gi, "")
    .replace(/owner:[^\s|;]+/gi, "")
    .replace(/status:[^\s|;]+/gi, "")
    .replace(/organizer:[^\s|;]+/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function strongestSource(
  sources: EvidenceSource[] | undefined,
): EvidenceSource | undefined {
  return [...(sources ?? [])].sort(
    (left, right) => right.relevanceScore - left.relevanceScore,
  )[0];
}

function requestSummary(input: {
  decision: FollowupDecision;
  inboxEvidence?: EvidenceSource[];
  calendarEvidence?: EvidenceSource[];
  workflowStateEvidence?: EvidenceSource[];
}): string {
  const topInbox = strongestSource(input.inboxEvidence);
  const topCalendar = strongestSource(input.calendarEvidence);
  const topWorkflow = strongestSource(input.workflowStateEvidence);
  const haystack = cleanupEvidenceText(
    [
      topInbox?.title ?? "",
      topInbox?.excerpt ?? "",
      topCalendar?.title ?? "",
      topCalendar?.excerpt ?? "",
      topWorkflow?.title ?? "",
      topWorkflow?.excerpt ?? "",
      input.decision.rationale,
    ].join(" ").toLowerCase(),
  );

  if (/revised media budget|revised budget|budget/.test(haystack)) {
    return "the revised media budget you asked for";
  }

  if (/implementation recap|recap promised|send recap|strategy recap|post-meeting/.test(haystack)) {
    return "the recap and next steps we promised";
  }

  if (/pricing|proposal resend|resend the pricing proposal|package options|starter package/.test(haystack)) {
    return "the pricing details and proposal you asked for";
  }

  if (/next step|meeting completed|strategy session|meeting-context/.test(haystack)) {
    return "the next step coming out of our meeting";
  }

  const excerpt = cleanupEvidenceText(topInbox?.excerpt ?? topCalendar?.excerpt ?? "");
  if (excerpt.length >= 12) {
    return excerpt.endsWith(".") ? excerpt : `${excerpt}.`;
  }

  return "the request you sent";
}

function ownerLabel(owner: string): string {
  if (owner.startsWith("escalation:client-success")) {
    return "our client success lead";
  }

  if (owner.startsWith("escalation:sales")) {
    return "our sales lead";
  }

  if (owner.startsWith("escalation:meeting-owner-review")) {
    return "the meeting owner";
  }

  if (owner.startsWith("escalation:")) {
    return "the right owner";
  }

  return owner;
}

function specificCta(input: {
  requestSummary: string;
  escalationRequired: boolean;
  urgency: FollowupDecision["urgency"];
}): string {
  const request = input.requestSummary.toLowerCase();

  if (input.escalationRequired && /pricing|proposal|package/.test(request)) {
    return "If you want, reply with the package or budget range to prioritize and I will route it to sales today.";
  }

  if (input.escalationRequired && /recap|next step|meeting/.test(request)) {
    return "If you want, reply with the one point you need covered first and I will route it to the right owner today.";
  }

  if (/budget/.test(request)) {
    return "If you want, reply with the budget line or channel you want prioritized and I will send the revision next.";
  }

  if (/pricing|proposal|package/.test(request)) {
    return "If you want, reply with the package you want first and I will send that version next.";
  }

  if (/recap|next step|meeting/.test(request)) {
    return input.urgency === "high" || input.urgency === "critical"
      ? "If you want, reply with the key decision to capture and I will send the recap today."
      : "If you want, reply with the point you want covered first and I will send the recap next.";
  }

  return input.urgency === "high" || input.urgency === "critical"
    ? "If you want, reply with the specific item you need first and I will send the next step today."
    : "If you want, reply with the specific item you need first and I will send the next step next.";
}

export async function draftFollowup(input: {
  decision: FollowupDecision;
  recipientName?: string;
  inboxEvidence?: EvidenceSource[];
  calendarEvidence?: EvidenceSource[];
  workflowStateEvidence?: EvidenceSource[];
}): Promise<FollowupDraft> {
  const groundingContext = {
    decision: input.decision,
    ...(input.inboxEvidence ? { inboxEvidence: input.inboxEvidence } : {}),
    ...(input.calendarEvidence ? { calendarEvidence: input.calendarEvidence } : {}),
    ...(input.workflowStateEvidence
      ? { workflowStateEvidence: input.workflowStateEvidence }
      : {}),
  };

  const confidenceBase = Math.max(
    35,
    Math.min(
      92,
      input.decision.confidence - (input.decision.escalationRequired ? 18 : 0),
    ),
  );

  const tone =
    input.decision.urgency === "critical"
      ? "firm"
      : input.decision.urgency === "high"
        ? "executive"
        : "warm";

  const subject =
    input.decision.urgency === "critical"
      ? "Following up on your outstanding request"
      : /budget/.test(requestSummary(groundingContext).toLowerCase())
        ? "Revised budget follow-up"
        : /pricing|proposal/.test(requestSummary(groundingContext).toLowerCase())
          ? "Pricing follow-up"
          : /recap|meeting|next step/.test(
                requestSummary(groundingContext).toLowerCase(),
              )
            ? "Recap follow-up"
            : "Following up";

  const groundedRequest = requestSummary(groundingContext);

  const ctaLine = specificCta({
    requestSummary: groundedRequest,
    escalationRequired: input.decision.escalationRequired,
    urgency: input.decision.urgency,
  });

  const body = [
    input.recipientName ? `Hi ${input.recipientName},` : "Hi there,",
    "",
    `Following up on ${groundedRequest} so we can keep this moving.`,
    input.decision.escalationRequired
      ? "Let me confirm this with our team and I’ll follow up with the right details shortly."
      : `I wanted to make sure you get ${groundedRequest}.`,
    ctaLine,
    "",
    "Thanks,",
    input.decision.owner === "unassigned" ? "Aaliyah Team" : ownerLabel(input.decision.owner),
  ].join("\n");

  return FollowupDraftSchema.parse({
    taskId: input.decision.taskId,
    threadId: input.decision.threadId,
    subject,
    body,
    tone,
    approvalRequired: true,
    draftConfidence: confidenceBase,
  });
}
