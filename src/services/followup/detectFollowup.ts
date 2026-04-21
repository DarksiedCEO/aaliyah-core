import {
  FollowupDecisionSchema,
  type EvidenceSource,
  type FollowupDecision,
} from "@aaliyah/contracts/v1";

import { hasMeetingFollowupObligation } from "./hasMeetingFollowupObligation";
import { hasEscalatedFollowupObligation } from "./hasEscalatedFollowupObligation";
import { scoreFollowupUrgency } from "./scoreFollowupUrgency";
import { isResolvedThread } from "./isResolvedThread";
import { selectFollowupOwner } from "./selectFollowupOwner";

type DetectFollowupInput = {
  taskId: string;
  tenantId: string;
  userId: string;
  threadId: string;
  inboxEvidence: EvidenceSource[];
  calendarEvidence: EvidenceSource[];
  workflowStateEvidence: EvidenceSource[];
};

function sourceIds(sources: EvidenceSource[]): string[] {
  return sources.map((source) => source.sourceId);
}

function hoursSince(dateLike: string | undefined): number {
  if (!dateLike) {
    return 0;
  }

  const timestamp = Date.parse(dateLike);

  if (Number.isNaN(timestamp)) {
    return 0;
  }

  return Math.max(0, (Date.now() - timestamp) / (1000 * 60 * 60));
}

function explicitAskCount(inboxEvidence: EvidenceSource[]): number {
  return inboxEvidence.reduce((count, source) => {
    const haystack = `${source.title} ${source.excerpt ?? ""}`.toLowerCase();
    return count +
      (/(pricing|quote|proposal|reply|follow up|follow-up|deadline|can you|can someone|could you|please|send|resend|confirm|waiting on|status update|need someone to answer)/.test(
        haystack,
      )
        ? 1
        : 0);
  }, 0);
}

function hasClientSignalInText(text: string): boolean {
  return /status:client|client\b|customer\b|account\b/.test(text);
}

function hasProspectSignalInText(text: string): boolean {
  return /status:prospect|status:lead|prospect\b|pricing\b|proposal\b|quote\b|lead\b/.test(
    text,
  );
}

function hasContradictions(sources: EvidenceSource[]): boolean {
  return sources.some((source) => source.contradictionFlags.length > 0);
}

function meetingSignals(calendarEvidence: EvidenceSource[]): {
  missedMeeting: boolean;
  upcomingMeetingHours: number | null;
} {
  let missedMeeting = false;
  let upcomingMeetingHours: number | null = null;

  for (const source of calendarEvidence) {
    const excerpt = (source.excerpt ?? "").toLowerCase();

    if (excerpt.includes("missed") || excerpt.includes("no show")) {
      missedMeeting = true;
    }

    const startMatch = source.excerpt?.match(/Start:\s*([^|]+)/i);
    if (startMatch?.[1]) {
      const startTime = Date.parse(startMatch[1].trim());
      if (!Number.isNaN(startTime)) {
        const hoursUntil = (startTime - Date.now()) / (1000 * 60 * 60);
        if (hoursUntil >= 0 && (upcomingMeetingHours === null || hoursUntil < upcomingMeetingHours)) {
          upcomingMeetingHours = hoursUntil;
        }
      }
    }
  }

  return { missedMeeting, upcomingMeetingHours };
}

function meetingFollowupEvidence(input: DetectFollowupInput): {
  meetingScheduled: boolean;
  meetingOccurred: boolean;
  meetingMissed: boolean;
  promisedNextStep: boolean;
  postMeetingReplySent: boolean;
} {
  const calendarText = joinedEvidenceText(input.calendarEvidence);
  const workflowText = joinedEvidenceText(input.workflowStateEvidence);
  const inboxText = joinedEvidenceText(input.inboxEvidence);

  return {
    meetingScheduled:
      /meeting|calendar|scheduled|invite|organizer:/.test(calendarText),
    meetingOccurred:
      /meeting occurred|met with|meeting completed|post-call|post meeting|recap/.test(
        `${calendarText} ${workflowText}`,
      ),
    meetingMissed: /missed|no show/.test(calendarText),
    promisedNextStep:
      /next step|send recap|send proposal|send pricing|follow up after meeting|recap promised/.test(
        `${calendarText} ${workflowText} ${inboxText}`,
      ),
    postMeetingReplySent:
      /recap sent|follow-up completed|post-meeting reply sent|next steps sent|reply sent after meeting/.test(
        `${calendarText} ${workflowText} ${inboxText}`,
      ),
  };
}

function meetingOrganizer(
  calendarEvidence: EvidenceSource[],
): string | undefined {
  for (const source of calendarEvidence) {
    const organizerMatch = source.excerpt?.match(/organizer:([^\s|;]+)/i);
    if (organizerMatch?.[1]) {
      return organizerMatch[1].trim();
    }
  }

  return undefined;
}

function strongestInboxSource(inboxEvidence: EvidenceSource[]): EvidenceSource | undefined {
  return [...inboxEvidence].sort((left, right) => right.relevanceScore - left.relevanceScore)[0];
}

function joinedEvidenceText(sources: EvidenceSource[]): string {
  return sources
    .map((source) => `${source.title} ${source.excerpt ?? ""}`)
    .join(" ")
    .toLowerCase();
}

function joinedEvidenceExcerptText(sources: EvidenceSource[]): string {
  return sources
    .map((source) => source.excerpt ?? "")
    .join(" ")
    .toLowerCase();
}

function hasTruthyMarker(text: string, key: string): boolean {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const truthyPattern = new RegExp(
    `${escapedKey}\\s*(?::|=|\\s)\\s*(true|yes|1)\\b`,
    "i",
  );
  return truthyPattern.test(text);
}

function resolutionSignals(input: DetectFollowupInput): {
  workflowResolved: boolean;
  outboundReplyAfterLatestInbound: boolean;
  closureLanguageDetected: boolean;
  followupCompleted: boolean;
} {
  const workflowText = joinedEvidenceText(input.workflowStateEvidence);
  const inboxText = joinedEvidenceText(input.inboxEvidence);
  const calendarText = joinedEvidenceText(input.calendarEvidence);

  return {
    workflowResolved:
      /status:(resolved|closed|completed)|resolved:true|closed:true|later_resolved|rescheduled/.test(
        workflowText,
      ),
    outboundReplyAfterLatestInbound:
      hasTruthyMarker(
        `${workflowText} ${inboxText}`,
        "outbound_reply_after_latest_inbound",
      ) ||
      hasTruthyMarker(`${workflowText} ${inboxText}`, "latest_reply_sent") ||
      hasTruthyMarker(`${workflowText} ${inboxText}`, "replied_after_ask"),
    closureLanguageDetected:
      /thank you[, ]+we('?| a)re all set|all set|resolved|closed loop|no action pending|handled already/.test(
        inboxText,
      ),
    followupCompleted:
      /follow-up completed|followup completed|recap sent|next steps sent/.test(
        `${workflowText} ${calendarText} ${inboxText}`,
      ),
  };
}

export async function detectFollowup(
  input: DetectFollowupInput,
): Promise<FollowupDecision> {
  const allEvidence = [
    ...input.inboxEvidence,
    ...input.calendarEvidence,
    ...input.workflowStateEvidence,
  ];

  if (hasContradictions(allEvidence)) {
    throw new Error("Contradictory follow-up evidence detected");
  }

  const topInboxSource = strongestInboxSource(input.inboxEvidence);
  const askCount = explicitAskCount(input.inboxEvidence);
  const { missedMeeting, upcomingMeetingHours } = meetingSignals(input.calendarEvidence);
  const ownerSelection = selectFollowupOwner({
    workflowStateEvidence: input.workflowStateEvidence,
    inboxEvidence: input.inboxEvidence,
    calendarEvidence: input.calendarEvidence,
  });
  const resolvedEvidence = resolutionSignals(input);
  const meetingObligationEvidence = meetingFollowupEvidence(input);
  const meetingFollowupOwed = hasMeetingFollowupObligation(meetingObligationEvidence);
  const workflowText = joinedEvidenceText(input.workflowStateEvidence);
  const inboxSignalText = joinedEvidenceExcerptText(input.inboxEvidence);
  const deadlinePressure =
    /deadline|by eod|by end of day|\btoday\b(?!['’]s)|this week|urgent|asap|before friday/.test(
      inboxSignalText,
    );
  const pendingPromise =
    /promised|still waiting|waiting on|send recap|send proposal|send pricing|next step|need someone to answer|implementation recap/.test(
      `${workflowText} ${inboxSignalText}`,
    );
  const unresolvedPromise =
    pendingPromise &&
    !resolvedEvidence.followupCompleted &&
    !meetingObligationEvidence.postMeetingReplySent;

  const threadAgeHours = hoursSince(topInboxSource?.retrievedAt);
  const inboxText = `${topInboxSource?.title ?? ""} ${topInboxSource?.excerpt ?? ""}`.toLowerCase();

  const hasClientSignal = hasClientSignalInText(`${workflowText} ${inboxSignalText}`);
  const hasProspectSignal = hasProspectSignalInText(`${workflowText} ${inboxSignalText}`);
  const threadResolved = isResolvedThread(resolvedEvidence);

  const strongObligation =
    meetingFollowupOwed ||
    (askCount > 0 && deadlinePressure) ||
    (unresolvedPromise && deadlinePressure) ||
    (missedMeeting && !meetingObligationEvidence.postMeetingReplySent) ||
    (typeof upcomingMeetingHours === "number" && upcomingMeetingHours <= 24);

  const helpfulClientDeliverableFollowup =
    askCount > 0 &&
    !threadResolved &&
    !strongObligation &&
    hasClientSignal &&
    /budget|scope|status update|implementation recap|send|resend|update/.test(
      inboxText,
    );

  const helpfulProspectPricingFollowup =
    askCount > 0 &&
    !threadResolved &&
    !strongObligation &&
    hasProspectSignal &&
    /pricing|proposal|quote|package/.test(inboxText);

  const followupOwed =
    (strongObligation ||
      helpfulClientDeliverableFollowup ||
      helpfulProspectPricingFollowup) &&
    !threadResolved;

  const activeObligationSignal =
    askCount > 0 ||
    unresolvedPromise ||
    deadlinePressure ||
    /need someone to answer|waiting on a reply|waiting|reply|follow up|deadline|pricing|proposal|quote/.test(
      inboxSignalText,
    ) ||
    meetingFollowupOwed;

  const evidenceSourceIds = sourceIds([
    ...input.inboxEvidence.slice(0, 2),
    ...input.calendarEvidence.slice(0, 1),
    ...input.workflowStateEvidence.slice(0, 1),
  ]);

  const escalatedFollowupOwed =
    strongObligation &&
    hasEscalatedFollowupObligation({
      ownerUnknown: ownerSelection.owner.startsWith("escalation:"),
      escalationRequired: ownerSelection.escalationRequired,
      hasClientSignal,
      hasProspectSignal,
      activeObligationSignal,
      threadResolved,
      postReplyClosure:
        resolvedEvidence.outboundReplyAfterLatestInbound ||
        resolvedEvidence.closureLanguageDetected ||
        resolvedEvidence.followupCompleted,
    });

  if (threadResolved) {
    const suppressionReasons: string[] = [];

    if (resolvedEvidence.workflowResolved) {
      suppressionReasons.push("workflow state marks the thread resolved");
    }

    if (resolvedEvidence.outboundReplyAfterLatestInbound) {
      suppressionReasons.push("a later outbound reply already closed the loop");
    }

    if (resolvedEvidence.closureLanguageDetected) {
      suppressionReasons.push("closure language indicates no action is pending");
    }

    if (resolvedEvidence.followupCompleted) {
      suppressionReasons.push("calendar or workflow notes show follow-up completion");
    }

    return FollowupDecisionSchema.parse({
      taskId: input.taskId,
      tenantId: input.tenantId,
      userId: input.userId,
      threadId: input.threadId,
      followupOwed: false,
      urgency: "low",
      owner: ownerSelection.owner,
      rationale: `Follow-up suppressed because ${suppressionReasons.join(", ")}.`,
      evidenceSourceIds,
      escalationRequired: false,
      confidence: 94,
    });
  }

  const followupOwedWithEscalation = followupOwed || escalatedFollowupOwed;
  const rationale = escalatedFollowupOwed
    ? "Evidence suggests a follow-up is owed because the owner is unresolved, escalation is required, and the thread still carries an active client or prospect obligation."
    : followupOwed
    ? `Evidence suggests a follow-up is owed due to ${
        meetingFollowupOwed
          ? "meeting-context follow-up obligation"
          : askCount > 0
            ? "explicit client asks"
            : unresolvedPromise
              ? "an unresolved promised next step"
            : "time-sensitive thread state"
      }${missedMeeting ? " and a missed meeting signal" : ""}.`
    : "Evidence does not support that a follow-up is currently owed.";
  const organizer = meetingOrganizer(input.calendarEvidence);

  if (followupOwedWithEscalation && evidenceSourceIds.length === 0) {
    throw new Error("Follow-up cannot be marked owed without evidence");
  }

  return FollowupDecisionSchema.parse({
    taskId: input.taskId,
    tenantId: input.tenantId,
    userId: input.userId,
    threadId: input.threadId,
    followupOwed: followupOwedWithEscalation,
    urgency: scoreFollowupUrgency({
      threadAgeHours,
      isClient: hasClientSignal,
      isProspect: hasProspectSignal,
      explicitAskCount: askCount,
      explicitAskPresent: askCount > 0,
      missedMeeting,
      upcomingMeetingHours,
      escalationRequired: ownerSelection.escalationRequired,
      ownerMissing: ownerSelection.owner.startsWith("escalation:"),
      hasMeetingContext: meetingObligationEvidence.meetingScheduled,
      meetingOccurred: meetingObligationEvidence.meetingOccurred,
      ownerIsMeetingOrganizer: organizer === ownerSelection.owner,
      postMeetingReplySent: meetingObligationEvidence.postMeetingReplySent,
      promisedNextStep: meetingObligationEvidence.promisedNextStep,
      ownerKnown: !ownerSelection.owner.startsWith("escalation:"),
      ownerLabel: ownerSelection.owner,
      followupOwed: followupOwedWithEscalation,
      threadResolved,
    }),
    owner: ownerSelection.owner,
    rationale,
    evidenceSourceIds,
    escalationRequired: ownerSelection.escalationRequired,
    confidence: followupOwedWithEscalation
      ? Math.min(95, 60 + evidenceSourceIds.length * 8 + askCount * 5)
      : 72,
  });
}
