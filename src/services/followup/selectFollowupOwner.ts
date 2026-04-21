import type { EvidenceSource } from "@aaliyah/contracts/v1";

import { resolveEscalationQueue } from "./resolveEscalationQueue";

export type FollowupOwnerSelection = {
  owner: string;
  escalationRequired: boolean;
  rationale: string;
};

function isPlaceholderOwner(owner: string | undefined): boolean {
  if (!owner) {
    return true;
  }

  return /^(unknown|unassigned|team|general_owner|owner:unknown)$/i.test(
    owner.trim(),
  );
}

function ownerFromWorkflowState(
  workflowStateEvidence: EvidenceSource[],
): string | undefined {
  for (const source of workflowStateEvidence) {
    const match = source.excerpt?.match(/owner:([^\s|;]+)/i);
    if (match?.[1]) {
      const owner = match[1].trim();
      if (!isPlaceholderOwner(owner)) {
        return owner;
      }
    }
  }

  return undefined;
}

function ownerFromCalendar(
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

function ownerFromInbox(
  inboxEvidence: EvidenceSource[],
): string | undefined {
  for (const source of inboxEvidence) {
    const match = source.excerpt?.match(/internal_owner:([^\s|;]+)/i);
    if (match?.[1]) {
      const owner = match[1].trim();
      if (!isPlaceholderOwner(owner)) {
        return owner;
      }
    }
  }

  return undefined;
}

function ownerFromAccountAssignment(
  workflowStateEvidence: EvidenceSource[],
): string | undefined {
  for (const source of workflowStateEvidence) {
    const accountOwnerMatch = source.excerpt?.match(/account_owner:([^\s|;]+)/i);
    if (accountOwnerMatch?.[1]) {
      const owner = accountOwnerMatch[1].trim();
      if (!isPlaceholderOwner(owner)) {
        return owner;
      }
    }

    const dealOwnerMatch = source.excerpt?.match(/deal_owner:([^\s|;]+)/i);
    if (dealOwnerMatch?.[1]) {
      const owner = dealOwnerMatch[1].trim();
      if (!isPlaceholderOwner(owner)) {
        return owner;
      }
    }
  }

  return undefined;
}

export function selectFollowupOwner(input: {
  workflowStateEvidence: EvidenceSource[];
  inboxEvidence: EvidenceSource[];
  calendarEvidence?: EvidenceSource[];
}): FollowupOwnerSelection {
  const explicitOwner = ownerFromWorkflowState(input.workflowStateEvidence);

  if (explicitOwner) {
    return {
      owner: explicitOwner,
      escalationRequired: false,
      rationale: "Owner selected from workflow state.",
    };
  }

  const meetingOwner = ownerFromCalendar(input.calendarEvidence ?? []);

  if (meetingOwner) {
    return {
      owner: meetingOwner,
      escalationRequired: false,
      rationale: "Owner selected from meeting organizer context.",
    };
  }

  const lastResponsibleSender = ownerFromInbox(input.inboxEvidence);

  if (lastResponsibleSender) {
    return {
      owner: lastResponsibleSender,
      escalationRequired: false,
      rationale: "Owner inferred from the last responsible internal sender.",
    };
  }

  const assignedAccountOwner = ownerFromAccountAssignment(input.workflowStateEvidence);

  if (assignedAccountOwner) {
    return {
      owner: assignedAccountOwner,
      escalationRequired: false,
      rationale: "Owner selected from account or deal assignment.",
    };
  }

  const workflowText = input.workflowStateEvidence
    .map((source) => source.excerpt ?? "")
    .join(" ")
    .toLowerCase();
  const calendarText = (input.calendarEvidence ?? [])
    .map((source) => `${source.title} ${source.excerpt ?? ""}`)
    .join(" ")
    .toLowerCase();

  return {
    owner: resolveEscalationQueue({
      hasProspectSignal: workflowText.includes("status:prospect"),
      hasClientSignal: workflowText.includes("status:client"),
      hasMeetingContext: calendarText.length > 0,
    }),
    escalationRequired: true,
    rationale: "No explicit owner found; routed to a specific escalation queue.",
  };
}
