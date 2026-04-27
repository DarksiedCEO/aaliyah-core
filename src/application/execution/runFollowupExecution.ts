import {
  FollowupExecutionInputSchema,
  type EvidenceSource,
  type FollowupDecision,
  type FollowupDraft,
  type FollowupExecutionInput,
  type FollowupExecutionResult,
} from "@aaliyah/contracts/v1";

import { logExecution } from "../logging/logExecution";
import { createGmailDraft } from "../../integrations/gmail/createDraft";
import {
  readGmailThread,
  type GmailThread,
  type GmailThreadMessage,
} from "../../integrations/gmail/readThread";

export type FollowupDecisionResolverInput = {
  execution: FollowupExecutionInput;
  inboxEvidence: EvidenceSource[];
  recipientName?: string;
  userId?: string;
};

export type FollowupDecisionResolverResult = {
  decision: FollowupDecision;
  draft?: FollowupDraft;
};

type FollowupExecutionRuntime = {
  accessToken: string;
  userId?: string;
  now?: () => string;
  readThread?: typeof readGmailThread;
  resolveFollowupDecision?: (
    input: FollowupDecisionResolverInput,
  ) => Promise<FollowupDecisionResolverResult>;
  createDraft?: typeof createGmailDraft;
  logExecution?: typeof logExecution;
};

function normalizeUrgency(
  urgency: FollowupDecision["urgency"],
): "low" | "medium" | "high" {
  return urgency === "critical" ? "high" : urgency;
}

function headerValue(
  message: GmailThreadMessage | undefined,
  name: string,
): string | undefined {
  return message?.payload?.headers?.find(
    (header) => header.name?.toLowerCase() === name.toLowerCase(),
  )?.value ?? undefined;
}

function sortMessages(thread: GmailThread): GmailThreadMessage[] {
  return [...(thread.messages ?? [])].sort((left, right) => {
    const leftDate = Number(left.internalDate ?? "0");
    const rightDate = Number(right.internalDate ?? "0");
    return leftDate - rightDate;
  });
}

function messageToEvidence(
  message: GmailThreadMessage,
  tenantId: string,
  threadId: string,
  now: () => string,
): EvidenceSource {
  const subject = headerValue(message, "Subject") ?? "No subject";
  const from = headerValue(message, "From") ?? "Unknown sender";
  const date = headerValue(message, "Date") ?? "";

  return {
    sourceId: `gmail:${tenantId}:${threadId}:${message.id ?? "unknown"}`,
    sourceType: "gmail",
    title: subject,
    excerpt: [from, date, message.snippet ?? ""].filter(Boolean).join(" | "),
    trustLevel: "high",
    freshness: "current",
    relevanceScore: 90,
    authorityScore: 85,
    recencyScore: 90,
    contradictionFlags: [],
    tags: ["gmail", "execution"],
    retrievedAt: now(),
  };
}

function inferRecipient(messages: GmailThreadMessage[]): string | undefined {
  const latest = messages[messages.length - 1];
  return headerValue(latest, "Reply-To") ?? headerValue(latest, "From");
}

function inferRecipientName(recipient: string | undefined): string | undefined {
  if (!recipient) {
    return undefined;
  }

  const name = recipient.split("<")[0]?.replace(/"/g, "").trim();
  return name || undefined;
}

function buildRawDraft(input: {
  to?: string;
  threadId: string;
  subject: string;
  body: string;
}): string {
  const headers = [
    input.to ? `To: ${input.to}` : "",
    `Subject: ${input.subject}`,
    "Content-Type: text/plain; charset=UTF-8",
    "MIME-Version: 1.0",
    `References: ${input.threadId}`,
    `In-Reply-To: ${input.threadId}`,
  ].filter(Boolean);

  return `${headers.join("\r\n")}\r\n\r\n${input.body}`;
}

export async function runFollowupExecution(
  rawInput: FollowupExecutionInput,
  runtime: FollowupExecutionRuntime,
): Promise<FollowupExecutionResult> {
  const input = FollowupExecutionInputSchema.parse(rawInput);
  const now = runtime.now ?? (() => new Date().toISOString());
  const readThreadImpl = runtime.readThread ?? readGmailThread;
  const createDraftImpl = runtime.createDraft ?? createGmailDraft;
  const logExecutionImpl = runtime.logExecution ?? logExecution;
  const resolveFollowupDecision = runtime.resolveFollowupDecision;
  const userId = runtime.userId ?? "gmail-manual-approval";

  if (!resolveFollowupDecision) {
    throw new Error("Follow-up decision resolver required");
  }

  const thread = await readThreadImpl(input.threadId, runtime.accessToken);
  const messages = sortMessages(thread);
  const inboxEvidence = messages.map((message) =>
    messageToEvidence(message, input.tenantId, input.threadId, now),
  );

  const recipient = inferRecipient(messages);
  const recipientName = inferRecipientName(recipient);
  const { decision, draft } = await resolveFollowupDecision({
    execution: input,
    inboxEvidence,
    ...(recipientName ? { recipientName } : {}),
    userId,
  });

  if (!decision.followupOwed) {
    return {
      followupOwed: false,
      urgency: "low",
      owner: "none",
      escalationRequired: false,
      status: "no_action",
    };
  }

  if (!draft) {
    throw new Error("Follow-up draft required when follow-up is owed");
  }

  const rawDraftInput: {
    to?: string;
    threadId: string;
    subject: string;
    body: string;
  } = {
    threadId: input.threadId,
    subject: draft.subject,
    body: draft.body,
  };

  if (recipient) {
    rawDraftInput.to = recipient;
  }

  const draftId = await createDraftImpl(
    buildRawDraft(rawDraftInput),
    runtime.accessToken,
  );

  await logExecutionImpl({
    input,
    decision,
    draftId,
  });

  return {
    followupOwed: decision.followupOwed,
    urgency: normalizeUrgency(decision.urgency),
    owner: decision.owner,
    escalationRequired: decision.escalationRequired,
    draftId,
    status: "awaiting_approval",
  };
}
