import {
  MailThreadSchema,
  MailDraftSchema,
  SentMessageSchema,
  type ApplyLabelInput,
  type ConnectMailboxInput,
  type ConnectionHealth,
  type CreateDraftInput,
  type ListThreadsInput,
  type MailCapabilities,
  type MailboxConnection,
  type MailDraft,
  type MailThread,
  type ReadThreadInput,
  type SendMessageInput,
  type SentMessage,
} from "@aaliyah/contracts/v1";

import type { MailProviderAdapter } from "../types";
import { assertSendApproved } from "../sendGuard";
import {
  base64url,
  buildRawRfc822,
  connectionIdFor,
  makeConnection,
  type AdapterDeps,
} from "./helpers";

const GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me";

type GmailHeader = { name?: string | null; value?: string | null };
type GmailMessage = {
  id?: string;
  threadId?: string;
  snippet?: string;
  internalDate?: string;
  payload?: { headers?: GmailHeader[] | null } | null;
};

function header(msg: GmailMessage, name: string): string {
  return (
    msg.payload?.headers?.find((h) => h?.name?.toLowerCase() === name.toLowerCase())
      ?.value ?? ""
  );
}

function normalizeMessage(threadId: string, msg: GmailMessage): object {
  const fromRaw = header(msg, "From");
  const email =
    fromRaw.match(/<([^>]+)>/)?.[1] ?? (fromRaw.trim() || "unknown@unknown.invalid");
  return {
    messageId: msg.id ?? "unknown",
    threadId: msg.threadId ?? threadId,
    from: { email },
    to: [],
    subject: header(msg, "Subject"),
    snippet: msg.snippet ?? "",
    receivedAt: msg.internalDate
      ? new Date(Number(msg.internalDate)).toISOString()
      : new Date(0).toISOString(),
  };
}

/**
 * Google Mail adapter — Gmail API over OAuth. Real REST shapes; transport is
 * injectable so it is testable without network, and tokens stay external
 * (resolveAccessToken), never held inside the adapter.
 */
export class GoogleMailAdapter implements MailProviderAdapter {
  readonly provider = "google" as const;
  readonly capabilities: MailCapabilities = {
    provider: "google",
    authKinds: ["oauth"],
    listThreads: true,
    readThread: true,
    createDraft: true,
    sendMessage: true,
    applyLabel: true,
    // Implemented against the real Gmail API but not yet proven end-to-end
    // against a live account in this environment.
    verified: false,
  };

  private readonly fetchImpl: typeof fetch;
  private readonly resolveToken: (connectionId: string) => string;
  private readonly now: () => string;
  private readonly isSendApproved: (connectionId: string, token: string) => boolean;

  constructor(
    deps: AdapterDeps & {
      isSendApproved?: (connectionId: string, token: string) => boolean;
    } = {},
  ) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.resolveToken =
      deps.resolveAccessToken ??
      (() => {
        throw new Error("google: no access-token resolver configured");
      });
    this.now = deps.now ?? (() => new Date().toISOString());
    this.isSendApproved = deps.isSendApproved ?? (() => false);
  }

  private async call(connectionId: string, path: string, init?: RequestInit): Promise<unknown> {
    const token = this.resolveToken(connectionId);
    const res = await this.fetchImpl(`${GMAIL}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
    if (!res.ok) {
      throw new Error(`google: request failed (${res.status})`);
    }
    return res.json();
  }

  async connect(input: ConnectMailboxInput): Promise<MailboxConnection> {
    if (!input.oauth?.accessToken) {
      throw new Error("google: OAuth access token required");
    }
    return makeConnection(input, "oauth", this.now);
  }

  async verify(connectionId: string): Promise<ConnectionHealth> {
    try {
      await this.call(connectionId, "/profile");
      return { connectionId, healthy: true, checkedAt: this.now() };
    } catch (error) {
      return {
        connectionId,
        healthy: false,
        checkedAt: this.now(),
        detail: error instanceof Error ? error.message : "unknown",
      };
    }
  }

  async listThreads(input: ListThreadsInput): Promise<MailThread[]> {
    const q = input.query ? `&q=${encodeURIComponent(input.query)}` : "";
    const data = (await this.call(
      input.connectionId,
      `/threads?maxResults=${input.limit}${q}`,
    )) as { threads?: { id?: string; snippet?: string }[] };
    return (data.threads ?? []).map((t) =>
      MailThreadSchema.parse({ threadId: t.id ?? "unknown", subject: "", messages: [] }),
    );
  }

  async readThread(input: ReadThreadInput): Promise<MailThread> {
    const data = (await this.call(
      input.connectionId,
      `/threads/${input.threadId}?format=metadata`,
    )) as { id?: string; messages?: GmailMessage[] };
    const messages = (data.messages ?? []).map((m) => normalizeMessage(input.threadId, m));
    return MailThreadSchema.parse({
      threadId: data.id ?? input.threadId,
      subject: messages.length > 0 ? (messages[0] as { subject: string }).subject : "",
      messages,
    });
  }

  async createDraft(input: CreateDraftInput): Promise<MailDraft> {
    const raw = base64url(
      buildRawRfc822({
        to: input.to.map((a) => a.email).join(", "),
        subject: input.subject,
        body: input.body,
        ...(input.inReplyToMessageId ? { inReplyTo: input.inReplyToMessageId } : {}),
      }),
    );
    const data = (await this.call(input.connectionId, "/drafts", {
      method: "POST",
      body: JSON.stringify({ message: { raw, ...(input.threadId ? { threadId: input.threadId } : {}) } }),
    })) as { id?: string; message?: { threadId?: string } };
    if (!data.id) throw new Error("google: draft creation failed");
    return MailDraftSchema.parse({
      draftId: data.id,
      connectionId: input.connectionId,
      ...(data.message?.threadId ? { threadId: data.message.threadId } : {}),
    });
  }

  async sendMessage(input: SendMessageInput): Promise<SentMessage> {
    assertSendApproved(input, this.isSendApproved);
    const body = input.draftId
      ? JSON.stringify({ id: input.draftId })
      : JSON.stringify({
          raw: base64url(
            buildRawRfc822({
              to: (input.to ?? []).map((a) => a.email).join(", "),
              subject: input.subject ?? "",
              body: input.body ?? "",
            }),
          ),
        });
    const path = input.draftId ? "/drafts/send" : "/messages/send";
    const data = (await this.call(input.connectionId, path, { method: "POST", body })) as {
      id?: string;
      threadId?: string;
    };
    return SentMessageSchema.parse({
      messageId: data.id ?? "unknown",
      ...(data.threadId ? { threadId: data.threadId } : {}),
      sentAt: this.now(),
    });
  }

  async applyLabel(input: ApplyLabelInput): Promise<void> {
    await this.call(input.connectionId, `/threads/${input.threadId}/modify`, {
      method: "POST",
      body: JSON.stringify({ addLabelIds: [input.label] }),
    });
  }

  async disconnect(_connectionId: string): Promise<void> {
    // Token revocation is handled by the credential layer; nothing to call here.
    void connectionIdFor;
  }
}
