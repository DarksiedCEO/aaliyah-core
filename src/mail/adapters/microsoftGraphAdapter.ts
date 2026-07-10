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
import { makeConnection, type AdapterDeps } from "./helpers";

const GRAPH = "https://graph.microsoft.com/v1.0/me";

type GraphMessage = {
  id?: string;
  conversationId?: string;
  subject?: string;
  bodyPreview?: string;
  receivedDateTime?: string;
  from?: { emailAddress?: { address?: string; name?: string } };
};

function normalize(msg: GraphMessage): object {
  return {
    messageId: msg.id ?? "unknown",
    threadId: msg.conversationId ?? msg.id ?? "unknown",
    from: {
      email: msg.from?.emailAddress?.address ?? "unknown@unknown.invalid",
      ...(msg.from?.emailAddress?.name ? { name: msg.from.emailAddress.name } : {}),
    },
    to: [],
    subject: msg.subject ?? "",
    snippet: msg.bodyPreview ?? "",
    receivedAt: msg.receivedDateTime
      ? new Date(msg.receivedDateTime).toISOString()
      : new Date(0).toISOString(),
  };
}

/**
 * Microsoft Graph adapter — covers Outlook.com, Hotmail, Live, and Microsoft
 * 365 / Exchange Online mailboxes under one connector. Real Graph REST shapes;
 * transport injectable; tokens external.
 */
export class MicrosoftGraphAdapter implements MailProviderAdapter {
  readonly provider = "microsoft" as const;
  readonly capabilities: MailCapabilities = {
    provider: "microsoft",
    authKinds: ["oauth"],
    listThreads: true,
    readThread: true,
    createDraft: true,
    sendMessage: true,
    applyLabel: true,
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
        throw new Error("microsoft: no access-token resolver configured");
      });
    this.now = deps.now ?? (() => new Date().toISOString());
    this.isSendApproved = deps.isSendApproved ?? (() => false);
  }

  private async call(connectionId: string, path: string, init?: RequestInit): Promise<unknown> {
    const token = this.resolveToken(connectionId);
    const res = await this.fetchImpl(`${GRAPH}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
    if (!res.ok) throw new Error(`microsoft: request failed (${res.status})`);
    if (res.status === 202 || res.status === 204) return {};
    return res.json();
  }

  async connect(input: ConnectMailboxInput): Promise<MailboxConnection> {
    if (!input.oauth?.accessToken) throw new Error("microsoft: OAuth access token required");
    return makeConnection(input, "oauth", this.now);
  }

  async verify(connectionId: string): Promise<ConnectionHealth> {
    try {
      await this.call(connectionId, "?$select=id");
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
    const data = (await this.call(
      input.connectionId,
      `/messages?$top=${input.limit}&$select=id,conversationId,subject,bodyPreview,receivedDateTime,from`,
    )) as { value?: GraphMessage[] };

    const byConversation = new Map<string, GraphMessage>();
    for (const m of data.value ?? []) {
      const key = m.conversationId ?? m.id ?? "unknown";
      if (!byConversation.has(key)) byConversation.set(key, m);
    }
    return [...byConversation.entries()].map(([threadId, first]) =>
      MailThreadSchema.parse({ threadId, subject: first.subject ?? "", messages: [] }),
    );
  }

  async readThread(input: ReadThreadInput): Promise<MailThread> {
    const filter = encodeURIComponent(`conversationId eq '${input.threadId}'`);
    const data = (await this.call(input.connectionId, `/messages?$filter=${filter}`)) as {
      value?: GraphMessage[];
    };
    const messages = (data.value ?? []).map(normalize);
    return MailThreadSchema.parse({
      threadId: input.threadId,
      subject: messages.length > 0 ? (messages[0] as { subject: string }).subject : "",
      messages,
    });
  }

  async createDraft(input: CreateDraftInput): Promise<MailDraft> {
    const data = (await this.call(input.connectionId, "/messages", {
      method: "POST",
      body: JSON.stringify({
        subject: input.subject,
        body: { contentType: "Text", content: input.body },
        toRecipients: input.to.map((a) => ({ emailAddress: { address: a.email } })),
      }),
    })) as { id?: string; conversationId?: string };
    if (!data.id) throw new Error("microsoft: draft creation failed");
    return MailDraftSchema.parse({
      draftId: data.id,
      connectionId: input.connectionId,
      ...(data.conversationId ? { threadId: data.conversationId } : {}),
    });
  }

  async sendMessage(input: SendMessageInput): Promise<SentMessage> {
    assertSendApproved(input, this.isSendApproved);
    if (input.draftId) {
      await this.call(input.connectionId, `/messages/${input.draftId}/send`, { method: "POST" });
      return SentMessageSchema.parse({ messageId: input.draftId, sentAt: this.now() });
    }
    await this.call(input.connectionId, "/sendMail", {
      method: "POST",
      body: JSON.stringify({
        message: {
          subject: input.subject ?? "",
          body: { contentType: "Text", content: input.body ?? "" },
          toRecipients: (input.to ?? []).map((a) => ({ emailAddress: { address: a.email } })),
        },
      }),
    });
    return SentMessageSchema.parse({ messageId: `sent:${this.now()}`, sentAt: this.now() });
  }

  async applyLabel(input: ApplyLabelInput): Promise<void> {
    // Graph models labels as per-message categories.
    await this.call(input.connectionId, `/messages/${input.threadId}`, {
      method: "PATCH",
      body: JSON.stringify({ categories: [input.label] }),
    });
  }

  async disconnect(_connectionId: string): Promise<void> {
    // Token revocation handled by the credential layer.
  }
}
