import type {
  ApplyLabelInput,
  ConnectMailboxInput,
  ConnectionHealth,
  CreateDraftInput,
  ListThreadsInput,
  MailboxConnection,
  MailCapabilities,
  MailDraft,
  MailProvider,
  MailThread,
  ReadThreadInput,
  SendMessageInput,
  SentMessage,
} from "@aaliyah/contracts/v1";

import { MailProviderAdapter, MailTransportNotConfiguredError } from "../types";
import {
  denyAllSends,
  noopSettler,
  classifySendError,
  type ApprovalConsumer,
  type SendSettler,
} from "../sendGuard";
import { makeConnection, type AdapterDeps } from "./helpers";

/**
 * The live transport a real IMAP/SMTP (or Yahoo) integration must implement —
 * e.g. imapflow for reading/appending drafts and nodemailer for SMTP send. We
 * deliberately do NOT ship an unproven concrete transport; the operator injects
 * a verified one. Until then, operations fail loud rather than pretend.
 */
export interface MailTransport {
  verify(connection: MailboxConnection): Promise<boolean>;
  listThreads(connection: MailboxConnection, input: ListThreadsInput): Promise<MailThread[]>;
  readThread(connection: MailboxConnection, input: ReadThreadInput): Promise<MailThread>;
  createDraft(connection: MailboxConnection, input: CreateDraftInput): Promise<MailDraft>;
  sendMessage(connection: MailboxConnection, input: SendMessageInput): Promise<SentMessage>;
  applyLabel(connection: MailboxConnection, input: ApplyLabelInput): Promise<void>;
}

/**
 * Adapter for providers reached over a pluggable transport (generic IMAP/SMTP,
 * Yahoo). The architecture is complete and normalized; the concrete network
 * transport is an injected dependency. With no transport configured, every mail
 * operation throws `MailTransportNotConfiguredError` — honest by construction.
 */
export class TransportBackedAdapter implements MailProviderAdapter {
  readonly provider: MailProvider;
  readonly capabilities: MailCapabilities;

  private readonly transport: MailTransport | undefined;
  private readonly now: () => string;
  private readonly beginSend: ApprovalConsumer;
  private readonly settleSend: SendSettler;
  private readonly connections = new Map<string, MailboxConnection>();

  constructor(config: {
    provider: MailProvider;
    capabilities: MailCapabilities;
    transport?: MailTransport;
    deps?: AdapterDeps & { beginSend?: ApprovalConsumer; settleSend?: SendSettler };
  }) {
    this.provider = config.provider;
    this.capabilities = config.capabilities;
    this.transport = config.transport;
    this.now = config.deps?.now ?? (() => new Date().toISOString());
    this.beginSend = config.deps?.beginSend ?? denyAllSends;
    this.settleSend = config.deps?.settleSend ?? noopSettler;
  }

  private requireTransport(operation: string): MailTransport {
    if (!this.transport) {
      throw new MailTransportNotConfiguredError(this.provider, operation);
    }
    return this.transport;
  }

  private connection(connectionId: string): MailboxConnection {
    const conn = this.connections.get(connectionId);
    if (!conn) throw new Error(`${this.provider}: unknown connection ${connectionId}`);
    return conn;
  }

  async connect(input: ConnectMailboxInput): Promise<MailboxConnection> {
    const authKind = input.oauth ? "oauth" : "password";
    if (authKind === "password" && !input.password) {
      throw new Error(`${this.provider}: a password or app password is required`);
    }
    const conn = makeConnection(input, authKind, this.now);
    this.connections.set(conn.connectionId, conn);
    return conn;
  }

  async verify(connectionId: string): Promise<ConnectionHealth> {
    if (!this.transport) {
      return {
        connectionId,
        healthy: false,
        status: "degraded",
        checkedAt: this.now(),
        detail: `${this.provider}: no verified transport configured`,
      };
    }
    const healthy = await this.transport.verify(this.connection(connectionId));
    return {
      connectionId,
      healthy,
      status: healthy ? "active" : "unreachable",
      checkedAt: this.now(),
    };
  }

  async listThreads(input: ListThreadsInput): Promise<MailThread[]> {
    return this.requireTransport("listThreads").listThreads(
      this.connection(input.connectionId),
      input,
    );
  }

  async readThread(input: ReadThreadInput): Promise<MailThread> {
    return this.requireTransport("readThread").readThread(
      this.connection(input.connectionId),
      input,
    );
  }

  async createDraft(input: CreateDraftInput): Promise<MailDraft> {
    return this.requireTransport("createDraft").createDraft(
      this.connection(input.connectionId),
      input,
    );
  }

  async sendMessage(input: SendMessageInput): Promise<SentMessage> {
    const claim = this.beginSend(input);
    try {
      const sent = await this.requireTransport("sendMessage").sendMessage(
        this.connection(input.connectionId),
        input,
      );
      this.settleSend(claim.approvalId, { sent: true, providerMessageId: sent.messageId });
      return sent;
    } catch (error) {
      const outcome = classifySendError(error);
      if (outcome) this.settleSend(claim.approvalId, outcome);
      throw error;
    }
  }

  async applyLabel(input: ApplyLabelInput): Promise<void> {
    await this.requireTransport("applyLabel").applyLabel(
      this.connection(input.connectionId),
      input,
    );
  }

  async disconnect(connectionId: string): Promise<void> {
    this.connections.delete(connectionId);
  }
}

const GENERIC_CAPS: MailCapabilities = {
  provider: "imap_smtp",
  authKinds: ["password", "oauth"],
  listThreads: true,
  readThread: true,
  createDraft: true,
  sendMessage: true,
  applyLabel: false, // IMAP folders/flags vary by host; not universally supported
  implementationStatus: "experimental",
};

const YAHOO_CAPS: MailCapabilities = {
  provider: "yahoo",
  authKinds: ["oauth", "password"],
  listThreads: true,
  readThread: true,
  createDraft: true,
  sendMessage: true,
  applyLabel: false,
  // Yahoo is the weaker link: its mailbox API surface is less proven than
  // Google/Microsoft — experimental until an end-to-end run proves it.
  implementationStatus: "experimental",
};

export function createGenericImapSmtpAdapter(config?: {
  transport?: MailTransport;
  deps?: ConstructorParameters<typeof TransportBackedAdapter>[0]["deps"];
}): TransportBackedAdapter {
  return new TransportBackedAdapter({
    provider: "imap_smtp",
    capabilities: GENERIC_CAPS,
    ...(config?.transport ? { transport: config.transport } : {}),
    ...(config?.deps ? { deps: config.deps } : {}),
  });
}

export function createYahooMailAdapter(config?: {
  transport?: MailTransport;
  deps?: ConstructorParameters<typeof TransportBackedAdapter>[0]["deps"];
}): TransportBackedAdapter {
  return new TransportBackedAdapter({
    provider: "yahoo",
    capabilities: YAHOO_CAPS,
    ...(config?.transport ? { transport: config.transport } : {}),
    ...(config?.deps ? { deps: config.deps } : {}),
  });
}
