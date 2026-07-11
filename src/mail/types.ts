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

/**
 * The one internal interface every mail provider implements. Aaliyah is
 * provider-agnostic — she issues the same normalized commands regardless of
 * whether Google, Microsoft, Yahoo, or a generic IMAP/SMTP host is underneath.
 */
export interface MailProviderAdapter {
  readonly provider: MailProvider;
  readonly capabilities: MailCapabilities;
  connect(input: ConnectMailboxInput): Promise<MailboxConnection>;
  verify(connectionId: string): Promise<ConnectionHealth>;
  listThreads(input: ListThreadsInput): Promise<MailThread[]>;
  readThread(input: ReadThreadInput): Promise<MailThread>;
  createDraft(input: CreateDraftInput): Promise<MailDraft>;
  sendMessage(input: SendMessageInput): Promise<SentMessage>;
  applyLabel(input: ApplyLabelInput): Promise<void>;
  disconnect(connectionId: string): Promise<void>;
}

/** Raised when an adapter's live transport has not been configured/proven. */
export class MailTransportNotConfiguredError extends Error {
  constructor(provider: MailProvider, operation: string) {
    super(
      `${provider}: '${operation}' requires a configured, verified transport — refusing to fake it`,
    );
    this.name = "MailTransportNotConfiguredError";
  }
}
