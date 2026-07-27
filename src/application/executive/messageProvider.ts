import {
  NormalizedAttachmentSchema,
  NormalizedMessageSchema,
  NormalizedThreadSchema,
  ProviderCapabilitiesV2Schema,
  ProviderReadbackReceiptSchema,
  Wave1ProviderDraftReceiptSchema,
  assertProviderCapabilitiesTrusted,
  verifyProviderReadbackReceipt,
  type NormalizedAttachment,
} from "@aaliyah/contracts/v1";

type ProviderCapabilities = ReturnType<
  typeof ProviderCapabilitiesV2Schema.parse
>;
type ProviderOperation = ProviderCapabilities["operations"][number]["operation"];
type HandlerOperation = Exclude<ProviderOperation, "get_capabilities">;
type ProviderDraftReceipt = ReturnType<
  typeof Wave1ProviderDraftReceiptSchema.parse
>;
type ProviderReadbackReceipt = ReturnType<
  typeof ProviderReadbackReceiptSchema.parse
>;
type NormalizedMessage = ReturnType<typeof NormalizedMessageSchema.parse>;
type NormalizedThread = ReturnType<typeof NormalizedThreadSchema.parse>;

export type ProviderScope = {
  tenantId: string;
  workspaceId: string;
  userId: string;
  connectionId: string;
};

export type ProviderDraftInput = ProviderScope & {
  taskId: string;
  requestId: string;
  threadId: string;
  idempotencyKey: string;
  recipientDigest: string;
  candidateDigest: string;
  contextDigest: string;
  capabilityCandidateDigest: string;
  authorizationId: string;
  approvalId: string;
  qualityBundleId: string;
  verifiedEnvelopeDigest: string;
  to: ReadonlyArray<{ email: string; name?: string }>;
  cc: ReadonlyArray<{ email: string; name?: string }>;
  bcc: ReadonlyArray<{ email: string; name?: string }>;
  subject: string;
  body: string;
};

export type ProviderReadbackInput = ProviderScope & {
  providerDraftReceipt: ProviderDraftReceipt;
};

export interface MessageProvider {
  getCapabilities(): ProviderCapabilities;
  listMessages(input: ProviderScope): Promise<NormalizedMessage[]>;
  readMessage(input: ProviderScope & { messageId: string }): Promise<NormalizedMessage>;
  readThread(input: ProviderScope & { threadId: string }): Promise<NormalizedThread>;
  searchMessages(input: ProviderScope & { query: string }): Promise<NormalizedMessage[]>;
  retrieveAttachments(
    input: ProviderScope & { messageId: string },
  ): Promise<NormalizedAttachment[]>;
  createDraft(input: ProviderDraftInput): Promise<ProviderDraftReceipt>;
  updateDraft(
    input: ProviderDraftInput & { providerDraftId: string },
  ): Promise<ProviderDraftReceipt>;
  verifyDraftExists(input: ProviderReadbackInput): Promise<ProviderReadbackReceipt>;
  verifyMessageState(input: ProviderScope & { messageId: string }): Promise<unknown>;
  moveOrLabel(
    input: ProviderScope & { messageId: string; destination: string },
  ): Promise<void>;
  subscribeToChanges(input: ProviderScope): Promise<unknown>;
  revokeConnection(input: ProviderScope): Promise<void>;
  healthCheck(input: ProviderScope): Promise<unknown>;
}

export class ProviderCapabilityUnavailableError extends Error {
  constructor(
    readonly operation: ProviderOperation,
    reason: string,
  ) {
    super(`${operation}: capability unavailable (${reason})`);
    this.name = "ProviderCapabilityUnavailableError";
  }
}

export type MessageProviderHandlers = Partial<{
  list_messages: (input: ProviderScope) => Promise<unknown>;
  read_message: (
    input: ProviderScope & { messageId: string },
  ) => Promise<unknown>;
  read_thread: (
    input: ProviderScope & { threadId: string },
  ) => Promise<unknown>;
  search_messages: (
    input: ProviderScope & { query: string },
  ) => Promise<unknown>;
  retrieve_attachments: (
    input: ProviderScope & { messageId: string },
  ) => Promise<unknown>;
  create_provider_draft: (input: ProviderDraftInput) => Promise<unknown>;
  update_provider_draft: (
    input: ProviderDraftInput & { providerDraftId: string },
  ) => Promise<unknown>;
  verify_draft_exists: (input: ProviderReadbackInput) => Promise<unknown>;
  verify_message_state: (
    input: ProviderScope & { messageId: string },
  ) => Promise<unknown>;
  move_or_label: (
    input: ProviderScope & { messageId: string; destination: string },
  ) => Promise<unknown>;
  subscribe_to_changes: (input: ProviderScope) => Promise<unknown>;
  revoke_connection: (input: ProviderScope) => Promise<unknown>;
  health_check: (input: ProviderScope) => Promise<unknown>;
}>;

type CapabilityEvidenceResolver = Parameters<
  typeof assertProviderCapabilitiesTrusted
>[2];

export function createCapabilityEnforcedMessageProvider(input: {
  capabilities: unknown;
  handlers: MessageProviderHandlers;
  now: () => number;
  resolveCapabilityEvidence: CapabilityEvidenceResolver;
  resolveReadbackReceipt: Parameters<typeof verifyProviderReadbackReceipt>[2];
  resolveActorAuthority: Parameters<typeof verifyProviderReadbackReceipt>[3];
}): MessageProvider {
  function assertScope<T extends { tenantId: string; workspaceId: string; userId: string }>(
    scope: ProviderScope,
    value: T,
  ): T {
    if (
      value.tenantId !== scope.tenantId ||
      value.workspaceId !== scope.workspaceId ||
      value.userId !== scope.userId
    ) {
      throw new Error("provider result is not bound to the requested scope");
    }
    return value;
  }

  function assertDraftBinding(
    request: ProviderDraftInput,
    raw: unknown,
  ): ProviderDraftReceipt {
    const receipt = Wave1ProviderDraftReceiptSchema.parse(raw);
    const provider = receipt.providerReceipt;
    if (
      receipt.tenantId !== request.tenantId ||
      receipt.workspaceId !== request.workspaceId ||
      receipt.userId !== request.userId ||
      receipt.taskId !== request.taskId ||
      receipt.requestId !== request.requestId ||
      receipt.idempotencyKey !== request.idempotencyKey ||
      receipt.authorizationId !== request.authorizationId ||
      receipt.approvalId !== request.approvalId ||
      receipt.qualityBundleId !== request.qualityBundleId ||
      receipt.recipientDigest !== request.recipientDigest ||
      receipt.verifiedEnvelopeDigest !== request.verifiedEnvelopeDigest ||
      provider.connectionId !== request.connectionId ||
      provider.threadId !== request.threadId ||
      provider.contextDigest !== request.contextDigest ||
      provider.candidateDigest !== request.candidateDigest ||
      provider.capabilityCandidateDigest !== request.capabilityCandidateDigest
    ) {
      throw new Error("provider draft receipt is not bound to the requested operation");
    }
    return receipt;
  }

  function capabilities(): ProviderCapabilities {
    return assertProviderCapabilitiesTrusted(
      input.capabilities,
      input.now(),
      input.resolveCapabilityEvidence,
    );
  }

  async function invoke<T>(
    operation: HandlerOperation,
    operationInput: unknown,
    parse: (raw: unknown) => T,
  ): Promise<T> {
    const declaration = capabilities().operations.find(
      (entry) => entry.operation === operation,
    );
    if (!declaration?.supported) {
      throw new ProviderCapabilityUnavailableError(
        operation,
        declaration?.reason ?? "operation is not declared",
      );
    }
    const handler = input.handlers[operation] as
      | ((value: unknown) => Promise<unknown>)
      | undefined;
    if (!handler) {
      throw new ProviderCapabilityUnavailableError(
        operation,
        "supported operation has no configured implementation",
      );
    }
    return parse(await handler(operationInput));
  }

  return {
    getCapabilities: capabilities,
    listMessages: (value) =>
      invoke("list_messages", value, (raw) =>
        NormalizedMessageSchema.array().parse(raw).map((item) => assertScope(value, item)),
      ),
    readMessage: (value) =>
      invoke("read_message", value, (raw) =>
        assertScope(value, NormalizedMessageSchema.parse(raw)),
      ),
    readThread: (value) =>
      invoke("read_thread", value, (raw) =>
        assertScope(value, NormalizedThreadSchema.parse(raw)),
      ),
    searchMessages: (value) =>
      invoke("search_messages", value, (raw) =>
        NormalizedMessageSchema.array().parse(raw).map((item) => assertScope(value, item)),
      ),
    retrieveAttachments: (value) =>
      invoke("retrieve_attachments", value, (raw) =>
        NormalizedAttachmentSchema.array().parse(raw),
      ),
    createDraft: (value) =>
      invoke("create_provider_draft", value, (raw) => assertDraftBinding(value, raw)),
    updateDraft: (value) =>
      invoke("update_provider_draft", value, (raw) => assertDraftBinding(value, raw)),
    verifyDraftExists: (value) =>
      invoke("verify_draft_exists", value, (raw) => {
        const verified = verifyProviderReadbackReceipt(
          raw,
          input.now(),
          input.resolveReadbackReceipt,
          input.resolveActorAuthority,
        );
        if (
          JSON.stringify(verified.providerDraftReceipt) !==
          JSON.stringify(value.providerDraftReceipt)
        ) {
          throw new Error("provider read-back is not bound to the requested draft");
        }
        return assertScope(value, verified);
      }),
    verifyMessageState: (value) =>
      invoke("verify_message_state", value, (raw) => raw),
    moveOrLabel: (value) =>
      invoke("move_or_label", value, () => undefined),
    subscribeToChanges: (value) =>
      invoke("subscribe_to_changes", value, (raw) => raw),
    revokeConnection: (value) =>
      invoke("revoke_connection", value, () => undefined),
    healthCheck: (value) => invoke("health_check", value, (raw) => raw),
  };
}

export function createGmailMessageProvider(
  input: Parameters<typeof createCapabilityEnforcedMessageProvider>[0],
): MessageProvider {
  const parsed = ProviderCapabilitiesV2Schema.parse(input.capabilities);
  if (parsed.providerFamily !== "gmail_api") {
    throw new Error("Gmail provider requires providerFamily gmail_api");
  }
  return createCapabilityEnforcedMessageProvider(input);
}
