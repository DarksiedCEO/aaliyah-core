import assert from "node:assert/strict";
import test from "node:test";

import { ProviderOperationSchema } from "@aaliyah/contracts/v1";

import {
  ProviderCapabilityUnavailableError,
  createCapabilityEnforcedMessageProvider,
  createGmailMessageProvider,
} from "../src/application/executive/messageProvider";

const NOW_ISO = "2026-07-26T10:02:00.000Z";
const NOW = Date.parse(NOW_ISO);
const DIGEST = `sha256:${"a".repeat(64)}`;
const EVIDENCE = {
  evidenceRef: "audit:provider-capability-1",
  evidenceDigest: DIGEST,
  observedAt: "2026-07-26T10:00:01.000Z",
  freshUntil: "2026-07-26T11:00:00.000Z",
};

function capabilities(supported: string[] = []) {
  const flags = {
    supportsThreads: supported.includes("read_thread"),
    supportsNativeDrafts: supported.includes("create_provider_draft"),
    supportsDraftReadback: supported.includes("verify_draft_exists"),
    supportsPushChanges: supported.includes("subscribe_to_changes"),
    supportsLabels: supported.includes("move_or_label"),
    supportsFolders: false,
    supportsAttachments: supported.includes("retrieve_attachments"),
    supportsMessageMutation: supported.includes("verify_message_state"),
    supportsOAuth: false,
    supportsServiceAccounts: false,
    supportsSharedMailboxes: false,
    supportsIdempotencyKey:
      supported.includes("create_provider_draft") &&
      supported.includes("update_provider_draft"),
    supportsCustomHeaders: false,
  };
  return {
    providerFamily: "gmail_api",
    adapterId: "gmail.adapter",
    adapterVersion: "1",
    flags,
    flagEvidence: Object.fromEntries(
      Object.entries(flags)
        .filter(([, value]) => value)
        .map(([flag]) => [flag, EVIDENCE]),
    ),
    operations: ProviderOperationSchema.options.map((operation) =>
      supported.includes(operation)
        ? {
            operation,
            supported: true as const,
            tier: "locally_verified" as const,
            evidence: EVIDENCE,
          }
        : {
            operation,
            supported: false as const,
            tier: "designed" as const,
            reason: "not locally implemented",
          },
    ),
  };
}

function provider(
  supported: string[],
  handlers: Parameters<typeof createCapabilityEnforcedMessageProvider>[0]["handlers"] = {},
  overrides: Partial<Parameters<typeof createCapabilityEnforcedMessageProvider>[0]> = {},
) {
  return createCapabilityEnforcedMessageProvider({
    capabilities: capabilities(supported),
    handlers,
    now: () => NOW,
    resolveCapabilityEvidence: (subject) => ({ subject, evidence: EVIDENCE }),
    resolveReadbackReceipt: () => null,
    resolveActorAuthority: () => null,
    ...overrides,
  });
}

const SCOPE = {
  tenantId: "tenant-1",
  workspaceId: "workspace-1",
  userId: "user-1",
  connectionId: "connection-1",
};

test("every unsupported operation fails explicitly before any handler runs", async () => {
  let called = false;
  const handlers = Object.fromEntries(
    ProviderOperationSchema.options
      .filter((operation) => operation !== "get_capabilities")
      .map((operation) => [operation, async () => {
        called = true;
        return {};
      }]),
  );
  const p = provider([], handlers);
  const calls = [
    () => p.listMessages(SCOPE),
    () => p.readMessage({ ...SCOPE, messageId: "message-1" }),
    () => p.readThread({ ...SCOPE, threadId: "thread-1" }),
    () => p.searchMessages({ ...SCOPE, query: "query" }),
    () => p.retrieveAttachments({ ...SCOPE, messageId: "message-1" }),
    () => p.createDraft({ ...SCOPE } as never),
    () => p.updateDraft({ ...SCOPE } as never),
    () => p.verifyDraftExists({ ...SCOPE } as never),
    () => p.verifyMessageState({ ...SCOPE, messageId: "message-1" }),
    () => p.moveOrLabel({ ...SCOPE, messageId: "message-1", destination: "label" }),
    () => p.subscribeToChanges(SCOPE),
    () => p.revokeConnection(SCOPE),
    () => p.healthCheck(SCOPE),
  ];
  for (const call of calls) {
    await assert.rejects(call, ProviderCapabilityUnavailableError);
  }
  assert.equal(called, false);
});

test("supported declarations without implementations fail closed", async () => {
  const p = provider(["read_thread"]);
  await assert.rejects(
    () => p.readThread({ ...SCOPE, threadId: "thread-1" }),
    /no configured implementation/,
  );
});

test("capabilities are independently verified and rechecked for freshness", async () => {
  const caps = capabilities(["health_check"]);
  const p = provider(
    ["health_check"],
    { health_check: async () => ({ healthy: true }) },
    {
      capabilities: caps,
      resolveCapabilityEvidence: () => null,
    },
  );
  assert.throws(() => p.getCapabilities(), /unverified/);
  await assert.rejects(() => p.healthCheck(SCOPE), /unverified/);

  const stale = provider(
    ["health_check"],
    { health_check: async () => ({ healthy: true }) },
    { now: () => Date.parse("2026-07-27T10:02:00.000Z") },
  );
  await assert.rejects(() => stale.healthCheck(SCOPE), /stale/);
});

test("provider capabilities are immutable after construction", () => {
  const declared = capabilities();
  const p = createGmailMessageProvider({
    capabilities: declared,
    handlers: {},
    now: () => NOW,
    resolveCapabilityEvidence: (subject) => ({ subject, evidence: EVIDENCE }),
    resolveReadbackReceipt: () => null,
    resolveActorAuthority: () => null,
  });
  declared.providerFamily = "microsoft_graph" as never;
  assert.equal(p.getCapabilities().providerFamily, "gmail_api");
});

test("Gmail fabric preserves normalized thread parsing and exposes no send", async () => {
  const normalized = {
    contractVersion: "aaliyah.executive-communications/wave1",
    tenantId: "tenant-1",
    workspaceId: "workspace-1",
    userId: "user-1",
    taskId: "task-1",
    requestId: "request-1",
    idempotencyKey: "operation-1",
    thread: {
      contractVersion: "aaliyah.executive-messaging/v1",
      providerFamily: "gmail_api",
      connectionId: "connection-1",
      threadId: "thread-1",
      subject: "Subject",
      messages: [{
        messageId: "message-1",
        threadId: "thread-1",
        externalRef: "gmail:message:message-1",
        from: [{ email: "sender@example.com" }],
        to: [{ email: "ceo@example.com" }],
        cc: [],
        bcc: [],
        replyTo: [],
        subject: "Subject",
        receivedAt: "2026-07-26T10:00:00.000Z",
        timeZone: "UTC",
        textBody: {
          trust: "untrusted_content",
          value: "Hello",
          sourceRef: "gmail:message:message-1:body",
          observedAt: "2026-07-26T10:00:01.000Z",
          contentKind: "email_body",
        },
        attachments: [],
      }],
      readReceipt: {
        receiptId: "read-1",
        adapterId: "gmail.adapter",
        connectionId: "connection-1",
        externalRefs: ["gmail:message:message-1"],
        observedAt: "2026-07-26T10:00:01.000Z",
        freshUntil: "2026-07-26T10:05:00.000Z",
      },
    },
    completeness: "complete",
    participants: [
      { participantId: "sender-1", canonicalAddress: "sender@example.com", aliases: [], resolution: "unresolved" },
      { participantId: "ceo-1", canonicalAddress: "ceo@example.com", aliases: [], resolution: "unresolved" },
    ],
  };
  const makeProvider = (result: unknown) => createGmailMessageProvider({
      capabilities: capabilities(["read_thread"]),
      handlers: { read_thread: async () => result },
      now: () => NOW,
      resolveCapabilityEvidence: (subject) => ({ subject, evidence: EVIDENCE }),
      resolveReadbackReceipt: () => null,
      resolveActorAuthority: () => null,
    });
  const p = makeProvider(normalized);
  assert.equal(
    (await p.readThread({ ...SCOPE, threadId: "thread-1" })).thread.threadId,
    "thread-1",
  );
  assert.equal("send" in p, false);
  assert.equal("sendMessage" in p, false);
  for (const changedThread of [
    { ...normalized.thread, connectionId: "other-connection" },
    { ...normalized.thread, threadId: "other-thread", messages: normalized.thread.messages.map((message) => ({ ...message, threadId: "other-thread" })) },
    { ...normalized.thread, providerFamily: "microsoft_graph" },
    { ...normalized.thread, readReceipt: { ...normalized.thread.readReceipt, adapterId: "other.adapter" } },
  ]) {
    await assert.rejects(
      () => makeProvider({ ...normalized, thread: changedThread }).readThread({
        ...SCOPE,
        threadId: "thread-1",
      }),
    );
  }
});

test("Gmail factory rejects another provider family", () => {
  assert.throws(() =>
    createGmailMessageProvider({
      capabilities: { ...capabilities(), providerFamily: "microsoft_graph" },
      handlers: {},
      now: () => NOW,
      resolveCapabilityEvidence: () => null,
      resolveReadbackReceipt: () => null,
      resolveActorAuthority: () => null,
    }),
  );
});

test("normalized reads reject a valid artifact from another tenant", async () => {
  const p = provider(
    ["read_thread"],
    {
      read_thread: async () => ({
        contractVersion: "aaliyah.executive-communications/wave1",
        tenantId: "other-tenant",
        workspaceId: "workspace-1",
        userId: "user-1",
        taskId: "task-1",
        requestId: "request-1",
        idempotencyKey: "operation-1",
        thread: {
          contractVersion: "aaliyah.executive-messaging/v1",
          providerFamily: "gmail_api",
          connectionId: "connection-1",
          threadId: "thread-1",
          subject: "Subject",
          messages: [{
            messageId: "message-1",
            threadId: "thread-1",
            externalRef: "gmail:message:message-1",
            from: [{ email: "sender@example.com" }],
            to: [],
            cc: [],
            bcc: [],
            replyTo: [],
            subject: "Subject",
            receivedAt: "2026-07-26T10:00:00.000Z",
            timeZone: "UTC",
            attachments: [],
          }],
          readReceipt: {
            receiptId: "read-1",
            adapterId: "gmail.adapter",
            connectionId: "connection-1",
            externalRefs: ["gmail:message:message-1"],
            observedAt: "2026-07-26T10:00:01.000Z",
            freshUntil: "2026-07-26T10:05:00.000Z",
          },
        },
        completeness: "complete",
        participants: [{
          participantId: "sender-1",
          canonicalAddress: "sender@example.com",
          aliases: [],
          resolution: "unresolved",
        }],
      }),
    },
  );
  await assert.rejects(
    () => p.readThread({ ...SCOPE, threadId: "thread-1" }),
    /not bound to the requested scope/,
  );
});

test("point-message and attachment results require exact provider envelopes", async () => {
  const normalizedMessage = {
    contractVersion: "aaliyah.executive-communications/wave1",
    tenantId: "tenant-1",
    workspaceId: "workspace-1",
    userId: "user-1",
    taskId: "task-1",
    requestId: "request-1",
    idempotencyKey: "operation-1",
    providerFamily: "gmail_api",
    message: {
      messageId: "message-1",
      threadId: "thread-1",
      externalRef: "gmail:message:message-1",
      from: [{ email: "sender@example.com" }],
      to: [],
      cc: [],
      bcc: [],
      replyTo: [],
      subject: "Subject",
      receivedAt: "2026-07-26T10:00:00.000Z",
      timeZone: "UTC",
      attachments: [],
    },
    participants: [{
      participantId: "sender-1",
      canonicalAddress: "sender@example.com",
      aliases: [],
      resolution: "unresolved",
    }],
  };
  const messageEnvelope = {
    connectionId: "connection-1",
    providerFamily: "gmail_api",
    adapterId: "gmail.adapter",
    message: normalizedMessage,
  };
  for (const mutation of [
    { connectionId: "other-connection" },
    { providerFamily: "microsoft_graph" },
    { adapterId: "other.adapter" },
    { message: {
      ...normalizedMessage,
      message: { ...normalizedMessage.message, messageId: "other-message" },
    } },
  ]) {
    const p = provider(
      ["read_message"],
      { read_message: async () => ({ ...messageEnvelope, ...mutation }) },
    );
    await assert.rejects(() =>
      p.readMessage({ ...SCOPE, messageId: "message-1" }),
    );
  }

  for (const operation of ["list_messages", "search_messages"] as const) {
    const p = provider(
      [operation],
      {
        [operation]: async () => ({
          connectionId: "connection-1",
          providerFamily: "gmail_api",
          adapterId: "gmail.adapter",
          messages: [{
            ...normalizedMessage,
            providerFamily: "microsoft_graph",
          }],
        }),
      },
    );
    await assert.rejects(() =>
      operation === "list_messages"
        ? p.listMessages(SCOPE)
        : p.searchMessages({ ...SCOPE, query: "query" }),
    );
  }

  assert.throws(
    () => provider(["retrieve_attachments"]),
    /no independently verifiable attachment retrieval receipt/,
  );
});

test("draft read-back requires an exact independently persisted receipt", async () => {
  const providerReceipt = {
    receiptId: "provider-receipt",
    adapterId: "gmail.adapter",
    connectionId: "connection-1",
    tenantId: "tenant-1",
    workspaceId: "workspace-1",
    userId: "user-1",
    requestId: "request-1",
    taskId: "task-1",
    threadId: "thread-1",
    contextDigest: DIGEST,
    providerDraftId: "draft-1",
    candidateDigest: DIGEST,
    capabilityCandidateDigest: DIGEST,
    createdAt: "2026-07-26T10:01:00.000Z",
  };
  const draftReceipt = {
    contractVersion: "aaliyah.executive-communications/wave1",
    tenantId: "tenant-1",
    workspaceId: "workspace-1",
    userId: "user-1",
    taskId: "task-1",
    requestId: "request-1",
    idempotencyKey: "operation-1",
    authorizationId: "authorization-1",
    recipientDigest: DIGEST,
    approvalId: "approval-1",
    qualityBundleId: "quality-1",
    verifiedEnvelopeDigest: DIGEST,
    providerReceipt,
  };
  const draftInput = {
    ...SCOPE,
    taskId: "task-1",
    requestId: "request-1",
    threadId: "thread-1",
    idempotencyKey: "operation-1",
    recipientDigest: DIGEST,
    candidateDigest: DIGEST,
    contextDigest: DIGEST,
    capabilityCandidateDigest: DIGEST,
    authorizationId: "authorization-1",
    approvalId: "approval-1",
    qualityBundleId: "quality-1",
    verifiedEnvelopeDigest: DIGEST,
    to: [{ email: "recipient@example.com" }],
    cc: [],
    bcc: [],
    subject: "Subject",
    body: "Body",
  };
  const draftWriter = provider(
    ["create_provider_draft", "update_provider_draft"],
    {
      create_provider_draft: async () => ({
        ...draftReceipt,
        providerReceipt: { ...providerReceipt, adapterId: "other.adapter" },
      }),
      update_provider_draft: async () => draftReceipt,
    },
  );
  await assert.rejects(
    () => draftWriter.createDraft(draftInput),
    /not bound to the requested operation/,
  );
  const successfulWriter = provider(
    ["create_provider_draft", "update_provider_draft"],
    {
      create_provider_draft: async () => draftReceipt,
      update_provider_draft: async () => draftReceipt,
    },
  );
  assert.equal(
    (await successfulWriter.createDraft(draftInput)).providerReceipt.providerDraftId,
    "draft-1",
  );
  assert.equal(
    (await successfulWriter.updateDraft({
      ...draftInput,
      providerDraftId: "draft-1",
    })).providerReceipt.providerDraftId,
    "draft-1",
  );
  await assert.rejects(
    () => draftWriter.updateDraft({
      ...draftInput,
      providerDraftId: "different-draft",
    }),
    /not bound to the requested operation/,
  );
  const receiptMutations = [
    { tenantId: "other" },
    { workspaceId: "other" },
    { userId: "other" },
    { taskId: "other" },
    { requestId: "other" },
    { idempotencyKey: "other" },
    { authorizationId: "other" },
    { approvalId: "other" },
    { qualityBundleId: "other" },
    { recipientDigest: `sha256:${"b".repeat(64)}` },
    { verifiedEnvelopeDigest: `sha256:${"b".repeat(64)}` },
    { providerReceipt: { ...providerReceipt, connectionId: "other" } },
    { providerReceipt: { ...providerReceipt, adapterId: "other.adapter" } },
    { providerReceipt: { ...providerReceipt, threadId: "other" } },
    { providerReceipt: { ...providerReceipt, contextDigest: `sha256:${"b".repeat(64)}` } },
    { providerReceipt: { ...providerReceipt, candidateDigest: `sha256:${"b".repeat(64)}` } },
    { providerReceipt: { ...providerReceipt, capabilityCandidateDigest: `sha256:${"b".repeat(64)}` } },
  ];
  for (const mutation of receiptMutations) {
    const writer = provider(
      ["create_provider_draft", "update_provider_draft"],
      {
        create_provider_draft: async () => ({ ...draftReceipt, ...mutation }),
        update_provider_draft: async () => ({ ...draftReceipt, ...mutation }),
      },
    );
    await assert.rejects(() => writer.createDraft(draftInput));
    await assert.rejects(() =>
      writer.updateDraft({ ...draftInput, providerDraftId: "draft-1" }),
    );
  }
  const readback = {
    contractVersion: "aaliyah.executive-communications/wave1",
    tenantId: "tenant-1",
    workspaceId: "workspace-1",
    userId: "user-1",
    taskId: "task-1",
    requestId: "request-1",
    idempotencyKey: "operation-1",
    receiptId: "readback-1",
    providerDraftReceipt: draftReceipt,
    verifierActorId: "provider.readback",
    verifierMethod: "independent_provider_read",
    providerDraftId: "draft-1",
    adapterId: "gmail.adapter",
    connectionId: "connection-1",
    threadId: "thread-1",
    contextDigest: DIGEST,
    candidateDigest: DIGEST,
    capabilityCandidateDigest: DIGEST,
    observedAt: "2026-07-26T10:01:30.000Z",
    freshUntil: "2026-07-26T10:05:00.000Z",
    matched: true,
  };
  let persisted: unknown = readback;
  const p = provider(
    ["verify_draft_exists"],
    { verify_draft_exists: async () => readback },
    {
      resolveReadbackReceipt: () => persisted as never,
      resolveActorAuthority: (actorId) =>
        actorId === "gmail.adapter" ? "draft-writer" : "draft-reader",
    },
  );
  assert.equal(
    (await p.verifyDraftExists({ ...SCOPE, providerDraftReceipt: draftReceipt as never }))
      .providerDraftId,
    "draft-1",
  );
  const otherDraft = {
    ...draftReceipt,
    providerReceipt: {
      ...providerReceipt,
      providerDraftId: "draft-2",
    },
  };
  const otherReadback = {
    ...readback,
    receiptId: "readback-2",
    providerDraftId: "draft-2",
    providerDraftReceipt: otherDraft,
  };
  persisted = otherReadback;
  const mismatched = provider(
    ["verify_draft_exists"],
    { verify_draft_exists: async () => otherReadback },
    {
      resolveReadbackReceipt: () => persisted as never,
      resolveActorAuthority: (actorId) =>
        actorId === "gmail.adapter" ? "draft-writer" : "draft-reader",
    },
  );
  await assert.rejects(
    () => mismatched.verifyDraftExists({
      ...SCOPE,
      providerDraftReceipt: draftReceipt as never,
    }),
    /not bound to the requested draft/,
  );
  persisted = null;
  await assert.rejects(
    () => p.verifyDraftExists({ ...SCOPE, providerDraftReceipt: draftReceipt as never }),
    /not independently verified/,
  );

  const sameAuthority = provider(
    ["verify_draft_exists"],
    { verify_draft_exists: async () => readback },
    {
      resolveReadbackReceipt: () => readback as never,
      resolveActorAuthority: () => "shared-authority",
    },
  );
  await assert.rejects(() =>
    sameAuthority.verifyDraftExists({
      ...SCOPE,
      providerDraftReceipt: draftReceipt as never,
    }),
  );

  const stale = provider(
    ["verify_draft_exists"],
    { verify_draft_exists: async () => readback },
    {
      now: () => Date.parse("2026-07-26T11:00:00.000Z"),
      resolveReadbackReceipt: () => readback as never,
      resolveActorAuthority: (actorId) =>
        actorId === "gmail.adapter" ? "draft-writer" : "draft-reader",
    },
  );
  await assert.rejects(() =>
    stale.verifyDraftExists({
      ...SCOPE,
      providerDraftReceipt: draftReceipt as never,
    }),
  );
  const futureReadback = {
    ...readback,
    observedAt: "2026-07-26T10:03:00.000Z",
    freshUntil: "2026-07-26T10:05:00.000Z",
  };
  const future = provider(
    ["verify_draft_exists"],
    { verify_draft_exists: async () => futureReadback },
    {
      resolveReadbackReceipt: () => futureReadback as never,
      resolveActorAuthority: (actorId) =>
        actorId === "gmail.adapter" ? "draft-writer" : "draft-reader",
    },
  );
  await assert.rejects(() =>
    future.verifyDraftExists({
      ...SCOPE,
      providerDraftReceipt: draftReceipt as never,
    }),
  );
});
