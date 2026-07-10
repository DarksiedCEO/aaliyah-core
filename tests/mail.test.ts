import assert from "node:assert/strict";
import test from "node:test";

import type { ConnectMailboxInput } from "@aaliyah/contracts/v1";

import { detectProvider } from "../src/mail/autodetect";
import { MailProviderRegistry } from "../src/mail/mailProviderRegistry";
import { GoogleMailAdapter } from "../src/mail/adapters/googleMailAdapter";
import { MicrosoftGraphAdapter } from "../src/mail/adapters/microsoftGraphAdapter";
import {
  createGenericImapSmtpAdapter,
  createYahooMailAdapter,
} from "../src/mail/adapters/transportBackedAdapter";
import { MailTransportNotConfiguredError } from "../src/mail/types";

const NOW = () => "2026-06-23T12:00:00.000Z";

function fakeFetch(routes: { match: RegExp; status?: number; body?: unknown }[]): typeof fetch {
  const calls: { url: string; init?: RequestInit }[] = [];
  const impl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, ...(init ? { init } : {}) });
    const route = routes.find((r) => r.match.test(url));
    const status = route?.status ?? 200;
    return {
      ok: status < 400,
      status,
      json: async () => route?.body ?? {},
    } as Response;
  }) as unknown as typeof fetch;
  (impl as unknown as { calls: typeof calls }).calls = calls;
  return impl;
}

function connectInput(over: Partial<ConnectMailboxInput> = {}): ConnectMailboxInput {
  return {
    tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "u1",
    provider: "google", emailAddress: "sales@pussycatalley.com",
    oauth: { accessToken: "tok" },
    ...over,
  } as ConnectMailboxInput;
}

test("autodetect routes emails to the right provider", () => {
  assert.equal(detectProvider("a@gmail.com").provider, "google");
  assert.equal(detectProvider("a@outlook.com").provider, "microsoft");
  assert.equal(detectProvider("a@hotmail.com").provider, "microsoft");
  assert.equal(detectProvider("a@yahoo.com").provider, "yahoo");

  // Known hosted domain -> imap_smtp, fully auto-configured.
  const zoho = detectProvider("a@zoho.com");
  assert.equal(zoho.provider, "imap_smtp");
  assert.equal(zoho.autoConfigured, true);
  assert.ok(zoho.imap && zoho.smtp);

  // Unknown custom domain -> imap_smtp, needs Advanced setup.
  const custom = detectProvider("a@some-company.dev");
  assert.equal(custom.provider, "imap_smtp");
  assert.equal(custom.autoConfigured, false);
});

test("registry exposes all four providers with honest capability flags", () => {
  const caps = new MailProviderRegistry().capabilities();
  assert.equal(caps.length, 4);
  // Nothing claims to be end-to-end verified yet — honesty by construction.
  assert.ok(caps.every((c) => c.verified === false));
  // Yahoo + generic IMAP do not claim applyLabel.
  assert.equal(caps.find((c) => c.provider === "yahoo")!.applyLabel, false);
  assert.equal(caps.find((c) => c.provider === "imap_smtp")!.applyLabel, false);
});

test("Google adapter creates a draft and reads a thread via the normalized commands", async () => {
  const fetchImpl = fakeFetch([
    { match: /\/drafts$/, body: { id: "draft_1", message: { threadId: "th_1" } } },
    {
      match: /\/threads\/th_1/,
      body: {
        id: "th_1",
        messages: [
          {
            id: "m1", threadId: "th_1", snippet: "hello", internalDate: "1700000000000",
            payload: { headers: [{ name: "From", value: "Client <c@example.com>" }, { name: "Subject", value: "Hi" }] },
          },
        ],
      },
    },
  ]);
  const adapter = new GoogleMailAdapter({ fetchImpl, resolveAccessToken: () => "tok", now: NOW });

  const draft = await adapter.createDraft({
    connectionId: "c1", to: [{ email: "c@example.com" }], subject: "Re: Hi", body: "Thanks",
  });
  assert.equal(draft.draftId, "draft_1");
  assert.equal(draft.threadId, "th_1");

  const thread = await adapter.readThread({ connectionId: "c1", threadId: "th_1" });
  assert.equal(thread.messages[0]!.from.email, "c@example.com");
  assert.equal(thread.messages[0]!.subject, "Hi");
});

test("Microsoft adapter groups messages into threads by conversationId", async () => {
  const fetchImpl = fakeFetch([
    {
      match: /\/messages\?\$top/,
      body: {
        value: [
          { id: "m1", conversationId: "conv_1", subject: "A", receivedDateTime: "2026-06-23T10:00:00Z", from: { emailAddress: { address: "x@e.com" } } },
          { id: "m2", conversationId: "conv_1", subject: "A", receivedDateTime: "2026-06-23T11:00:00Z", from: { emailAddress: { address: "x@e.com" } } },
          { id: "m3", conversationId: "conv_2", subject: "B", receivedDateTime: "2026-06-23T12:00:00Z", from: { emailAddress: { address: "y@e.com" } } },
        ],
      },
    },
  ]);
  const adapter = new MicrosoftGraphAdapter({ fetchImpl, resolveAccessToken: () => "tok", now: NOW });
  const threads = await adapter.listThreads({ connectionId: "c1", limit: 25 });
  assert.equal(threads.length, 2); // two conversations, not three messages
});

test("NO AUTO-SEND: sendMessage is refused without a valid approval token", async () => {
  const fetchImpl = fakeFetch([{ match: /\/messages\/send/, body: { id: "sent_1" } }]);
  // Approval oracle rejects everything (simulating no human approval).
  const adapter = new GoogleMailAdapter({
    fetchImpl, resolveAccessToken: () => "tok", now: NOW, isSendApproved: () => false,
  });
  await assert.rejects(
    () => adapter.sendMessage({ connectionId: "c1", approvalToken: "forged", to: [{ email: "c@e.com" }], subject: "x", body: "y" }),
    /Refusing to send/,
  );
});

test("send succeeds only with a human-approved token", async () => {
  const fetchImpl = fakeFetch([{ match: /\/messages\/send/, body: { id: "sent_1", threadId: "th_1" } }]);
  const adapter = new GoogleMailAdapter({
    fetchImpl, resolveAccessToken: () => "tok", now: NOW,
    isSendApproved: (_c, t) => t === "human-approved",
  });
  const sent = await adapter.sendMessage({
    connectionId: "c1", approvalToken: "human-approved", to: [{ email: "c@e.com" }], subject: "x", body: "y",
  });
  assert.equal(sent.messageId, "sent_1");
});

test("IMAP/SMTP + Yahoo connect but fail loud without a verified transport (no faking)", async () => {
  const generic = createGenericImapSmtpAdapter({ deps: { now: NOW } });
  const conn = await generic.connect(
    connectInput({ provider: "imap_smtp", oauth: undefined, password: "app-password", emailAddress: "me@zoho.com" }),
  );
  assert.equal(conn.authKind, "password");

  // verify reports unhealthy with an explicit reason.
  const health = await generic.verify(conn.connectionId);
  assert.equal(health.healthy, false);
  assert.match(health.detail ?? "", /no verified transport/);

  // Real mail ops refuse rather than pretend.
  await assert.rejects(
    () => generic.listThreads({ connectionId: conn.connectionId, limit: 10 }),
    (e: unknown) => e instanceof MailTransportNotConfiguredError,
  );

  const yahoo = createYahooMailAdapter({ deps: { now: NOW } });
  assert.equal(yahoo.capabilities.verified, false);
});

test("registry resolves the adapter straight from an email address", () => {
  const registry = new MailProviderRegistry();
  assert.equal(registry.forEmail("x@gmail.com").adapter.provider, "google");
  assert.equal(registry.forEmail("x@outlook.com").adapter.provider, "microsoft");
  assert.equal(registry.forEmail("x@customhost.io").adapter.provider, "imap_smtp");
});
