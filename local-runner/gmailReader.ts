import type { InboundEmail } from "@aaliyah/contracts/v1";
import type { MailSignals } from "../src/application/executive/triage";

/**
 * Read-only Gmail helper for the local runner.
 *
 * Reading is not the safety-critical surface — drafting and (never) sending stay
 * on the verified adapter/core path. This helper only pulls enough of a thread to
 * hand the core a well-formed InboundEmail: the latest message NOT written by the
 * operator, with a decoded plain-text body. It creates nothing and mutates
 * nothing.
 */

const GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me";

type GmailHeader = { name?: string; value?: string };
type GmailPart = {
  mimeType?: string;
  headers?: GmailHeader[];
  body?: { data?: string; size?: number };
  parts?: GmailPart[];
};
type GmailMessage = {
  id?: string;
  threadId?: string;
  internalDate?: string;
  snippet?: string;
  payload?: GmailPart;
};

function header(headers: GmailHeader[] | undefined, name: string): string {
  return (
    headers?.find((h) => (h.name ?? "").toLowerCase() === name.toLowerCase())?.value ?? ""
  );
}

/** Parse the bare address out of a `Name <addr@host>` (or bare) From header. */
function parseAddress(from: string): string | null {
  const angled = from.match(/<([^>]+)>/);
  const candidate = (angled?.[1] ?? from).trim().toLowerCase();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(candidate) ? candidate : null;
}

/** Depth-first search for the first text/plain body; fall back to stripped HTML. */
function extractBody(part: GmailPart | undefined): string {
  if (!part) return "";
  const decode = (data: string): string => Buffer.from(data, "base64url").toString("utf8");

  if (part.mimeType === "text/plain" && part.body?.data) {
    return decode(part.body.data);
  }
  for (const child of part.parts ?? []) {
    const found = extractBody(child);
    if (found.trim().length > 0) return found;
  }
  if (part.mimeType === "text/html" && part.body?.data) {
    return decode(part.body.data)
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/\s+\n/g, "\n")
      .trim();
  }
  return "";
}

/** Derive bulk-mail signals from a message's raw headers. Pure and total: missing
 * or undefined headers resolve to `false` rather than throwing. */
export function extractMailSignals(headers: GmailHeader[] | undefined): MailSignals {
  const has = (n: string) => (headers ?? []).some((h) => (h.name ?? "").toLowerCase() === n.toLowerCase());
  const precedence = (headers ?? []).find((h) => (h.name ?? "").toLowerCase() === "precedence")?.value ?? "";
  return { listUnsubscribe: has("List-Unsubscribe"), precedenceBulk: /bulk|list|junk/i.test(precedence) };
}

async function getThread(
  fetchImpl: typeof fetch,
  token: string,
  threadId: string,
): Promise<GmailMessage[]> {
  const res = await fetchImpl(`${GMAIL}/threads/${threadId}?format=full`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`gmail: read thread failed (${res.status})`);
  const data = (await res.json()) as { messages?: GmailMessage[] };
  return data.messages ?? [];
}

/**
 * Build an InboundEmail from the most recent message in a thread that the
 * operator did not write. Returns null when the thread has no inbound message to
 * reply to (e.g. a thread the operator started and nobody answered).
 */
export async function readLatestInbound(
  token: string,
  threadId: string,
  ownerEmail: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ email: InboundEmail; signals: MailSignals } | null> {
  const messages = await getThread(fetchImpl, token, threadId);
  const owner = ownerEmail.trim().toLowerCase();

  // Latest first — the newest message that isn't from the operator is what a
  // reply would answer.
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const msg = messages[i];
    if (!msg) continue;
    const headers = msg.payload?.headers;
    const fromEmail = parseAddress(header(headers, "From"));
    if (!fromEmail || fromEmail === owner) continue;

    const body = extractBody(msg.payload).trim() || (msg.snippet ?? "").trim();
    const receivedAt = msg.internalDate
      ? new Date(Number(msg.internalDate)).toISOString()
      : new Date().toISOString();
    // Prefer the RFC822 Message-ID (stable, threads correctly); fall back to the
    // Gmail message id so the idempotency key is always present.
    const rfcId = header(headers, "Message-ID").trim();
    const toEmail = parseAddress(header(headers, "To"));
    const signals = extractMailSignals(headers);

    return {
      email: {
        messageId: rfcId || msg.id || threadId,
        threadId,
        fromEmail,
        ...(toEmail ? { toEmail } : {}),
        subject: header(headers, "Subject"),
        body,
        receivedAt,
      },
      signals,
    };
  }
  return null;
}
