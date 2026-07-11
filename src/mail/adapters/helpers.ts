import {
  MailboxConnectionSchema,
  type ConnectMailboxInput,
  type MailAuthKind,
  type MailboxConnection,
} from "@aaliyah/contracts/v1";

export type AdapterDeps = {
  fetchImpl?: typeof fetch;
  /** Resolve the OAuth access token for a connection (secrets stay external). */
  resolveAccessToken?: (connectionId: string) => string;
  now?: () => string;
};

export function connectionIdFor(input: {
  tenantId: string;
  workspaceId: string;
  userId: string;
  provider: string;
  emailAddress: string;
}): string {
  return `${input.tenantId}:${input.workspaceId}:${input.userId}:${input.provider}:${input.emailAddress}`;
}

export function makeConnection(
  input: ConnectMailboxInput,
  authKind: MailAuthKind,
  now: () => string,
): MailboxConnection {
  return MailboxConnectionSchema.parse({
    connectionId: connectionIdFor(input),
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    provider: input.provider,
    emailAddress: input.emailAddress,
    authKind,
    status: "connected",
    connectedAt: now(),
  });
}

export function buildRawRfc822(input: {
  to: string;
  subject: string;
  body: string;
  inReplyTo?: string;
}): string {
  const headers = [
    `To: ${input.to}`,
    `Subject: ${input.subject}`,
    ...(input.inReplyTo
      ? [`In-Reply-To: ${input.inReplyTo}`, `References: ${input.inReplyTo}`]
      : []),
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    input.body,
  ];
  return headers.join("\r\n");
}

export function base64url(value: string): string {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
