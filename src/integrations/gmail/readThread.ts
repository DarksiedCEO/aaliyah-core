export type GmailThreadMessage = {
  id?: string | null;
  threadId?: string | null;
  snippet?: string | null;
  internalDate?: string | null;
  payload?: {
    headers?: Array<{
      name?: string | null;
      value?: string | null;
    }> | null;
  } | null;
};

export type GmailThread = {
  id?: string | null;
  messages?: GmailThreadMessage[] | null;
};

export async function readGmailThread(
  threadId: string,
  accessToken: string,
): Promise<GmailThread> {
  const res = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/threads/${threadId}`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  );

  if (!res.ok) {
    throw new Error("Gmail thread fetch failed");
  }

  return (await res.json()) as GmailThread;
}
