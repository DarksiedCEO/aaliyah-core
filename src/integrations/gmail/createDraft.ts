export async function createGmailDraft(
  rawMessage: string,
  accessToken: string,
): Promise<string> {
  const encoded = Buffer.from(rawMessage)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const res = await fetch(
    "https://gmail.googleapis.com/gmail/v1/users/me/drafts",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: { raw: encoded },
      }),
    },
  );

  if (!res.ok) {
    throw new Error("Draft creation failed");
  }

  const data = (await res.json()) as { id?: string };

  if (!data.id) {
    throw new Error("Draft creation failed");
  }

  return data.id;
}
