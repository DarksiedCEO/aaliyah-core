import crypto from "node:crypto";

import type { MailAddress } from "@aaliyah/contracts/v1";

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

/** Order-independent hash of the recipient set. */
export function recipientHash(to: MailAddress[]): string {
  const normalized = to
    .map((a) => a.email.trim().toLowerCase())
    .sort()
    .join(",");
  return sha256(normalized);
}

/** Hash of the exact content being sent (subject + body). */
export function bodyHash(subject: string, body: string): string {
  return sha256(`${subject}\n\n${body}`);
}
