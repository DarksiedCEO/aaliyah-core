const HEADER_CONTROL = /[\r\n\u0000]/;

export function requireSafeMailHeader(name: string, value: string): string {
  if (HEADER_CONTROL.test(value)) {
    throw new Error(`invalid_mail_header:${name}`);
  }
  return value;
}

function escapeUnsafeJsonCodePoints(value: string): string {
  return value
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * Serialize content from messages, memory, profiles, tools, and providers as a
 * single JSON data object. Callers must place this only in the user prompt;
 * untrusted values must never be concatenated into system authority.
 */
export function serializeUntrustedContent(value: Record<string, unknown>): string {
  return escapeUnsafeJsonCodePoints(JSON.stringify(value));
}
