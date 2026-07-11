import crypto from "node:crypto";

/**
 * Real Google ID-token verification. Nothing here trusts a client-decoded
 * claim: issuer, audience, signature (RS256 against Google's published JWKS),
 * expiry, nonce, and verified-email are all enforced server-side, and the
 * external subject — never the email — anchors identity. Error messages
 * carry reasons only, never the token or its claims.
 */

export type JwksProvider = () => Promise<{
  keys: Array<Record<string, unknown> & { kid?: string; alg?: string }>;
}>;

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

/** Production JWKS source — fails closed on any network/shape problem. */
export function fetchGoogleJwks(fetchImpl: typeof fetch = fetch): JwksProvider {
  return async () => {
    const res = await fetchImpl(GOOGLE_JWKS_URL);
    if (!res.ok) throw new Error(`google jwks fetch failed (${res.status})`);
    const body = (await res.json()) as { keys?: unknown };
    if (!Array.isArray(body.keys)) throw new Error("google jwks fetch failed (bad shape)");
    return { keys: body.keys as Array<Record<string, unknown> & { kid?: string }> };
  };
}

export type VerifiedGoogleIdentity = {
  subject: string;
  email: string;
  emailVerified: true;
  audience: string;
  expiresAt: number; // epoch ms
};

function decodeSegment(segment: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    throw new Error("google id token rejected: malformed");
  }
}

export async function verifyGoogleIdToken(
  idToken: string,
  opts: {
    clientId: string;
    jwks: JwksProvider;
    expectedNonce?: string;
    now?: () => number;
  },
): Promise<VerifiedGoogleIdentity> {
  const now = opts.now ?? (() => Date.now());
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("google id token rejected: malformed");
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  const header = decodeSegment(headerB64);
  if (header.alg !== "RS256") {
    throw new Error("google id token rejected: unsupported algorithm");
  }
  const kid = typeof header.kid === "string" ? header.kid : "";

  // Signature first: an unsigned claim is not a claim.
  const { keys } = await opts.jwks();
  const jwk = keys.find((k) => k.kid === kid);
  if (!jwk) throw new Error("google id token rejected: unknown signing key");
  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({
      key: jwk,
      format: "jwk",
    } as unknown as Parameters<typeof crypto.createPublicKey>[0]);
  } catch {
    throw new Error("google id token rejected: unusable signing key");
  }
  const signatureValid = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${headerB64}.${payloadB64}`),
    publicKey,
    Buffer.from(signatureB64, "base64url"),
  );
  if (!signatureValid) throw new Error("google id token rejected: invalid signature");

  const payload = decodeSegment(payloadB64);

  if (typeof payload.iss !== "string" || !GOOGLE_ISSUERS.includes(payload.iss)) {
    throw new Error("google id token rejected: wrong issuer");
  }
  if (payload.aud !== opts.clientId) {
    throw new Error("google id token rejected: wrong audience");
  }
  const expSec = typeof payload.exp === "number" ? payload.exp : 0;
  if (expSec * 1000 <= now()) {
    throw new Error("google id token rejected: expired");
  }
  if (opts.expectedNonce !== undefined && payload.nonce !== opts.expectedNonce) {
    throw new Error("google id token rejected: nonce mismatch");
  }
  const subject = typeof payload.sub === "string" ? payload.sub : "";
  if (!subject) throw new Error("google id token rejected: missing subject");
  if (payload.email_verified !== true) {
    throw new Error("google id token rejected: email not verified");
  }
  const email = typeof payload.email === "string" ? payload.email : "";
  if (!email) throw new Error("google id token rejected: email not verified");

  return {
    subject,
    email,
    emailVerified: true,
    audience: opts.clientId,
    expiresAt: expSec * 1000,
  };
}
