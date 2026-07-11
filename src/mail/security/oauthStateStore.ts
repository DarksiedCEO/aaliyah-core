import crypto from "node:crypto";

import { OAuthStateSchema, type OAuthState } from "@aaliyah/contracts/v1";

// Short-lived, one-time OAuth states. In production this MUST be a durable,
// tenant-scoped table so consume() is atomic across instances.
const store = new Map<string, OAuthState>();

const DEFAULT_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export type CreatedState = {
  state: OAuthState;
  /** PKCE code_challenge (S256) to put in the authorization URL. */
  codeChallenge: string;
};

export function createOAuthState(input: {
  tenantId: string;
  workspaceId: string;
  userId: string;
  redirectUri: string;
  ttlMs?: number;
  now?: () => number;
}): CreatedState {
  const now = input.now ?? (() => Date.now());
  const at = now();
  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = b64url(crypto.createHash("sha256").update(codeVerifier).digest());

  const state = OAuthStateSchema.parse({
    state: b64url(crypto.randomBytes(32)),
    codeVerifier,
    provider: "google",
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    redirectUri: input.redirectUri,
    createdAt: new Date(at).toISOString(),
    expiresAt: new Date(at + (input.ttlMs ?? DEFAULT_TTL_MS)).toISOString(),
    consumedAt: null,
  });
  store.set(state.state, state);
  return { state, codeChallenge };
}

/**
 * Validate and atomically consume a state. Throws — fail closed — on unknown,
 * reused, expired state, or a redirect-URI that does not exactly match the one
 * bound at creation (defends against CSRF, code replay, redirect manipulation).
 */
export function consumeOAuthState(
  stateValue: string,
  redirectUri: string,
  now: () => number = () => Date.now(),
): OAuthState {
  const state = store.get(stateValue);
  if (!state) throw new Error("oauth callback rejected: unknown state");
  if (state.consumedAt) throw new Error("oauth callback rejected: state already used");
  if (now() > new Date(state.expiresAt).getTime()) {
    throw new Error("oauth callback rejected: state expired");
  }
  if (state.redirectUri !== redirectUri) {
    throw new Error("oauth callback rejected: redirect URI mismatch");
  }
  const consumed = { ...state, consumedAt: new Date(now()).toISOString() };
  store.set(stateValue, consumed);
  return consumed;
}

export function clearOAuthStates(): void {
  store.clear();
}
