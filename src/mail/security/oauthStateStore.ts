import crypto from "node:crypto";

import { MailOAuthStateSchema, type MailOAuthState } from "@aaliyah/contracts/v1";

import {
  openSecret,
  sealSecret,
  type KeyProvider,
} from "../../crypto/authenticatedEncryption";

// Short-lived, one-time OAuth states, keyed by SHA-256 of the state value so
// the raw value never rests here; the PKCE verifier rests only as ciphertext.
// In production this MUST be a durable, tenant-scoped table so consume() is
// atomic across instances.
const store = new Map<string, MailOAuthState>();

const DEFAULT_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hashState(stateValue: string): string {
  return crypto.createHash("sha256").update(stateValue).digest("hex");
}

export type CreatedState = {
  /** The raw state value for the authorization URL — returned once, never stored. */
  stateValue: string;
  /** PKCE code_challenge (S256) to put in the authorization URL. */
  codeChallenge: string;
};

export function createOAuthState(input: {
  tenantId: string;
  workspaceId: string;
  userId: string;
  sessionId: string;
  redirectUri: string;
  keyProvider: KeyProvider;
  ttlMs?: number;
  now?: () => number;
}): CreatedState {
  const now = input.now ?? (() => Date.now());
  const at = now();
  const stateValue = b64url(crypto.randomBytes(32));
  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = b64url(crypto.createHash("sha256").update(codeVerifier).digest());
  const sealed = sealSecret(codeVerifier, input.keyProvider);

  const state = MailOAuthStateSchema.parse({
    stateHash: hashState(stateValue),
    provider: "google",
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    sessionId: input.sessionId,
    redirectUri: input.redirectUri,
    codeVerifierEncrypted: sealed.ciphertext,
    codeVerifierKeyVersion: sealed.keyVersion,
    createdAt: new Date(at).toISOString(),
    expiresAt: new Date(at + (input.ttlMs ?? DEFAULT_TTL_MS)).toISOString(),
    consumedAt: null,
  });
  store.set(state.stateHash, state);
  return { stateValue, codeChallenge };
}

export type ConsumedState = {
  tenantId: string;
  workspaceId: string;
  userId: string;
  sessionId: string;
  codeVerifier: string;
};

/**
 * Validate and atomically consume a state. Throws — fail closed — on unknown,
 * reused, or expired state, a redirect-URI mismatch, or an attempt made under
 * a different authenticated session than the one that started the flow
 * (defends against CSRF, code replay, redirect manipulation, session hijack).
 */
export function consumeOAuthState(
  stateValue: string,
  input: {
    redirectUri: string;
    sessionId: string;
    keyProvider: KeyProvider;
    now?: () => number;
  },
): ConsumedState {
  const now = input.now ?? (() => Date.now());
  const state = store.get(hashState(stateValue));
  if (!state) throw new Error("oauth callback rejected: unknown state");
  if (state.consumedAt) throw new Error("oauth callback rejected: state already used");
  if (now() > new Date(state.expiresAt).getTime()) {
    throw new Error("oauth callback rejected: state expired");
  }
  if (state.redirectUri !== input.redirectUri) {
    throw new Error("oauth callback rejected: redirect URI mismatch");
  }
  if (state.sessionId !== input.sessionId) {
    throw new Error("oauth callback rejected: session mismatch");
  }
  const codeVerifier = openSecret(
    { ciphertext: state.codeVerifierEncrypted, keyVersion: state.codeVerifierKeyVersion },
    input.keyProvider,
  );
  store.set(state.stateHash, { ...state, consumedAt: new Date(now()).toISOString() });
  return {
    tenantId: state.tenantId,
    workspaceId: state.workspaceId,
    userId: state.userId,
    sessionId: state.sessionId,
    codeVerifier,
  };
}

/** Inspection hook for tests: stored records only (hashes + ciphertext). */
export function debugOAuthStates(): MailOAuthState[] {
  return [...store.values()];
}

export function clearOAuthStates(): void {
  store.clear();
}
