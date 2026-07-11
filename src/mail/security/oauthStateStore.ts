import crypto from "node:crypto";

import { MailOAuthStateSchema } from "@aaliyah/contracts/v1";

import {
  envelopeOpen,
  envelopeSeal,
  type KmsKeyWrapper,
} from "../../crypto/envelopeEncryption";
import type { MailStateBackend } from "../mailState";

// Short-lived, one-time OAuth states. The raw state value never rests
// anywhere (keyed by SHA-256); the PKCE verifier rests only as a KMS
// envelope. Persistence lives behind MailStateBackend — Postgres in
// production, in-memory for dev/tests — with atomic consume either way.

const DEFAULT_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hashState(stateValue: string): string {
  return crypto.createHash("sha256").update(stateValue).digest("hex");
}

export type OAuthStateDeps = {
  store: MailStateBackend["oauthStates"];
  kms: KmsKeyWrapper;
};

export type CreatedState = {
  /** The raw state value for the authorization URL — returned once, never stored. */
  stateValue: string;
  /** PKCE code_challenge (S256) to put in the authorization URL. */
  codeChallenge: string;
};

export async function createOAuthState(
  input: {
    tenantId: string;
    workspaceId: string;
    userId: string;
    sessionId: string;
    redirectUri: string;
    ttlMs?: number;
    now?: () => number;
  },
  deps: OAuthStateDeps,
): Promise<CreatedState> {
  const now = input.now ?? (() => Date.now());
  const at = now();
  const stateValue = b64url(crypto.randomBytes(32));
  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = b64url(crypto.createHash("sha256").update(codeVerifier).digest());
  const sealed = envelopeSeal(codeVerifier, deps.kms);

  const state = MailOAuthStateSchema.parse({
    stateHash: hashState(stateValue),
    provider: "google",
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    userId: input.userId,
    sessionId: input.sessionId,
    redirectUri: input.redirectUri,
    codeVerifierEncrypted: JSON.stringify(sealed),
    codeVerifierKeyVersion: sealed.keyId,
    createdAt: new Date(at).toISOString(),
    expiresAt: new Date(at + (input.ttlMs ?? DEFAULT_TTL_MS)).toISOString(),
    consumedAt: null,
  });
  await deps.store.put(state);
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
export async function consumeOAuthState(
  stateValue: string,
  input: {
    redirectUri: string;
    sessionId: string;
    now?: () => number;
  },
  deps: OAuthStateDeps,
): Promise<ConsumedState> {
  const consumed = await deps.store.consume(hashState(stateValue), {
    redirectUri: input.redirectUri,
    sessionId: input.sessionId,
    ...(input.now ? { now: input.now } : {}),
  });
  const codeVerifier = envelopeOpen(JSON.parse(consumed.codeVerifierEncrypted), deps.kms);
  return {
    tenantId: consumed.tenantId,
    workspaceId: consumed.workspaceId,
    userId: consumed.userId,
    sessionId: consumed.sessionId,
    codeVerifier,
  };
}
