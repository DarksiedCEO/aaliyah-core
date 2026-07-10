import {
  MailboxConnectionSchema,
  SanitizedConnectionSchema,
  type SanitizedConnection,
} from "@aaliyah/contracts/v1";

import type { KeyProvider } from "../../crypto/authenticatedEncryption";
import type { TenantScope } from "../../persistence/tenantScopedStore";
import { connectionIdFor } from "../adapters/helpers";
import {
  deleteConnection,
  getConnection,
  saveConnection,
} from "../connectionStore";
import {
  deleteMailCredential,
  getMailCredential,
  openRefreshToken,
  revokeMailCredential,
  saveMailCredential,
} from "../security/credentialVault";
import { invalidateApprovalsForConnection } from "../security/sendApproval";
import { recordMailAudit } from "../security/mailAudit";
import {
  consumeOAuthState,
  createOAuthState,
} from "../security/oauthStateStore";

const AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const DEFAULT_SCOPES = [
  "https://www.googleapis.com/auth/gmail.modify",
  "openid",
  "email",
];

export type GoogleTokenResponse = {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scope: string;
};
export type GoogleMailboxProfile = { email: string };

/** Injectable Google network surface — real HTTP behind it in production. */
export interface GoogleOAuthHttp {
  exchangeAuthorizationCode(input: {
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<GoogleTokenResponse>;
  refreshAccessToken(refreshToken: string): Promise<GoogleTokenResponse>;
  fetchMailboxProfile(accessToken: string): Promise<GoogleMailboxProfile>;
  revokeToken(token: string): Promise<void>;
}

export type GoogleConnectDeps = {
  http: GoogleOAuthHttp;
  keyProvider: KeyProvider;
  clientId: string;
  scopes?: string[];
  now?: () => string;
  onDisconnect?: (connectionId: string) => void; // stop polling / queued jobs
};

/**
 * Build the "Continue with Google" authorization URL. Creates a one-time,
 * tenant-bound PKCE state; the user never types their address — Google returns
 * the verified mailbox identity in the callback.
 */
export function buildGoogleAuthorizationUrl(
  input: {
    tenantId: string;
    workspaceId: string;
    userId: string;
    sessionId: string;
    redirectUri: string;
  },
  deps: GoogleConnectDeps,
): { url: string; state: string } {
  const { stateValue, codeChallenge } = createOAuthState({
    ...input,
    keyProvider: deps.keyProvider,
  });
  const params = new URLSearchParams({
    client_id: deps.clientId,
    redirect_uri: input.redirectUri,
    response_type: "code",
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "true",
    scope: (deps.scopes ?? DEFAULT_SCOPES).join(" "),
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: stateValue,
  });
  return { url: `${AUTHORIZE_URL}?${params.toString()}`, state: stateValue };
}

/**
 * Handle the OAuth callback as a single transaction: validate state → exchange
 * code → fetch verified identity → verify tenant → encrypt refresh token →
 * persist → audit → return a sanitized status. Any failure leaves NO
 * half-connected mailbox and cannot be replayed (state is consumed first).
 */
export async function handleGoogleCallback(
  input: {
    code: string;
    state: string;
    redirectUri: string;
    /** sessionId of the authenticated principal presenting the callback. */
    expectedSessionId: string;
    expectedTenantId?: string;
  },
  deps: GoogleConnectDeps,
): Promise<SanitizedConnection> {
  const now = deps.now ?? (() => new Date().toISOString());

  // 1. One-time, session-bound state — consumed up front so a replayed or
  // hijacked callback is dead. Tenant/workspace/user come ONLY from the state.
  const state = consumeOAuthState(input.state, {
    redirectUri: input.redirectUri,
    sessionId: input.expectedSessionId,
    keyProvider: deps.keyProvider,
  });

  // 2. Tenant-confusion defense.
  if (input.expectedTenantId && state.tenantId !== input.expectedTenantId) {
    throw new Error("oauth callback rejected: tenant mismatch");
  }

  // 3. Exchange the code (not retried — single-use). A refresh token is required.
  const tokens = await deps.http.exchangeAuthorizationCode({
    code: input.code,
    codeVerifier: state.codeVerifier,
    redirectUri: input.redirectUri,
  });
  if (!tokens.refreshToken) {
    // Nothing persisted yet; revoke the access token we just received.
    await safeRevoke(deps, tokens.accessToken);
    recordFailureAudit(state, "no_refresh_token", now);
    throw new Error("oauth callback rejected: no refresh token granted");
  }

  // Everything after a successful exchange is wrapped so ANY failure fully rolls
  // back: revoke the fresh token, destroy any persisted credential/connection.
  let connectionId: string | undefined;
  try {
    const identity = await deps.http.fetchMailboxProfile(tokens.accessToken);
    connectionId = connectionIdFor({
      tenantId: state.tenantId,
      workspaceId: state.workspaceId,
      userId: state.userId,
      provider: "google",
      emailAddress: identity.email,
    });
    const at = now();

    saveMailCredential(
      {
        connectionId,
        tenantId: state.tenantId,
        workspaceId: state.workspaceId,
        userId: state.userId,
        refreshToken: tokens.refreshToken,
        grantedScopes: tokens.scope ? tokens.scope.split(" ") : [],
        connectedEmail: identity.email,
        accessTokenExpiresAt: new Date(Date.now() + tokens.expiresIn * 1000).toISOString(),
      },
      deps.keyProvider,
    );
    saveConnection(
      MailboxConnectionSchema.parse({
        connectionId,
        tenantId: state.tenantId,
        workspaceId: state.workspaceId,
        userId: state.userId,
        provider: "google",
        emailAddress: identity.email,
        authKind: "oauth",
        status: "connected",
        connectedAt: at,
      }),
    );

    recordMailAudit({
      tenantId: state.tenantId,
      workspaceId: state.workspaceId,
      connectionId,
      actorUserId: state.userId,
      action: "google.connected",
      detail: identity.email,
    });

    return SanitizedConnectionSchema.parse({
      connectionId,
      provider: "google",
      connectedEmail: identity.email,
      status: "connected",
    });
  } catch (error) {
    if (connectionId) {
      deleteMailCredential(connectionId);
      deleteConnection(connectionId);
    }
    await safeRevoke(deps, tokens.refreshToken);
    deps.onDisconnect?.(connectionId ?? "");
    recordFailureAudit(state, "connect_failed", now);
    throw error;
  }
}

async function safeRevoke(deps: GoogleConnectDeps, token: string): Promise<void> {
  try {
    await deps.http.revokeToken(token);
  } catch {
    // best effort — must not mask the original failure
  }
}

function recordFailureAudit(
  state: { tenantId: string; workspaceId: string; userId: string },
  reason: string,
  now: () => string,
): void {
  recordMailAudit({
    tenantId: state.tenantId,
    workspaceId: state.workspaceId,
    actorUserId: state.userId,
    action: "google.connect_failed",
    detail: reason,
    now,
  });
}

/** Refresh an access token from the encrypted refresh token. Never persists plaintext. */
export async function refreshGoogleAccessToken(
  connectionId: string,
  scope: TenantScope,
  deps: GoogleConnectDeps,
): Promise<string> {
  const refresh = openRefreshToken(connectionId, scope, deps.keyProvider);
  const { accessToken } = await deps.http.refreshAccessToken(refresh);
  return accessToken;
}

/**
 * Disconnect: revoke the provider token, cryptographically destroy the stored
 * credential, invalidate pending send approvals, stop queued work, delete the
 * connection — preserving only non-secret audit records.
 */
export async function disconnectGoogle(
  connectionId: string,
  scope: TenantScope,
  deps: GoogleConnectDeps,
): Promise<void> {
  const conn = getConnection(connectionId, scope);
  const credential = getMailCredential(connectionId, scope);

  // 1-2. Revoke at the provider (best effort — already-revoked is fine).
  if (credential && !credential.revokedAt) {
    try {
      const refresh = openRefreshToken(connectionId, scope, deps.keyProvider);
      await deps.http.revokeToken(refresh);
    } catch {
      // Revocation failure must not block local teardown.
    }
  }

  // 3. Destroy the stored secret.
  revokeMailCredential(connectionId, scope, deps.now);
  // 4. Stop polling / queued jobs.
  deps.onDisconnect?.(connectionId);
  // 5. Invalidate pending send approvals.
  invalidateApprovalsForConnection(connectionId);
  // 6. Remove the connection record (keep audit).
  deleteConnection(connectionId);

  if (conn) {
    recordMailAudit({
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      connectionId,
      action: "google.disconnected",
    });
  }
}
