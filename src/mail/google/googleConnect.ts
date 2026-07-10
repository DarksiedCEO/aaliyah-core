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

/** Injectable Google network surface — real HTTP behind it in production. */
export interface GoogleOAuthHttp {
  exchangeCode(input: {
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<{ accessToken: string; refreshToken: string; expiresIn: number; scope: string }>;
  fetchIdentity(accessToken: string): Promise<{ email: string }>;
  refresh(refreshToken: string): Promise<{ accessToken: string; expiresIn: number }>;
  revoke(refreshToken: string): Promise<void>;
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
    redirectUri: string;
  },
  deps: GoogleConnectDeps,
): { url: string; state: string } {
  const { state, codeChallenge } = createOAuthState(input);
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
    state: state.state,
  });
  return { url: `${AUTHORIZE_URL}?${params.toString()}`, state: state.state };
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
    expectedTenantId?: string;
  },
  deps: GoogleConnectDeps,
): Promise<SanitizedConnection> {
  const now = deps.now ?? (() => new Date().toISOString());

  // 1. One-time state — consumed up front so a replayed callback is dead.
  const state = consumeOAuthState(input.state, input.redirectUri);

  // 2. Tenant-confusion defense.
  if (input.expectedTenantId && state.tenantId !== input.expectedTenantId) {
    throw new Error("oauth callback rejected: tenant mismatch");
  }

  // 3-4. Exchange + verified mailbox identity (no persistence yet).
  const tokens = await deps.http.exchangeCode({
    code: input.code,
    codeVerifier: state.codeVerifier,
    redirectUri: input.redirectUri,
  });
  if (!tokens.refreshToken) {
    throw new Error("oauth callback rejected: no refresh token granted");
  }
  const identity = await deps.http.fetchIdentity(tokens.accessToken);

  const connectionId = connectionIdFor({
    tenantId: state.tenantId,
    workspaceId: state.workspaceId,
    userId: state.userId,
    provider: "google",
    emailAddress: identity.email,
  });
  const at = now();

  // 5-6. Persist credential + connection with rollback — no orphans.
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
  try {
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
  } catch (error) {
    deleteMailCredential(connectionId); // rollback the secret we just wrote
    throw error;
  }

  // 7. Audit (no secrets).
  recordMailAudit({
    tenantId: state.tenantId,
    workspaceId: state.workspaceId,
    connectionId,
    actorUserId: state.userId,
    action: "google.connected",
    detail: identity.email,
  });

  // 8. Sanitized status — never returns tokens.
  return SanitizedConnectionSchema.parse({
    connectionId,
    provider: "google",
    connectedEmail: identity.email,
    status: "connected",
  });
}

/** Refresh an access token from the encrypted refresh token. Never persists plaintext. */
export async function refreshGoogleAccessToken(
  connectionId: string,
  scope: TenantScope,
  deps: GoogleConnectDeps,
): Promise<string> {
  const refresh = openRefreshToken(connectionId, scope, deps.keyProvider);
  const { accessToken } = await deps.http.refresh(refresh);
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
      await deps.http.revoke(refresh);
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
