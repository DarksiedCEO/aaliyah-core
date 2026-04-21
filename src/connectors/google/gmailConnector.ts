import { google } from "googleapis";
import { type EvidenceSource, EvidenceSourceSchema } from "@aaliyah/contracts/v1";

import { enforceTenantBoundary } from "../../governance/enforceTenantBoundary";
import { auditCredentialUse } from "../../governance/credentialAudit";
import { getCredential } from "../../governance/credentialProvider";
import { validateSource } from "../validateSource";
import { buildGoogleOAuthClient } from "./googleClient";
import { emitConnectorEmptyResult, wrapConnectorFailure } from "./connectorErrors";

type GmailConnectorInput = {
  tenantId: string;
  userId: string;
  query: string;
};

export const gmailConnectorInternals = {
  buildService: (auth: InstanceType<typeof google.auth.OAuth2>) =>
    google.gmail({ version: "v1", auth }),
  now: () => new Date().toISOString(),
};

export async function gmailConnector(
  input: GmailConnectorInput,
): Promise<EvidenceSource[]> {
  try {
    const creds = getCredential(input.tenantId, input.userId, "google");
    auditCredentialUse(input.tenantId, input.userId, "google");
    const auth = buildGoogleOAuthClient({
      clientId: process.env.GOOGLE_CLIENT_ID ?? "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
      redirectUri: process.env.GOOGLE_REDIRECT_URI ?? "",
      accessToken: creds.accessToken,
      ...(creds.refreshToken ? { refreshToken: creds.refreshToken } : {}),
    });

    const gmail = gmailConnectorInternals.buildService(auth);
    const list = await gmail.users.messages.list({
      userId: "me",
      q: input.query,
      maxResults: 10,
    });

    const messages = list.data.messages ?? [];

    if (messages.length === 0) {
      emitConnectorEmptyResult("gmail");
      return [];
    }

    const results: EvidenceSource[] = [];

    for (const message of messages) {
      if (!message.id) {
        throw new Error("Malformed Gmail response");
      }

      const detail = await gmail.users.messages.get({
        userId: "me",
        id: message.id,
        format: "metadata",
        metadataHeaders: ["Subject", "From", "Date"],
      });

      const headers = detail.data.payload?.headers;

      if (!Array.isArray(headers)) {
        throw new Error("Malformed Gmail response");
      }

      const subject =
        headers.find((header) => header.name === "Subject")?.value ?? "No subject";
      const from =
        headers.find((header) => header.name === "From")?.value ?? "Unknown sender";
      const date = headers.find((header) => header.name === "Date")?.value ?? "";

      const source = EvidenceSourceSchema.parse({
          sourceId: `gmail:${input.tenantId}:${input.userId}:${message.id}`,
          sourceType: "gmail",
          title: subject,
          excerpt: `From: ${from} | Date: ${date}`,
          trustLevel: "high",
          freshness: "current",
          relevanceScore: 85,
          authorityScore: 80,
          recencyScore: 88,
          contradictionFlags: [],
          tags: ["gmail"],
          retrievedAt: gmailConnectorInternals.now(),
        });

      validateSource(source);
      results.push(source);
    }

    return enforceTenantBoundary(
      input.tenantId,
      results.map((result) => ({
        ...result,
        tenantId: input.tenantId,
      })),
    ).map(({ tenantId: _tenantId, ...rest }) => rest);
  } catch (error) {
    return wrapConnectorFailure("gmail", error);
  }
}
