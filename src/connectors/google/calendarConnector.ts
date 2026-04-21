import { google } from "googleapis";
import { type EvidenceSource, EvidenceSourceSchema } from "@aaliyah/contracts/v1";

import { enforceTenantBoundary } from "../../governance/enforceTenantBoundary";
import { auditCredentialUse } from "../../governance/credentialAudit";
import { getCredential } from "../../governance/credentialProvider";
import { validateSource } from "../validateSource";
import { buildGoogleOAuthClient } from "./googleClient";
import { emitConnectorEmptyResult, wrapConnectorFailure } from "./connectorErrors";

type CalendarConnectorInput = {
  tenantId: string;
  userId: string;
  query: string;
};

export const calendarConnectorInternals = {
  buildService: (auth: InstanceType<typeof google.auth.OAuth2>) =>
    google.calendar({ version: "v3", auth }),
  now: () => new Date().toISOString(),
};

export async function calendarConnector(
  input: CalendarConnectorInput,
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

    const calendar = calendarConnectorInternals.buildService(auth);
    const events = await calendar.events.list({
      calendarId: "primary",
      q: input.query,
      maxResults: 10,
      singleEvents: true,
      orderBy: "startTime",
      timeMin: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const items = events.data.items ?? [];

    if (items.length === 0) {
      emitConnectorEmptyResult("calendar");
      return [];
    }

    const results: EvidenceSource[] = items.map((item) => {
      if (!item.id) {
        throw new Error("Malformed Calendar response");
      }

      const source = EvidenceSourceSchema.parse({
        sourceId: `calendar:${input.tenantId}:${input.userId}:${item.id}`,
        sourceType: "calendar",
        title: item.summary ?? "Untitled event",
        excerpt: `Start: ${item.start?.dateTime ?? item.start?.date ?? "unknown"}`,
        trustLevel: "high",
        freshness: "current",
        relevanceScore: 82,
        authorityScore: 84,
        recencyScore: 90,
        contradictionFlags: [],
        tags: ["calendar"],
        retrievedAt: calendarConnectorInternals.now(),
      });

      validateSource(source);
      return source;
    });

    return enforceTenantBoundary(
      input.tenantId,
      results.map((result) => ({
        ...result,
        tenantId: input.tenantId,
      })),
    ).map(({ tenantId: _tenantId, ...rest }) => rest);
  } catch (error) {
    return wrapConnectorFailure("calendar", error);
  }
}
