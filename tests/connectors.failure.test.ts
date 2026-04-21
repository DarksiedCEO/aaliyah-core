import assert from "node:assert/strict";
import test, { afterEach, mock } from "node:test";

import * as tenantBoundaryModule from "../src/governance/enforceTenantBoundary";
import {
  clearCredentials,
  registerCredential,
} from "../src/governance/credentialProvider";
import {
  calendarConnector,
  calendarConnectorInternals,
} from "../src/connectors/google/calendarConnector";
import {
  gmailConnector,
  gmailConnectorInternals,
} from "../src/connectors/google/gmailConnector";

afterEach(() => {
  clearCredentials();
  mock.restoreAll();
});

test("gmail connector fails on expired credential", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    expiresAt: Date.now() - 1_000,
  });

  await assert.rejects(
    () =>
      gmailConnector({
        tenantId: "t1",
        userId: "u1",
        query: "status",
      }),
    /Credential expired/,
  );
});

test("gmail connector fails on revoked credential", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "revoked",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  await assert.rejects(
    () =>
      gmailConnector({
        tenantId: "t1",
        userId: "u1",
        query: "status",
      }),
    /Credential revoked/,
  );
});

test("calendar connector fails on missing credential", async () => {
  await assert.rejects(
    () =>
      calendarConnector({
        tenantId: "t1",
        userId: "u1",
        query: "meeting",
      }),
    /Missing credential/,
  );
});

test("gmail connector surfaces upstream timeout", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  mock.method(gmailConnectorInternals, "buildService", () => ({
    users: {
      messages: {
        list: async () => {
          throw new Error("request timeout");
        },
      },
    },
  }) as never);

  await assert.rejects(
    () =>
      gmailConnector({
        tenantId: "t1",
        userId: "u1",
        query: "status",
      }),
    /timeout/i,
  );
});

test("gmail connector fails on malformed upstream response", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  mock.method(gmailConnectorInternals, "buildService", () => ({
    users: {
      messages: {
        list: async () => ({
          data: {
            messages: [{ id: "m1" }],
          },
        }),
        get: async () => ({
          data: {
            payload: {},
          },
        }),
      },
    },
  }) as never);

  await assert.rejects(
    () =>
      gmailConnector({
        tenantId: "t1",
        userId: "u1",
        query: "status",
      }),
    /Malformed Gmail response/,
  );
});

test("calendar connector handles empty results without pretending success", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  mock.method(calendarConnectorInternals, "buildService", () => ({
    events: {
      list: async () => ({
        data: {
          items: [],
        },
      }),
    },
  }) as never);

  const result = await calendarConnector({
    tenantId: "t1",
    userId: "u1",
    query: "meeting",
  });

  assert.deepEqual(result, []);
});

test("calendar connector fails hard on tenant mismatch", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  mock.method(calendarConnectorInternals, "buildService", () => ({
    events: {
      list: async () => ({
        data: {
          items: [{ id: "event-1", summary: "Quarterly review", start: { dateTime: "2026-04-18T12:00:00Z" } }],
        },
      }),
    },
  }) as never);

  mock.method(tenantBoundaryModule, "enforceTenantBoundary", () => {
    throw new Error("Tenant boundary violation detected");
  });

  await assert.rejects(
    () =>
      calendarConnector({
        tenantId: "t1",
        userId: "u1",
        query: "meeting",
      }),
    /Tenant boundary violation detected/,
  );
});

test("gmail connector rejects low-quality source output", async () => {
  registerCredential({
    tenantId: "t1",
    userId: "u1",
    provider: "google",
    accessToken: "token",
    status: "active",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });

  mock.method(gmailConnectorInternals, "buildService", () => ({
    users: {
      messages: {
        list: async () => ({
          data: {
            messages: [{ id: "m1" }],
          },
        }),
        get: async () => ({
          data: {
            payload: {
              headers: [
                { name: "Subject", value: "ok" },
                { name: "From", value: "sender@example.com" },
                { name: "Date", value: "today" },
              ],
            },
          },
        }),
      },
    },
  }) as never);

  await assert.rejects(
    () =>
      gmailConnector({
        tenantId: "t1",
        userId: "u1",
        query: "status",
      }),
    /Invalid source title/,
  );
});
