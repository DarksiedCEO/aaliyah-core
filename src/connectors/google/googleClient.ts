import { google } from "googleapis";

export function buildGoogleOAuthClient(args: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  accessToken: string;
  refreshToken?: string;
}): InstanceType<typeof google.auth.OAuth2> {
  const client = new google.auth.OAuth2(
    args.clientId,
    args.clientSecret,
    args.redirectUri,
  );

  client.setCredentials(
    args.refreshToken
      ? {
          access_token: args.accessToken,
          refresh_token: args.refreshToken,
        }
      : {
          access_token: args.accessToken,
        },
  );

  return client;
}
