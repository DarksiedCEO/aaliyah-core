import type { MailProvider, MailServerConfig } from "@aaliyah/contracts/v1";

export type DetectedProvider = {
  provider: MailProvider;
  /** Present for imap_smtp when we know the host's settings; else undefined. */
  imap?: MailServerConfig;
  smtp?: MailServerConfig;
  /** True when settings are known; false means Advanced setup is needed. */
  autoConfigured: boolean;
};

// Domains that map to a native OAuth provider.
const GOOGLE = new Set(["gmail.com", "googlemail.com"]);
const MICROSOFT = new Set([
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
]);
const YAHOO = new Set(["yahoo.com", "ymail.com", "rocketmail.com"]);

// Known IMAP/SMTP settings for common hosted-email providers.
const KNOWN_IMAP_SMTP: Record<string, { imap: MailServerConfig; smtp: MailServerConfig }> = {
  "zoho.com": {
    imap: { host: "imap.zoho.com", port: 993, encryption: "ssl" },
    smtp: { host: "smtp.zoho.com", port: 465, encryption: "ssl" },
  },
  "fastmail.com": {
    imap: { host: "imap.fastmail.com", port: 993, encryption: "ssl" },
    smtp: { host: "smtp.fastmail.com", port: 465, encryption: "ssl" },
  },
  "privateemail.com": {
    // Namecheap Private Email
    imap: { host: "mail.privateemail.com", port: 993, encryption: "ssl" },
    smtp: { host: "mail.privateemail.com", port: 465, encryption: "ssl" },
  },
  "secureserver.net": {
    // GoDaddy
    imap: { host: "imap.secureserver.net", port: 993, encryption: "ssl" },
    smtp: { host: "smtpout.secureserver.net", port: 465, encryption: "ssl" },
  },
};

function domainOf(email: string): string {
  return email.split("@")[1]?.toLowerCase() ?? "";
}

/**
 * Detect the right provider (and, for IMAP/SMTP hosts, server settings) from an
 * email address. Native-OAuth domains route to their connector; known hosted
 * domains route to imap_smtp fully auto-configured; everything else routes to
 * imap_smtp needing Advanced setup.
 */
export function detectProvider(email: string): DetectedProvider {
  const domain = domainOf(email);

  if (GOOGLE.has(domain)) return { provider: "google", autoConfigured: true };
  if (MICROSOFT.has(domain)) return { provider: "microsoft", autoConfigured: true };
  if (YAHOO.has(domain)) return { provider: "yahoo", autoConfigured: true };

  const known = KNOWN_IMAP_SMTP[domain];
  if (known) {
    return {
      provider: "imap_smtp",
      imap: known.imap,
      smtp: known.smtp,
      autoConfigured: true,
    };
  }

  // Unknown custom domain — architecture supports it, but the user (or a live
  // autoconfig probe, added later) must supply server settings via Advanced.
  return { provider: "imap_smtp", autoConfigured: false };
}
