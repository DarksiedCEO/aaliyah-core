import type { MailCapabilities, MailProvider } from "@aaliyah/contracts/v1";

import type { MailProviderAdapter } from "./types";
import { GoogleMailAdapter } from "./adapters/googleMailAdapter";
import { MicrosoftGraphAdapter } from "./adapters/microsoftGraphAdapter";
import {
  createGenericImapSmtpAdapter,
  createYahooMailAdapter,
} from "./adapters/transportBackedAdapter";
import { detectProvider } from "./autodetect";

export type MailRegistryDeps = ConstructorParameters<typeof GoogleMailAdapter>[0];

/**
 * The single "Connect Inbox" entry point. Callers resolve an adapter by
 * provider (or auto-detect it from an email address); Aaliyah then issues the
 * same normalized commands regardless of which provider is underneath.
 */
export class MailProviderRegistry {
  private readonly adapters: Map<MailProvider, MailProviderAdapter>;

  constructor(deps: MailRegistryDeps = {}) {
    this.adapters = new Map<MailProvider, MailProviderAdapter>([
      ["google", new GoogleMailAdapter(deps)],
      ["microsoft", new MicrosoftGraphAdapter(deps)],
      ["yahoo", createYahooMailAdapter({ deps })],
      ["imap_smtp", createGenericImapSmtpAdapter({ deps })],
    ]);
  }

  /** Override/register a concrete adapter (e.g. an IMAP/SMTP transport). */
  register(adapter: MailProviderAdapter): void {
    this.adapters.set(adapter.provider, adapter);
  }

  get(provider: MailProvider): MailProviderAdapter {
    const adapter = this.adapters.get(provider);
    if (!adapter) throw new Error(`No mail adapter registered for provider ${provider}`);
    return adapter;
  }

  /** Resolve the right adapter straight from an email address. */
  forEmail(email: string): { adapter: MailProviderAdapter; autoConfigured: boolean } {
    const detected = detectProvider(email);
    return { adapter: this.get(detected.provider), autoConfigured: detected.autoConfigured };
  }

  capabilities(): MailCapabilities[] {
    return [...this.adapters.values()].map((a) => a.capabilities);
  }
}
