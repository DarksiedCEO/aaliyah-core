import type {
  ModelProvider,
  ModelRouterRequest,
  NormalizedModelResponse,
} from "@aaliyah/contracts/v1";

/**
 * Provider abstraction. Every provider (OpenAI, Anthropic, Gemini, and any
 * future one) implements this single interface; business logic depends only on
 * the interface, never on a concrete provider or SDK.
 */
export interface ProviderAdapter {
  readonly provider: ModelProvider;
  generate(request: ModelRouterRequest): Promise<NormalizedModelResponse>;
}

/** Thrown when every provider in the router failed or was skipped. */
export class AllProvidersFailedError extends Error {
  readonly failures: { provider: ModelProvider; error: Error }[];

  constructor(failures: { provider: ModelProvider; error: Error }[]) {
    const summary = failures
      .map((f) => `${f.provider}: ${f.error.message}`)
      .join("; ");
    super(`All model providers failed — ${summary}`);
    this.name = "AllProvidersFailedError";
    this.failures = failures;
  }
}
