import type {
  ModelProvider,
  ModelRouterRequest,
  NormalizedModelResponse,
} from "@aaliyah/contracts/v1";

import { logger } from "../observability/logger";
import { ProviderHealthTracker } from "./providerHealth";
import { AllProvidersFailedError, type ProviderAdapter } from "./types";

export type AaliyahModelRouterOptions = {
  /** Per-attempt timeout in ms. */
  timeoutMs?: number;
  failureThreshold?: number;
  cooldownMs?: number;
  health?: ProviderHealthTracker;
  now?: () => number;
};

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  provider: ModelProvider,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${provider}: request timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * AaliyahModelRouter — the single seam all generation flows through. v1 scope
 * (per the approved Block 3 modification): provider abstraction, fallback
 * routing, and provider-health awareness ONLY. No cost or quality routing.
 *
 * Providers are tried in their configured priority order; an unhealthy provider
 * is skipped unless every provider is unhealthy (last-resort: try anyway). On
 * error or timeout the next provider is tried. Health is updated per attempt.
 */
export class AaliyahModelRouter {
  private readonly adapters: ProviderAdapter[];
  private readonly health: ProviderHealthTracker;
  private readonly timeoutMs: number;

  constructor(adapters: ProviderAdapter[], options?: AaliyahModelRouterOptions) {
    if (adapters.length === 0) {
      throw new Error("AaliyahModelRouter requires at least one provider");
    }
    this.adapters = adapters;
    this.timeoutMs = options?.timeoutMs ?? 30_000;
    this.health =
      options?.health ??
      new ProviderHealthTracker({
        failureThreshold: options?.failureThreshold ?? 3,
        cooldownMs: options?.cooldownMs ?? 60_000,
        ...(options?.now ? { now: options.now } : {}),
      });
  }

  private order(): ProviderAdapter[] {
    const healthy = this.adapters.filter((a) => this.health.isHealthy(a.provider));
    // Fail open: if everything is cooling down, still attempt all providers
    // rather than refusing outright.
    return healthy.length > 0 ? healthy : this.adapters;
  }

  async generate(request: ModelRouterRequest): Promise<NormalizedModelResponse> {
    const failures: { provider: ModelProvider; error: Error }[] = [];

    for (const adapter of this.order()) {
      try {
        const response = await withTimeout(
          adapter.generate(request),
          this.timeoutMs,
          adapter.provider,
        );
        this.health.recordSuccess(adapter.provider);
        return response;
      } catch (error) {
        const err = error instanceof Error ? error : new Error("unknown error");
        this.health.recordFailure(adapter.provider);
        failures.push({ provider: adapter.provider, error: err });
        logger.warn(
          { provider: adapter.provider, err },
          "model_router.provider.failed",
        );
      }
    }

    throw new AllProvidersFailedError(failures);
  }
}
