import type { ModelProvider } from "@aaliyah/contracts/v1";

type HealthState = {
  consecutiveFailures: number;
  unhealthyUntil: number;
};

export type ProviderHealthOptions = {
  /** Consecutive failures before a provider is marked unhealthy. */
  failureThreshold: number;
  /** How long (ms) a provider stays unhealthy before it can be retried. */
  cooldownMs: number;
  now?: () => number;
};

/**
 * Provider health awareness (no cost/quality routing — out of scope for v1).
 * A provider that fails `failureThreshold` times in a row is skipped until its
 * cooldown elapses, then given another chance. Any success resets it.
 */
export class ProviderHealthTracker {
  private readonly states = new Map<ModelProvider, HealthState>();
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;
  private readonly now: () => number;

  constructor(options: ProviderHealthOptions) {
    this.failureThreshold = options.failureThreshold;
    this.cooldownMs = options.cooldownMs;
    this.now = options.now ?? (() => Date.now());
  }

  private stateFor(provider: ModelProvider): HealthState {
    let state = this.states.get(provider);
    if (!state) {
      state = { consecutiveFailures: 0, unhealthyUntil: 0 };
      this.states.set(provider, state);
    }
    return state;
  }

  isHealthy(provider: ModelProvider): boolean {
    return this.now() >= this.stateFor(provider).unhealthyUntil;
  }

  recordSuccess(provider: ModelProvider): void {
    const state = this.stateFor(provider);
    state.consecutiveFailures = 0;
    state.unhealthyUntil = 0;
  }

  recordFailure(provider: ModelProvider): void {
    const state = this.stateFor(provider);
    state.consecutiveFailures += 1;
    if (state.consecutiveFailures >= this.failureThreshold) {
      state.unhealthyUntil = this.now() + this.cooldownMs;
    }
  }
}
