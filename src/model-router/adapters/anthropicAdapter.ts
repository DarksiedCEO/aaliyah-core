import Anthropic from "@anthropic-ai/sdk";
import type {
  ModelRouterRequest,
  NormalizedModelResponse,
} from "@aaliyah/contracts/v1";

import type { ProviderAdapter } from "../types";

/**
 * Anthropic adapter, using the official SDK's Messages API. Default model is
 * the latest Opus; transport is injectable for testing.
 */
export class AnthropicAdapter implements ProviderAdapter {
  readonly provider = "anthropic" as const;

  private readonly buildClient: () => Anthropic;
  private readonly model: string;
  private readonly defaultMaxTokens: number;
  private readonly now: () => number;

  constructor(options?: {
    buildClient?: () => Anthropic;
    model?: string;
    defaultMaxTokens?: number;
    now?: () => number;
  }) {
    this.buildClient =
      options?.buildClient ??
      (() => new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));
    this.model =
      options?.model ?? process.env.AALIYAH_ANTHROPIC_MODEL ?? "claude-opus-4-8";
    this.defaultMaxTokens = options?.defaultMaxTokens ?? 4096;
    this.now = options?.now ?? (() => Date.now());
  }

  async generate(request: ModelRouterRequest): Promise<NormalizedModelResponse> {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error("anthropic: missing ANTHROPIC_API_KEY");
    }

    const start = this.now();
    const client = this.buildClient();

    const message = await client.messages.create({
      model: this.model,
      max_tokens: request.maxOutputTokens ?? this.defaultMaxTokens,
      ...(request.system ? { system: request.system } : {}),
      messages: [{ role: "user", content: request.prompt }],
    });

    if (message.stop_reason === "refusal") {
      throw new Error("anthropic: request refused by safety policy");
    }

    const text = message.content
      .filter((block): block is Anthropic.TextBlock => block.type === "text")
      .map((block) => block.text)
      .join("");

    return {
      text,
      provider: this.provider,
      model: this.model,
      latencyMs: this.now() - start,
    };
  }
}
