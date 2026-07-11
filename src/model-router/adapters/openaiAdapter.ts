import OpenAI from "openai";
import type {
  ModelRouterRequest,
  NormalizedModelResponse,
} from "@aaliyah/contracts/v1";

import type { ProviderAdapter } from "../types";

/**
 * OpenAI adapter. Uses the Responses API — the same surface the planner relies
 * on — and normalizes the result. Transport is injectable for testing.
 */
export class OpenAIAdapter implements ProviderAdapter {
  readonly provider = "openai" as const;

  private readonly buildClient: () => OpenAI;
  private readonly model: string;
  private readonly now: () => number;

  constructor(options?: {
    buildClient?: () => OpenAI;
    model?: string;
    now?: () => number;
  }) {
    this.buildClient =
      options?.buildClient ??
      (() => new OpenAI({ apiKey: process.env.OPENAI_API_KEY }));
    this.model = options?.model ?? process.env.AALIYAH_OPENAI_MODEL ?? "gpt-5";
    this.now = options?.now ?? (() => Date.now());
  }

  async generate(request: ModelRouterRequest): Promise<NormalizedModelResponse> {
    if (!process.env.OPENAI_API_KEY) {
      throw new Error("openai: missing OPENAI_API_KEY");
    }

    const start = this.now();
    const client = this.buildClient();
    const input = request.system
      ? `${request.system}\n\n${request.prompt}`
      : request.prompt;

    const response = await client.responses.create({
      model: this.model,
      input,
      ...(request.maxOutputTokens
        ? { max_output_tokens: request.maxOutputTokens }
        : {}),
    });

    return {
      text: response.output_text ?? "",
      provider: this.provider,
      model: this.model,
      latencyMs: this.now() - start,
    };
  }
}
