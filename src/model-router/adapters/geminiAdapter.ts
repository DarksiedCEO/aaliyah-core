import type {
  ModelRouterRequest,
  NormalizedModelResponse,
} from "@aaliyah/contracts/v1";

import type { ProviderAdapter } from "../types";

type GeminiResponse = {
  candidates?: {
    content?: { parts?: { text?: string }[] };
  }[];
};

/**
 * Gemini adapter via the Generative Language REST API. No official SDK is used
 * here — a thin fetch keeps the dependency surface small; `fetchImpl` is
 * injectable for testing.
 */
export class GeminiAdapter implements ProviderAdapter {
  readonly provider = "gemini" as const;

  private readonly model: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;

  constructor(options?: {
    model?: string;
    fetchImpl?: typeof fetch;
    now?: () => number;
  }) {
    this.model =
      options?.model ?? process.env.AALIYAH_GEMINI_MODEL ?? "gemini-2.5-flash";
    this.fetchImpl = options?.fetchImpl ?? fetch;
    this.now = options?.now ?? (() => Date.now());
  }

  async generate(request: ModelRouterRequest): Promise<NormalizedModelResponse> {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("gemini: missing GEMINI_API_KEY");
    }

    const start = this.now();
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${apiKey}`;

    const res = await this.fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: request.prompt }] }],
        ...(request.system
          ? { systemInstruction: { parts: [{ text: request.system }] } }
          : {}),
        ...(request.maxOutputTokens
          ? { generationConfig: { maxOutputTokens: request.maxOutputTokens } }
          : {}),
      }),
    });

    if (!res.ok) {
      throw new Error(`gemini: request failed with status ${res.status}`);
    }

    const data = (await res.json()) as GeminiResponse;
    const text =
      data.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ??
      "";

    return {
      text,
      provider: this.provider,
      model: this.model,
      latencyMs: this.now() - start,
    };
  }
}
