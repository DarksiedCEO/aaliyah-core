import type { EvidenceSource } from "@aaliyah/contracts/v1";

export function validateSource(source: EvidenceSource): void {
  if (!source.title || source.title.length < 3) {
    throw new Error("Invalid source title");
  }

  if (!source.relevanceScore || source.relevanceScore < 10) {
    throw new Error("Low-quality source");
  }

  if (!source.sourceType) {
    throw new Error("Missing source type");
  }
}
