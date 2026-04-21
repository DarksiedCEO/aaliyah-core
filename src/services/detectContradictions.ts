import type { EvidenceSource } from "@aaliyah/contracts/v1";

export function detectContradictions(
  sources: EvidenceSource[],
): EvidenceSource[] {
  const seen = new Map<string, string>();

  return sources.map((source) => {
    const key = source.title.toLowerCase();
    const excerpt = source.excerpt ?? "";
    const contradictionFlags = [...source.contradictionFlags];

    if (seen.has(key) && seen.get(key) !== excerpt) {
      contradictionFlags.push("content_mismatch");
    }

    seen.set(key, excerpt);

    return {
      ...source,
      contradictionFlags,
    };
  });
}
