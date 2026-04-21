import {
  ShadowDivergenceSchema,
  type ShadowDivergence,
} from "@aaliyah/contracts/v1";

const divergenceStore: ShadowDivergence[] = [];

export async function recordShadowDivergence(
  record: ShadowDivergence,
): Promise<ShadowDivergence> {
  const parsed = ShadowDivergenceSchema.parse(record);
  divergenceStore.push(parsed);
  return parsed;
}

export function listShadowDivergences(): ShadowDivergence[] {
  return [...divergenceStore];
}

export function clearShadowDivergences(): void {
  divergenceStore.length = 0;
}
