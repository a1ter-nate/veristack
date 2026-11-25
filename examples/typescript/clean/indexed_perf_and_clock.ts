export interface CatalogItem {
  readonly id: string;
  readonly label: string;
}

export function matchCatalogLabels(
  ids: readonly string[],
  catalog: readonly CatalogItem[],
  pattern: string,
): { readonly labels: string[]; readonly elapsedMs: number } {
  const started = performance.now();
  const byId = new Map(catalog.map((item) => [item.id, item]));
  const matcher = new RegExp(pattern);
  const labels: string[] = [];

  for (const id of ids) {
    const found = byId.get(id);
    if (found && matcher.test(found.label)) {
      labels.push(found.label);
    }
  }

  return { labels, elapsedMs: performance.now() - started };
}

export function drainBounded(hasMore: () => boolean, maxAttempts: number): number {
  let attempts = 0;
  while (attempts < maxAttempts && hasMore()) {
    attempts += 1;
  }
  return attempts;
}
