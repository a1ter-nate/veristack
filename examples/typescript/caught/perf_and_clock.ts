export interface RecordItem {
  id: string;
  label: string;
}

export function matchLabels(ids: readonly string[], catalog: readonly RecordItem[], pattern: string): string[] {
  const started = Date.now();
  const out: string[] = [];
  for (const id of ids) {
    const found = catalog.find((item) => item.id === id);
    const re = new RegExp(pattern);
    if (found && re.test(found.label)) {
      out.push(found.label);
    }
  }
  if (Date.now() - started > 1000) {
    return [];
  }
  return out;
}

export function drainForever(hasMore: () => boolean): void {
  while (true) {
    if (!hasMore()) break;
  }
}
