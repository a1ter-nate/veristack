export interface BoundedBatchInput {
  items: readonly number[];
  timeoutMsMax: number;
  startIndex: number;
  endIndex: number;
}

export function sumBoundedRange(input: BoundedBatchInput): number {
  if (input.startIndex < 0 || input.endIndex < input.startIndex) {
    throw new Error("Invalid index range");
  }
  const limit = Math.min(input.endIndex, input.items.length);
  let total = 0;
  for (let i = input.startIndex; i < limit; i++) {
    total += input.items[i] ?? 0;
  }
  return total;
}

export async function fetchWithExplicitTimeout(url: string, timeoutMsMax: number): Promise<Response> {
  if (!url) throw new Error("url is required");
  return fetch(url, { signal: AbortSignal.timeout(timeoutMsMax) });
}
