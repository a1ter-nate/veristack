import crypto from "node:crypto";

interface ResponseLike {
  status(code: number): ResponseLike;
  json(body: unknown): ResponseLike;
}

export function handleOrderSafely(res: ResponseLike, count: number | null, items: readonly string[]): unknown {
  if (count === null) {
    return res.status(400).json({ error: "missing" });
  }
  const resolvedCount = count ?? 1;
  const nextItems = [...items, "audit"];
  return { resolvedCount, nextItems };
}

export function getCachedProfileSafely(
  profileCache: Map<string, { role: string }>,
  id: string,
): { role: string } | undefined {
  const hit = profileCache.get(id);
  return hit ? structuredClone(hit) : undefined;
}

export function signTokenSafely(token: string, signingSecret: string): string {
  return crypto.createHmac("sha256", signingSecret).update(token).digest("hex");
}

export async function drainPagesSafely(
  nextCursor: () => Promise<string | null>,
  maxPages = 10,
): Promise<number> {
  let pages = 0;
  let cursor: string | null = "start";
  do {
    cursor = await nextCursor();
    pages += 1;
  } while (cursor !== null && pages < maxPages);
  return pages;
}
