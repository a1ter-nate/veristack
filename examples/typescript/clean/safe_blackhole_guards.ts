export async function runSafeBlackHoleOps(
  opts: { maxAge?: number },
  signal: AbortSignal,
  headers: Record<string, string>,
  parsedUrl: URL,
  session: { execute: (sql: string) => Promise<void> },
  stack: string[],
  step: () => void,
  decodeItem: (x: unknown) => unknown,
  items: unknown[],
  title: string,
): Promise<string> {
  if (opts.maxAge != null) {
    opts.maxAge = opts.maxAge / 1000;
  }
  if (signal.aborted) return "";
  signal.addEventListener("abort", () => {});
  delete headers["content-type"];
  delete headers["content-length"];
  await session.execute("SAVEPOINT s1");
  stack.push("frame");
  try {
    step();
  } finally {
    stack.pop();
  }
  const shortTitle = [...title].slice(0, 40).join("");
  for (const item of items) {
    decodeItem(item);
  }
  const host = parsedUrl.hostname.includes(":") ? `[${parsedUrl.hostname}]` : parsedUrl.hostname;
  return `${host}:8080:${shortTitle}`;
}
