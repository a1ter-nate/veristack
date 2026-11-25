export async function runUnsafeBlackHoleOps(
  opts: { maxAge?: number },
  signal: AbortSignal,
  headers: Record<string, string>,
  parsedUrl: URL,
  session: { execute: (sql: string) => Promise<void> },
  stack: string[],
  step: () => void,
  useEffect: (fn: () => void) => void,
  setDerived: (v: string) => void,
  Schema: { decodeUnknownSync: (s: unknown) => (x: unknown) => unknown },
  items: unknown[],
  title: string,
): Promise<string> {
  if ("maxAge" in opts) {
    opts.maxAge = opts.maxAge / 1000;
  }
  signal.addEventListener("abort", () => {});
  delete headers["content-type"];
  session.execute("SAVEPOINT s1");
  stack.push("frame");
  step();
  stack.pop();
  useEffect(() => {
    setDerived(title.slice(0, 40));
  });
  for (const item of items) {
    Schema.decodeUnknownSync(item);
  }
  return `${parsedUrl.hostname}:8080`;
}
