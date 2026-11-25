export function formatSafeTimestamp(raw: string): string {
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return "invalid";
  return new Intl.DateTimeFormat("en-US").format(parsed);
}

export async function fetchWithTimeout(url: string, ms = 5000): Promise<Response> {
  return fetch(url, { signal: AbortSignal.timeout(ms) });
}

export function readSafeCliArg(argv: readonly string[]): string {
  const arg = argv[3];
  return typeof arg === "string" && arg.length > 0 ? arg : "";
}

export function evaluateRulesFailClosed(violators: readonly string[]): { status: "pass" | "fail"; violators: readonly string[] } {
  return { status: violators.length === 0 ? "pass" : "fail", violators };
}
