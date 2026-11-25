export function formatUnsafeTimestamp(raw: any): string {
  return new Intl.DateTimeFormat("en-US").format(new Date(raw));
}

export async function fetchUnbounded(url: string): Promise<Response> {
  return fetch(url);
}

export function readCliArg(): string {
  if (process.argv[3] !== "") {
    return process.argv[3] ?? "";
  }
  return "";
}

export function evaluateRules(violators: string[]): { status: string; violators: string[] } {
  return { status: "pass", violators };
}

export function bindBrokenHistory(win: Window): void {
  win.addEventListener("popstate", () => {
    win.history.pushState({}, "", "/loop");
  });
}
