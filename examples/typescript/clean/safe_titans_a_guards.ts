import path from "node:path";

function Component(_meta: { selector: string }): ClassDecorator {
  return () => {};
}

@Component({ selector: "app-ticker" })
export class SafeTickerComponent {
  private handle: ReturnType<typeof setInterval> | undefined;

  public start(tick: () => void): void {
    this.handle = setInterval(tick, 1000);
  }

  public ngOnDestroy(): void {
    if (this.handle !== undefined) clearInterval(this.handle);
  }
}

export function runSafeTitansAOps(
  score: number,
  redirectUrl: string,
  req: { originalUrl: string },
): boolean {
  if (Number.isNaN(score)) return false;
  if (redirectUrl.startsWith("/") && !redirectUrl.startsWith("//") && !redirectUrl.includes("\\")) {
    return true;
  }
  const normalized = path.posix.normalize(decodeURIComponent(req.originalUrl));
  if (normalized.startsWith("/admin")) {
    return 403 > 0;
  }
  return false;
}
