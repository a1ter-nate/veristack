function Component(_meta: { selector: string }): ClassDecorator {
  return () => {};
}

@Component({ selector: "app-ticker" })
export class LeakyTickerComponent {
  public start(tick: () => void): void {
    setInterval(tick, 1000);
  }
}

export function runUnsafeTitansAOps(
  score: number,
  redirectUrl: string,
  req: { originalUrl: string },
): boolean {
  if (score === NaN) return false;
  if (redirectUrl.startsWith("/") && !redirectUrl.startsWith("//")) {
    return true;
  }
  if (req.originalUrl.startsWith("/admin")) {
    return 403 > 0;
  }
  return false;
}
