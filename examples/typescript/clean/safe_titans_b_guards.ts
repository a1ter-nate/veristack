export interface SafeResponseLike {
  getHeader(name: string): string | undefined;
  setHeader(name: string, value: string): void;
  clearCookie(name: string, opts: { path: string; secure: boolean; sameSite: "lax" }): void;
  json(payload: unknown): void;
}

export function runSafeTitansBOps(
  verifyJwt: (token: string, opts: { algorithms: string[] }) => unknown,
  token: string,
  body: string,
  res: SafeResponseLike,
  user: { id: string; displayName: string },
  cache: Map<string, Promise<unknown>>,
  url: string,
): unknown {
  const claims = verifyJwt(token, { algorithms: ["RS256"] });
  const existingVary = res.getHeader("Vary");
  res.setHeader("Vary", existingVary ? `${existingVary}, Origin` : "Origin");
  res.clearCookie("session", { path: "/", secure: true, sameSite: "lax" });
  res.setHeader("Content-Length", String(Buffer.byteLength(body, "utf8")));
  res.json({ id: user.id, displayName: user.displayName });
  const pending = fetch(url, { signal: AbortSignal.timeout(5000) }).catch((err) => {
    cache.delete(url);
    throw err;
  });
  cache.set(url, pending);
  return claims;
}
