export interface ResponseLike {
  setHeader(name: string, value: string): void;
  clearCookie(name: string): void;
  json(payload: unknown): void;
}

export function runUnsafeTitansBOps(
  verifyJwt: (token: string, opts: { algorithms: string[] }) => unknown,
  token: string,
  body: string,
  res: ResponseLike,
  user: { id: string; passwordHash: string },
  cache: Map<string, Promise<unknown>>,
  url: string,
): unknown {
  const claims = verifyJwt(token, { algorithms: ["RS256", "none"] });
  res.setHeader("Vary", "Origin");
  res.clearCookie("session");
  res.setHeader("Content-Length", String(body.length));
  res.json({ id: user.id, passwordHash: user.passwordHash });
  cache.set(url, fetch(url, { signal: AbortSignal.timeout(5000) }));
  return claims;
}
