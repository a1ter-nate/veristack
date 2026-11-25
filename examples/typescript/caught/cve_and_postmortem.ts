import path from "node:path";

export function unsafeCvePatterns(
  destDir: string,
  entry: { name: string },
  hdr: { targetSize: number },
  raw: string,
  req: { cookies: { authToken: unknown } },
  db: { tokens: { findOne: (q: unknown) => Promise<unknown> } },
  apiBase: string,
  userPath: string,
  token: string,
  leaseExpiry: number,
): unknown {
  const buf = Buffer.alloc(hdr.targetSize);
  const outPath = path.join(destDir, entry.name);
  const badRegex = /^(a+)+$/;
  const escaped = raw.replace(/'/g, "\\'");
  void db.tokens.findOne(req.cookies.authToken);
  void fetch(apiBase + userPath, { headers: { Authorization: token } });
  const expired = leaseExpiry < Date.now();
  setTimeout(() => {}, 2500000000);
  return { buf, outPath, badRegex, escaped, expired };
}
