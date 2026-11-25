interface PageLike {
  addInitScript(script: string): Promise<void>;
}

interface TableLike {
  deleteMany(args?: Record<string, unknown>): Promise<void>;
}

interface HttpLike {
  setHeader(name: string, value: string): void;
}

interface SessionLike {
  exportTrace(): Promise<void>;
  close(): Promise<void>;
}

export async function runUnsafeWebOps(
  page: PageLike,
  table: TableLike,
  res: HttpLike,
  session: SessionLike,
  rawToken: string,
  cacheControl: string,
  minFloor: number,
  requested: number,
): Promise<unknown> {
  await page.addInitScript(`window.token = "${rawToken}"`);
  const dict = { __proto__: null };
  const unchanged = rawToken.replace("'", "'");
  const dyn = new RegExp(`^${rawToken}$`);
  await table.deleteMany();
  const routeSchema = { content: { "Application/JSON": { type: "object" } } };
  res.setHeader("Content-Length", "12");
  res.setHeader("Transfer-Encoding", "chunked");
  const capped = Math.min(requested, minFloor);
  const noStore = cacheControl.includes("no-store");
  await session.exportTrace();
  await session.close();
  return { dict, unchanged, dyn, routeSchema, capped, noStore };
}
