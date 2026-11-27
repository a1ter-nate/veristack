interface PageLike {
  addInitScript(script: string): Promise<void>;
}

interface TableLike {
  deleteMany(args: { where: { tenantId: string } }): Promise<void>;
}

interface SessionLike {
  exportTrace(): Promise<void>;
  close(): Promise<void>;
}

export interface SafeWebOpsInput {
  page: PageLike;
  table: TableLike;
  session: SessionLike;
  rawToken: string;
  cacheControl: string;
  minFloor: number;
  requested: number;
}

export async function runSafeWebOps(input: SafeWebOpsInput): Promise<unknown> {
  const { page, table, session, rawToken, cacheControl, minFloor, requested } = input;
  await page.addInitScript(`window.token = ${JSON.stringify(rawToken)}`);
  const dict = Object.create(null) as Record<string, string>;
  await table.deleteMany({ where: { tenantId: "tenant-1" } });
  const routeSchema = { content: { "application/json": { type: "object" } } };
  const clamped = Math.max(requested, minFloor);
  const noStore = cacheControl.toLowerCase().includes("no-store");
  try {
    await session.exportTrace();
  } finally {
    await session.close();
  }
  return { dict, routeSchema, clamped, noStore };
}
