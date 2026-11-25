import fs from "node:fs";

interface ReqLike {
  body: { key: string; target: string; expr: string };
}

interface ResLike {
  redirect(url: string): void;
}

interface DbLike {
  query(sql: string): Promise<unknown>;
}

export function handleUnsafeTaint(req: ReqLike, res: ResLike, db: DbLike, el: { innerHTML: string }): unknown {
  const { key, target, expr } = req.body;
  const bag: Record<string, unknown> = {};
  bag[key] = target;
  res.redirect(target);
  el.innerHTML = target;
  void db.query(`SELECT * FROM users WHERE id = ${target}`);
  const evaluated = eval(expr);
  return { bag, evaluated };
}

export function handleDuplicateSwitch(code: string): number {
  switch (code) {
    case "a":
      return 1;
    case "a":
      return 2;
    default:
      return 0;
  }
}

export async function missingAwaitInTry(fetchData: () => Promise<string>): Promise<string> {
  try {
    return fetchData();
  } catch {
    return "fallback";
  }
}

export function leakyLinearHandles(filePath: string, useEffect: (fn: () => void) => void): void {
  const fd = fs.openSync(filePath, "r");
  const stream = fs.createWriteStream(filePath);
  stream.close();
  stream.write("after-close");
  useEffect(() => {
    setInterval(() => {}, 1000);
  });
  void fd;
}
