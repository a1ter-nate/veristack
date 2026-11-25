import fs from "node:fs";

export function handleSafeLookup(key: string, value: string): Map<string, string> {
  const bag = new Map<string, string>();
  bag.set(key, value);
  return bag;
}

export async function awaitedInsideTry(fetchData: () => Promise<string>): Promise<string> {
  try {
    return await fetchData();
  } catch {
    return "fallback";
  }
}

export function safeLinearHandle(filePath: string, useEffect: (fn: () => () => void) => void): void {
  const fd = fs.openSync(filePath, "r");
  try {
    fs.fstatSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  useEffect(() => {
    const id = setInterval(() => {}, 1000);
    return () => clearInterval(id);
  });
}
