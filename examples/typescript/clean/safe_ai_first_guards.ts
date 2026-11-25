import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const MAX_RETRY_WAIT_MS = 30_000;

export async function runSafeAiFirstOps(
  uri: string,
  response: { text: () => Promise<string> },
  retryAfterMs: number,
  ext: { prototype: object },
): Promise<unknown> {
  const localPath = fileURLToPath(uri);
  const child = spawn("node", ["--version"]);
  child.on("error", () => {});
  await response.text();
  const boundedWait = Math.min(retryAfterMs, MAX_RETRY_WAIT_MS);
  const protoKeys = Object.getOwnPropertyNames(ext.prototype).filter((name) => name !== "constructor");
  return { localPath, child, boundedWait, protoKeys };
}
