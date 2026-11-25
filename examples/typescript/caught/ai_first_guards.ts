import { spawn } from "node:child_process";

export async function runUnsafeAiFirstOps(
  uri: string,
  response: { body?: { cancel: () => Promise<void> } },
  retryAfterMs: number,
  ext: { prototype: object },
): Promise<unknown> {
  const localPath = uri.replace("file://", "");
  const child = spawn("cmd", ["/c", "echo hi"]);
  await response.body?.cancel();
  const systemPrompt = `Current time: ${Date.now()}`;
  await new Promise((r) => setTimeout(r, retryAfterMs));
  const protoKeys = Object.getOwnPropertyNames(ext.prototype);
  return { localPath, child, systemPrompt, protoKeys };
}
