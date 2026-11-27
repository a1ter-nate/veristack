import path from "node:path";

const MAX_ALLOC_BYTES = 1024 * 64;

export interface SafeCveInput {
  destDir: string;
  entry: { name: string };
  hdr: { targetSize: number };
  raw: string;
  rawToken: unknown;
  leaseDeadlineMs: number;
}

export function safeCvePatterns(
  input: SafeCveInput,
): { size: number; outPath: string; serialized: string; token: string; expired: boolean } {
  const { destDir, entry, hdr, raw, rawToken, leaseDeadlineMs } = input;
  const clampedSize = Math.min(hdr.targetSize, MAX_ALLOC_BYTES);
  const buf = Buffer.alloc(clampedSize);
  const root = path.resolve(destDir);
  const outPath = path.resolve(root, entry.name);
  if (!outPath.startsWith(`${root}${path.sep}`)) {
    throw new Error("Path traversal blocked");
  }
  const serialized = JSON.stringify(raw);
  if (typeof rawToken !== "string") {
    throw new Error("Invalid token type");
  }
  const expired = leaseDeadlineMs < performance.now();
  return { size: buf.length, outPath, serialized, token: rawToken, expired };
}
