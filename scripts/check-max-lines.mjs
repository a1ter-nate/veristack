import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const LOCKFILE_OR_GENERATED =
  /(?:^|\/)(?:Cargo\.lock|uv\.lock|bun\.lockb?|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|go\.sum)$|^dist\//;

const args = process.argv.slice(2);
const maxIdx = args.indexOf("--max");
const maxLines = maxIdx >= 0 && args[maxIdx + 1] ? Number(args[maxIdx + 1]) : 500;
const dirIdx = args.indexOf("--dir");
const rootDir = path.resolve(dirIdx >= 0 && args[dirIdx + 1] ? args[dirIdx + 1] : process.cwd());

if (!Number.isFinite(maxLines) || maxLines <= 0) {
  console.error(`Invalid --max value: ${args[maxIdx + 1] ?? ""}`);
  process.exit(2);
}

const listed = spawnSync("git", ["-C", rootDir, "ls-files", "-z"], { encoding: "utf8" });
if (listed.status !== 0) {
  console.error(`git ls-files failed: ${(listed.stderr ?? "").trim()}`);
  process.exit(1);
}

const offenders = [];
const files = listed.stdout.split("\0").filter(Boolean);
let checked = 0;

for (const rel of files) {
  if (LOCKFILE_OR_GENERATED.test(rel)) continue;
  const abs = path.join(rootDir, rel);
  let stat;
  try {
    stat = fs.lstatSync(abs);
  } catch {
    continue;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) continue;
  const buf = fs.readFileSync(abs);
  if (buf.includes(0)) continue;
  const text = buf.toString("utf8");
  const lines = text.length === 0 ? 0 : text.split(/\r?\n/).length;
  checked += 1;
  if (lines > maxLines) {
    offenders.push({ rel, lines });
  }
}

if (offenders.length > 0) {
  offenders.sort((a, b) => b.lines - a.lines);
  console.error(`check-max-lines: ${offenders.length} file(s) exceed ${maxLines}-line hard ceiling:`);
  for (const item of offenders) {
    console.error(`  - ${item.rel}: ${item.lines} lines (limit: ${maxLines})`);
  }
  process.exit(1);
}

console.log(`check-max-lines: PASS (${checked} tracked files checked, all <= ${maxLines} lines).`);
