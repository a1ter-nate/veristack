import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanSingleFile } from "../src/hooks/check-file.ts";
import { lintNoComments } from "../src/no-comments.ts";
import { fitEmpiricalBigO } from "../src/zero-defect/big-o.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetFile = path.join(repoRoot, "src", "cli.ts");

const checkDurations = [];
for (let i = 0; i < 5; i++) {
  const result = scanSingleFile(targetFile, { repoRoot, tier: "immediate", maxLines: 500 });
  checkDurations.push(result.elapsedMs);
}
checkDurations.sort((a, b) => a - b);
const medianCheckMs = checkDurations[2] ?? 0;
const maxCheckMs = 250;

if (medianCheckMs > maxCheckMs) {
  console.error(`check-perf-budget: FAIL — check-file median ${medianCheckMs}ms exceeds ${maxCheckMs}ms budget.`);
  process.exit(1);
}

const scales = [100, 200, 400, 800];
const samples = [];
for (const n of scales) {
  const source = Array.from(
    { length: n },
    (_, idx) => `export function fn_${idx}(x: number): number { return x + ${idx}; }`,
  ).join("\n");
  const t0 = performance.now();
  for (let rep = 0; rep < 20; rep++) {
    lintNoComments("src/synth.ts", source, "typescript");
  }
  const elapsed = Math.max(0.01, performance.now() - t0);
  samples.push({ n, timeMs: elapsed });
}

const bigO = fitEmpiricalBigO(samples, { maxTimeExponent: 1.65 });
if (!bigO.passed) {
  console.error(
    `check-perf-budget: FAIL — empirical scaling ${bigO.timeClass} (exp=${bigO.timeExponent}, R2=${bigO.timeR2}): ${bigO.reasons.join("; ")}`,
  );
  process.exit(1);
}

console.log(
  `check-perf-budget: PASS (check-file median=${medianCheckMs}ms <= ${maxCheckMs}ms | scaling=${bigO.timeClass}, exp=${bigO.timeExponent}, R2=${bigO.timeR2}).`,
);
