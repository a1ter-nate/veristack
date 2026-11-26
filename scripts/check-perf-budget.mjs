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

const scales = [200, 400, 800, 1600];
const samples = [];
const sources = scales.map((n) => ({
  n,
  source: Array.from(
    { length: n },
    (_, idx) => `export function fn_${idx}(x: number): number { return x + ${idx}; }`,
  ).join("\n"),
}));
for (const { source } of sources) lintNoComments("src/synth.ts", source, "typescript");
for (const { n, source } of sources) {
  const trials = [];
  for (let trial = 0; trial < 5; trial++) {
    const t0 = performance.now();
    const cpu0 = process.cpuUsage();
    for (let rep = 0; rep < 15; rep++) {
      lintNoComments("src/synth.ts", source, "typescript");
    }
    const cpu = process.cpuUsage(cpu0);
    const cpuMs = (cpu.user + cpu.system) / 1000;
    trials.push(Math.max(0.01, cpuMs > 0 ? cpuMs : performance.now() - t0));
  }
  trials.sort((a, b) => a - b);
  samples.push({ n, timeMs: trials[2] ?? 0.01 });
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
