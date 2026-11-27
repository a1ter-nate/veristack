import fs from "node:fs";
import { pathHelpers, Plugin, type CommandRunContext, type DiscoveredRepo, type Finding } from "@veristack/plugin";
import { formatBenchReport, runPrecisionBench } from "./bench.ts";
import { fitEmpiricalBigO, type ScalingSample } from "./big-o.ts";
import { analyzeCveAndPostmortemGuards } from "./cve-and-agent-guards.ts";
import {
  compareInvariantSnapshots,
  formatInvariantDiffReport,
  inferDynamicInvariants,
  type InvariantSnapshot,
  type TraceSample,
  writeInvariantSnapshot,
} from "./daikon-invariants.ts";
import { analyzeEcosystemGuards } from "./ecosystem-guards.ts";
import { analyzeOssGuards } from "./oss-guards.ts";
import { analyzePerfHygiene } from "./perf-lints.ts";
import { analyzeRuntimeGuards } from "./runtime-guards.ts";
import {
  auditZeroDefectArtifacts,
  evaluateSpcSeries,
  generateMcdcVectors,
  runRedBeforeFix,
  runTwoSidedOracleCheck,
} from "./zero-defect.ts";

export { formatBenchReport, runPrecisionBench, type BenchReport } from "./bench.ts";
export { fitEmpiricalBigO, measureEmpiricalBigO, type ScalingSample } from "./big-o.ts";
export { analyzeCveAndPostmortemGuards } from "./cve-and-agent-guards.ts";
export {
  compareInvariantSnapshots,
  formatInvariantDiffReport,
  inferDynamicInvariants,
  writeInvariantSnapshot,
  type InvariantDiffReport,
  type InvariantSnapshot,
  type TraceSample,
} from "./daikon-invariants.ts";
export { analyzeEcosystemGuards } from "./ecosystem-guards.ts";
export { generateMcdcVectors, type McdcResult, type McdcVector } from "./mcdc.ts";
export { analyzeOssGuards } from "./oss-guards.ts";
export { analyzePerfHygiene } from "./perf-lints.ts";
export { analyzeRuntimeGuards } from "./runtime-guards.ts";
export {
  auditZeroDefectArtifacts,
  computeRolledThroughputYield,
  evaluateSpcSeries,
  runRedBeforeFix,
  runTwoSidedOracleCheck,
  type RedBeforeFixResult,
  type SpcResult,
  type TwoSidedOracleResult,
} from "./zero-defect.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const GENERATED_HEADER = /(?:@generated|auto-generated|do\s+not\s+edit|generated\s+by\b)/i;

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) return args[i + 1];
    if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
  }
  return undefined;
}

function runZeroDefectAnalyzers(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    if (file.rel.endsWith(".sql")) {
      if (/(?:^|\/)migrations?\//i.test(file.rel)) findings.push(...analyzeCveAndPostmortemGuards(file));
      continue;
    }
    const isStub = Boolean(file.isStub) || pathHelpers.isDeclarationStub(file.rel);
    if (!file.language || file.isTest || isStub) continue;
    if (GENERATED_PATH.test(file.rel) && GENERATED_HEADER.test(file.content.slice(0, 600))) continue;
    findings.push(...analyzeRuntimeGuards(file), ...analyzeOssGuards(file), ...analyzeCveAndPostmortemGuards(file));
  }
  findings.push(...analyzeEcosystemGuards(repo), ...analyzePerfHygiene(repo), ...auditZeroDefectArtifacts(repo));
  return findings;
}

function runBigOCommand(ctx: CommandRunContext): number {
  const samplesPath = ctx.target;
  if (!samplesPath || samplesPath === ".") {
    throw new Error("vstack big-o requires a JSON samples file ({ samples: [{ n, timeMs, memoryBytes? }], maxTimeExponent? }).");
  }
  const parsed = JSON.parse(fs.readFileSync(samplesPath, "utf8")) as {
    samples: ScalingSample[];
    maxTimeExponent?: number;
    maxSpaceExponent?: number;
  };
  const maxTimeRaw = parseFlagValue(ctx.rest, "--max-time-exp");
  const maxSpaceRaw = parseFlagValue(ctx.rest, "--max-space-exp");
  const maxTimeExp = maxTimeRaw !== undefined ? Number(maxTimeRaw) : Math.min(1.45, parsed.maxTimeExponent ?? 1.45);
  const maxSpaceExp = maxSpaceRaw !== undefined ? Number(maxSpaceRaw) : parsed.maxSpaceExponent;
  if (!Number.isFinite(maxTimeExp) || maxTimeExp <= 0 || maxTimeExp > 2.5) {
    throw new Error(`Invalid --max-time-exp '${maxTimeRaw ?? String(maxTimeExp)}'; expected a number in (0, 2.5].`);
  }
  if (maxSpaceExp !== undefined && (!Number.isFinite(maxSpaceExp) || maxSpaceExp <= 0 || maxSpaceExp > 2.5)) {
    throw new Error(`Invalid --max-space-exp '${maxSpaceRaw ?? String(maxSpaceExp)}'; expected a number in (0, 2.5].`);
  }
  const result = fitEmpiricalBigO(parsed.samples, { maxTimeExponent: maxTimeExp, maxSpaceExponent: maxSpaceExp });
  if (ctx.asJson) console.log(JSON.stringify(result, null, 2));
  else {
    const spaceStr = result.spaceExponent !== null ? ` spaceExp=${result.spaceExponent} (${result.spaceClass})` : "";
    console.log(`Big-O [${result.passed ? "PASS" : "FAIL"}]: timeExp=${result.timeExponent} (${result.timeClass}, R2=${result.timeR2})${spaceStr}`);
    for (const r of result.reasons) console.log(`  - ${r}`);
  }
  return ctx.rest.includes("--fail") && !result.passed ? 1 : 0;
}

function runInvariantsCommand(ctx: CommandRunContext): number {
  const tracesPath = ctx.target;
  if (!tracesPath || tracesPath === ".") {
    throw new Error("vstack invariants requires a JSON traces file ({ samples: [{ fn, args?, result?, throws? }] }).");
  }
  const parsed = JSON.parse(fs.readFileSync(tracesPath, "utf8")) as { samples?: TraceSample[] } | TraceSample[];
  const samples = Array.isArray(parsed) ? parsed : (parsed.samples ?? []);
  const current = inferDynamicInvariants(samples);
  const baselinePath = parseFlagValue(ctx.rest, "--baseline");
  const update = ctx.rest.includes("--update");
  if (update && ctx.rest.includes("--fail")) {
    throw new Error("vstack invariants forbids combining --update with --fail (prevents self-passing rebaseline in CI).");
  }
  let diff: ReturnType<typeof compareInvariantSnapshots> | undefined;
  if (baselinePath) {
    if (update) {
      writeInvariantSnapshot(baselinePath, current);
      diff = compareInvariantSnapshots(current, current, baselinePath);
    } else {
      if (!fs.existsSync(baselinePath)) {
        throw new Error(`Invariants baseline not found at '${baselinePath}'. Pass --update explicitly to initialize a new baseline.`);
      }
      diff = compareInvariantSnapshots(JSON.parse(fs.readFileSync(baselinePath, "utf8")) as InvariantSnapshot, current, baselinePath);
    }
  }
  console.log(ctx.asJson ? JSON.stringify(diff ? { snapshot: current, diff } : { snapshot: current }, null, 2) : formatInvariantDiffReport(current, diff));
  if (ctx.rest.includes("--fail")) {
    if (!baselinePath) { console.error("vstack invariants --fail requires --baseline <file> to detect regressions."); return 1; }
    if (samples.length === 0 || (diff && !diff.passed)) return 1;
  }
  return 0;
}

function runBenchCommand(c: CommandRunContext): number {
  const report = runPrecisionBench(c.target, parseFlagValue(c.rest, "--corpus"), parseFlagValue(c.rest, "--replay"));
  console.log(c.asJson ? JSON.stringify(report, null, 2) : formatBenchReport(report));
  return c.rest.includes("--fail") && !report.passed ? 1 : 0;
}

function runOracleCheckCommand(c: CommandRunContext): number {
  const baseRef = parseFlagValue(c.rest, "--base");
  if (!baseRef) throw new Error("vstack oracle-check requires an explicit --base <ref> (e.g. origin/main or HEAD~1).");
  const testCmd = parseFlagValue(c.rest, "--test-cmd");
  if (!testCmd) throw new Error("vstack oracle-check requires --test-cmd <command>.");
  const result = runTwoSidedOracleCheck(c.target, baseRef, testCmd);
  console.log(c.asJson ? JSON.stringify(result, null, 2) : `${result.passed ? "PASS" : "FAIL"}: ${result.reason}`);
  return result.passed ? 0 : 1;
}

function runRedBeforeFixCommand(c: CommandRunContext): number {
  const testCmd = parseFlagValue(c.rest, "--test-cmd");
  if (!testCmd) throw new Error("vstack red-before-fix requires --test-cmd <command>.");
  const result = runRedBeforeFix(c.target, parseFlagValue(c.rest, "--base") ?? "HEAD", testCmd);
  console.log(c.asJson ? JSON.stringify(result, null, 2) : `${result.passed ? "PASS" : "FAIL"}: ${result.reason}`);
  return result.passed ? 0 : 1;
}

function runMcdcCommand(c: CommandRunContext): number {
  const expr = c.target;
  if (!expr || expr === ".") throw new Error('vstack mcdc requires a boolean expression, e.g. vstack mcdc "a || (b && !c)".');
  const result = generateMcdcVectors(expr);
  if (c.asJson) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`MC/DC Independence Table for: ${result.expression} (${result.vectors.length} vectors)`);
    for (const row of result.vectors) {
      const vals = result.variables.map((v) => `${v}=${row.inputs[v] ? "T" : "F"}`).join(" ");
      console.log(`  #${row.index}: ${vals} => ${row.output ? "T" : "F"}  [proves: ${row.provesIndependent.join(", ")}]`);
    }
    if (result.uncoveredVariables.length > 0) console.log(`  UNCOVERED (redundant/dead condition): ${result.uncoveredVariables.join(", ")}`);
  }
  return result.uncoveredVariables.length > 0 ? 1 : 0;
}

function runSpcCommand(c: CommandRunContext): number {
  if (!c.target || c.target === ".") throw new Error("vstack spc requires a JSON metrics file ({ metric, upperSpecLimit, values }).");
  const parsed = JSON.parse(fs.readFileSync(c.target, "utf8")) as { metric: string; upperSpecLimit: number; values: number[] };
  const result = evaluateSpcSeries(parsed.metric, parsed.values, parsed.upperSpecLimit);
  if (c.asJson) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`SPC [${result.status.toUpperCase()}] ${result.metric}: n=${result.count} mean=${result.mean} sd=${result.stdDev} USL=${result.upperSpecLimit} Cpk=${result.cpk ?? "n/a"}`);
    for (const r of result.reasons) console.log(`  - ${r}`);
  }
  return c.rest.includes("--fail") && result.status !== "in_control" ? 1 : 0;
}

export const zeroDefectPlugin = Plugin.define({
  id: "veristack.plugin.zero-defect",
  setup(ctx) {
    if (!ctx) throw new Error("Plugin context is required.");
    ctx.analyzer.transform((ed) => {
      ed.add({ id: "veristack.zero-defect.guards", phase: "lint", run: (runCtx) => runZeroDefectAnalyzers(runCtx.repo) });
    });
    ctx.command.transform((ed) => {
      ed.add({ id: "veristack.cmd.bench", name: "bench", usage: "vstack bench [dir] [--corpus <dir>] [--replay <dir>] [--json] [--fail]", run: runBenchCommand });
      ed.add({ id: "veristack.cmd.oracle-check", name: "oracle-check", usage: "vstack oracle-check [dir] --base <ref> --test-cmd <cmd> [--json]", run: runOracleCheckCommand });
      ed.add({ id: "veristack.cmd.red-before-fix", name: "red-before-fix", usage: "vstack red-before-fix [dir] --base <ref> --test-cmd <cmd> [--json]", run: runRedBeforeFixCommand });
      ed.add({ id: "veristack.cmd.mcdc", name: "mcdc", usage: 'vstack mcdc "<boolean expression>" [--json]', run: runMcdcCommand });
      ed.add({ id: "veristack.cmd.spc", name: "spc", usage: "vstack spc <metrics.json> [--json] [--fail]", run: runSpcCommand });
      ed.add({ id: "veristack.cmd.big-o", name: "big-o", usage: "vstack big-o <samples.json> [--max-time-exp <num>] [--max-space-exp <num>] [--json] [--fail]", run: runBigOCommand });
      ed.add({ id: "veristack.cmd.invariants", name: "invariants", usage: "vstack invariants <traces.json> [--baseline <file>] [--update] [--json] [--fail]", run: runInvariantsCommand });
    });
  },
});

export default zeroDefectPlugin;
