import { Plugin, type CommandRunContext } from "@veristack/plugin";
import { runPlantedFaultCanaryAsync } from "./mutation-probe.ts";
import { loadValidReceipts, runAllDeclaredRungsAsync } from "./receipts.ts";
import { evaluateCrapForCoverageFile } from "./reports.ts";

export { classifyCanaryOutcome, executeCanaryPlanAsync, isRetryableCanarySignal, type AsyncCanaryTask } from "./canary-runner.ts";
export {
  insertSemanticNoOp,
  runPlantedFaultCanary,
  runPlantedFaultCanaryAsync,
  type CanaryOptions,
} from "./mutation-probe.ts";
export { runTwoSidedOracleCheck, type TwoSidedOracleResult } from "./oracle-check.ts";
export {
  computeRepoTreeHash,
  hasGitTrackedReceipts,
  loadValidReceipts,
  runAllDeclaredRungs,
  runAllDeclaredRungsAsync,
  runRungAndWriteReceipt,
} from "./receipts.ts";
export { computeCrapScore, evaluateCrapForCoverageFile, parseStructuredReports, reportParsers } from "./reports.ts";
export { hasTestRunnerCommand, parseRunnerTestCounts, stripAnsi } from "./runner-metrics.ts";

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) return args[i + 1];
    if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
  }
  return undefined;
}

async function runCanaryCommand(ctx: CommandRunContext): Promise<number> {
  const testCmd = parseFlagValue(ctx.rest, "--test-cmd");
  if (!testCmd) throw new Error("vstack canary requires --test-cmd <command>.");
  const targetsRaw = parseFlagValue(ctx.rest, "--targets");
  const maxRaw = parseFlagValue(ctx.rest, "--max-mutants");
  const minRateRaw = parseFlagValue(ctx.rest, "--min-kill-rate");
  const report = await runPlantedFaultCanaryAsync({
    repoRoot: ctx.target,
    testCmd,
    targets: targetsRaw ? targetsRaw.split(",").map((t) => t.trim()).filter(Boolean) : undefined,
    baseRef: parseFlagValue(ctx.rest, "--base"),
    maxMutants: maxRaw ? Number(maxRaw) : undefined,
    minKillRate: minRateRaw ? Number(minRateRaw) : undefined,
  });
  if (ctx.asJson) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`canary [${report.passed ? "PASS" : "FAIL"}]: killed=${report.killedMutants}/${report.totalMutants} (${(report.killRate * 100).toFixed(1)}%, floor=${(report.minKillRate * 100).toFixed(0)}%, invalid=${report.invalidKills})`);
    for (const s of report.survivors) console.log(`  - [SURVIVED] ${s.file}:${s.line} (${s.operator}) — ${s.original}`);
    for (const d of report.invalidDiagnostics ?? []) console.log(`  - [INVALID] ${d}`);
  }
  return ctx.rest.includes("--fail") && !report.passed ? 1 : 0;
}

function runCrapCommand(ctx: CommandRunContext): number {
  const covPath = parseFlagValue(ctx.rest, "--coverage");
  if (!covPath) throw new Error("vstack crap requires --coverage <lcov.info|cobertura.xml>.");
  const maxRaw = parseFlagValue(ctx.rest, "--max-crap");
  const report = evaluateCrapForCoverageFile(ctx.target, covPath, maxRaw ? Number(maxRaw) : 30);
  if (ctx.asJson) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`crap [${report.passed ? "PASS" : "FAIL"}]: evaluated=${report.evaluatedFiles} worst=${report.worstCrap} maxAllowed=${report.maxAllowed} offenders=${report.offenders.length}`);
    for (const o of report.offenders.slice(0, 20)) console.log(`  - ${o.file}: CRAP=${o.crapScore} (CC=${o.cyclomaticComplexity}, cov=${o.coveragePct}%)`);
  }
  return ctx.rest.includes("--fail") && !report.passed ? 1 : 0;
}

export const canaryPlugin = Plugin.define({
  id: "veristack.plugin.canary",
  guarded: true,
  setup(ctx) {
    ctx.rung.transform((ed) => {
      ed.add({
        id: "veristack.canary.receipts",
        loadReceipts: (repo, manifest, opts) => {
          const loaded = loadValidReceipts(repo, manifest, opts);
          const recObj: Record<string, unknown> = {};
          for (const [k, v] of loaded.receipts.entries()) recObj[k] = v;
          return { receipts: recObj, findings: loaded.findings };
        },
        runAllDeclaredRungsAsync,
      });
    });
    ctx.command.transform((ed) => {
      ed.add({
        id: "veristack.cmd.canary",
        name: "canary",
        usage: "vstack canary [dir] --test-cmd <cmd> [--targets <files>] [--base <ref>] [--max-mutants <n>] [--min-kill-rate <0..1>] [--json] [--fail]",
        run: runCanaryCommand,
      });
      ed.add({
        id: "veristack.cmd.crap",
        name: "crap",
        usage: "vstack crap [dir] --coverage <lcov|cobertura> [--max-crap <n>] [--json] [--fail]",
        run: runCrapCommand,
      });
    });
  },
});

export default canaryPlugin;
