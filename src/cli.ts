import fs from "node:fs";
import { scanGitDiffCheats } from "./ci-auditor.ts";
import { createSystem1Engine, formatCircuitReport, listDefaultCircuits, runRepoCircuit } from "./circuits/index.ts";
import { discoverRepo } from "./discover.ts";
import { formatFindingsList, formatSystem1Report } from "./format.ts";
import { handleHooksAndDoctorCli } from "./hooks/index.ts";
import { lintNoComments } from "./no-comments.ts";
import { handleRungToolsCli, handleScanCli } from "./rungs/scan-cli.ts";
import { analyzeStateMachines } from "./state-machines/index.ts";
import { buildSystem1Packet, corroborateSystem1Batch } from "./system1-classifier.ts";
import { runSystem1Provider } from "./system1-providers.ts";
import type { CircuitId, Finding, System1ModelAnswer, System1ProviderId } from "./types.ts";
import { formatBenchReport, runPrecisionBench } from "./zero-defect/bench.ts";
import { fitEmpiricalBigO, type ScalingSample } from "./zero-defect/big-o.ts";
import {
  compareInvariantSnapshots,
  formatInvariantDiffReport,
  inferDynamicInvariants,
  type InvariantSnapshot,
  type TraceSample,
  writeInvariantSnapshot,
} from "./zero-defect/daikon-invariants.ts";
import { auditFormalSync, formatFormalSyncReport } from "./zero-defect/formal-sync.ts";
import { evaluateSpcSeries, generateMcdcVectors, runRedBeforeFix, runTwoSidedOracleCheck } from "./zero-defect/index.ts";
import { auditLaws, formatLawsReport } from "./zero-defect/laws.ts";
import {
  buildReviewBrief,
  formatReviewBriefMarkdown,
  formatReviewBriefTerminal,
} from "./anti-slop/review-brief.ts";

const VALID_PROVIDERS = new Set<System1ProviderId>(["laya", "jev", "local", "command", "fixture"]);
const VALID_CIRCUITS = new Set<CircuitId>([
  "test-triage",
  "pr-risk-router",
  "instruction-lint-promoter",
  "perf-architecture-advisor",
]);

function usage(): string {
  return [
    "vstack — Deterministic Verification Stack, Push-Down Analyzer, Formal Checks & JEV-Style System 1 Circuits",
    "",
    "Commands:",
    "  vstack scan [dir] [--json | --md] [--config <file>] [--disable <rules>] [--ratchet <file>] [--ratchet-base <ref>] [--update-ratchet] [--strict] [--allow-missing-rungs] [--fail-on-poor-coverage] [--fail-on-cheats] [--fail-on-errors]",
    "  vstack verify [dir] [--strict] [--json | --md]",
    "  vstack run-rung <R0..R8|all> [dir] [--json]",
    "  vstack canary [dir] --test-cmd <cmd> [--targets <files>] [--base <ref>] [--max-mutants <n>] [--min-kill-rate <0..1>] [--json] [--fail]",
    "  vstack perimeter [dir] [--check-github] [--json] [--fail]",
    "  vstack crap [dir] --coverage <lcov|cobertura> [--max-crap <n>] [--json] [--fail]",
    "  vstack oracle-check [dir] --base <ref> --test-cmd <cmd> [--json]",
    "  vstack no-comments [dir] [--json] [--fail]",
    "  vstack state-machines [dir] [--json] [--fail]",
    "  vstack diff-cheats [dir] [--base <ref>] [--json] [--fail]",
    "  vstack review-brief [dir] [--base <ref>] [--max-lines <n>] [--max-dirs <n>] [--max-doc-lines <n>] [--json | --md] [--fail]",
    "  vstack check-file <file> [--tier immediate|all] [--max-lines <n>] [--strict] [--json] [--fail]",
    "  vstack hook <post-edit|pre-edit|stop> [--harness claude|codex|cursor|copilot|grok] [--tier immediate|all]",
    "  vstack hooks <on|off|status|reset> [dir] [--harness claude,codex,cursor,copilot,grok] [--command <cmd>] [--json]",
    "  vstack doctor [dir] [--json] [--fail]",
    "  vstack formal-sync [dir] [--json] [--fail]",
    "  vstack laws [dir] [--verify] [--json] [--fail]",
    "  vstack bench [dir] [--corpus <dir>] [--replay <dir>] [--json] [--fail]",
    "  vstack classify [dir] [--max <n>] [--emit-requests] [--provider <laya|jev|local|command|fixture>] [--endpoint <url>] [--model <name>] [--command <cmd>] [--corroborate <answers.json>] [--json]",
    "  vstack circuit list [--json]",
    "  vstack circuit run <test-triage|pr-risk-router|instruction-lint-promoter|perf-architecture-advisor> [dir] [--provider <jev|laya|local|command|fixture>] [--endpoint <url>] [--model <name>] [--command <cmd>] [--base <ref>] [--max <n>] [--json]",
    "  vstack red-before-fix [dir] --base <ref> --test-cmd <cmd> [--json]",
    '  vstack mcdc "<boolean expression>" [--json]',
    "  vstack spc <metrics.json> [--json] [--fail]",
    "  vstack big-o <samples.json> [--max-time-exp <num>] [--max-space-exp <num>] [--json] [--fail]",
    "  vstack invariants <traces.json> [--baseline <file>] [--update] [--json] [--fail]",
  ].join("\n");
}

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index < 0) return undefined;
  return args[index + 1];
}

function firstPositional(args: readonly string[]): string {
  const valueFlags = new Set([
    "--base",
    "--max",
    "--max-lines",
    "--max-dirs",
    "--max-doc-lines",
    "--corroborate",
    "--provider",
    "--endpoint",
    "--model",
    "--image",
    "--command",
    "--input",
    "--test-cmd",
    "--max-time-exp",
    "--max-space-exp",
    "--ratchet",
    "--ratchet-base",
    "--config",
    "--disable",
    "--corpus",
    "--replay",
    "--baseline",
    "--tier",
    "--harness",
    "--targets",
    "--max-mutants",
    "--min-kill-rate",
    "--coverage",
    "--max-crap",
  ]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (valueFlags.has(arg)) {
      i += 1;
      continue;
    }
    if (!arg.startsWith("-")) return arg;
  }
  return ".";
}

function parseProvider(raw: string | undefined): System1ProviderId | undefined {
  if (!raw) return undefined;
  if (raw === "laya" || raw === "jev" || raw === "local" || raw === "command" || raw === "fixture") return raw;
  throw new Error(`Unsupported --provider "${raw}". Expected one of: ${[...VALID_PROVIDERS].join(", ")}.`);
}

function parseCircuitId(raw: string | undefined): CircuitId {
  if (
    raw === "test-triage" ||
    raw === "pr-risk-router" ||
    raw === "instruction-lint-promoter" ||
    raw === "perf-architecture-advisor"
  ) {
    return raw;
  }
  throw new Error(`Unsupported circuit "${raw ?? ""}". Expected one of: ${[...VALID_CIRCUITS].join(", ")}.`);
}

async function run(): Promise<number> {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (!cmd || cmd === "-h" || cmd === "--help") {
    console.log(usage());
    return 0;
  }

  const rest = args.slice(1);
  const target = firstPositional(rest);
  const asJson = rest.includes("--json");
  const asMd = rest.includes("--md");

  const hookOrDoctorCode = handleHooksAndDoctorCli(cmd, rest, target, asJson);
  if (hookOrDoctorCode !== null) return hookOrDoctorCode;

  const rungToolCode = handleRungToolsCli(cmd, rest, target, asJson);
  if (rungToolCode !== null) return rungToolCode;

  if (cmd === "scan") {
    return handleScanCli(rest, target, asJson, asMd);
  }

  if (cmd === "oracle-check") {
    const baseRef = parseFlagValue(rest, "--base");
    if (!baseRef) {
      throw new Error("vstack oracle-check requires an explicit --base <ref> (e.g. origin/main or HEAD~1).");
    }
    const testCmd = parseFlagValue(rest, "--test-cmd");
    if (!testCmd) {
      throw new Error("vstack oracle-check requires --test-cmd <command>.");
    }
    const result = runTwoSidedOracleCheck(target, baseRef, testCmd);
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else console.log(`${result.passed ? "PASS" : "FAIL"}: ${result.reason}`);
    return result.passed ? 0 : 1;
  }

  if (cmd === "formal-sync") {
    const repo = discoverRepo(target);
    const findings = auditFormalSync(repo);
    if (asJson) console.log(JSON.stringify({ findings }, null, 2));
    else console.log(formatFormalSyncReport(findings));
    return rest.includes("--fail") && findings.length > 0 ? 1 : 0;
  }

  if (cmd === "laws") {
    const repo = discoverRepo(target);
    const result = auditLaws(repo, { verify: rest.includes("--verify") });
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else console.log(formatLawsReport(result));
    return rest.includes("--fail") && result.findings.length > 0 ? 1 : 0;
  }

  if (cmd === "bench") {
    const corpus = parseFlagValue(rest, "--corpus");
    const replay = parseFlagValue(rest, "--replay");
    const report = runPrecisionBench(target, corpus, replay);
    if (asJson) console.log(JSON.stringify(report, null, 2));
    else console.log(formatBenchReport(report));
    return rest.includes("--fail") && !report.passed ? 1 : 0;
  }

  if (cmd === "no-comments") {
    const repo = discoverRepo(target);
    const findings: Finding[] = [];
    for (const file of repo.files) {
      if (file.language) {
        findings.push(...lintNoComments(file.rel, file.content, file.language));
      }
    }
    console.log(formatFindingsList("no-comments", findings, asJson));
    return rest.includes("--fail") && findings.length > 0 ? 1 : 0;
  }

  if (cmd === "state-machines") {
    const repo = discoverRepo(target);
    const findings = analyzeStateMachines(repo);
    console.log(formatFindingsList("no-implicit-state-machine", findings, asJson));
    return rest.includes("--fail") && findings.length > 0 ? 1 : 0;
  }

  if (cmd === "diff-cheats") {
    const baseRef = parseFlagValue(rest, "--base") ?? "HEAD";
    const findings = scanGitDiffCheats(target, baseRef);
    console.log(formatFindingsList(`diff-cheats (${baseRef})`, findings, asJson));
    return rest.includes("--fail") && findings.length > 0 ? 1 : 0;
  }

  if (cmd === "review-brief") {
    const baseRef = parseFlagValue(rest, "--base") ?? "HEAD";
    const maxLinesRaw = parseFlagValue(rest, "--max-lines");
    const maxDirsRaw = parseFlagValue(rest, "--max-dirs");
    const maxDocRaw = parseFlagValue(rest, "--max-doc-lines");
    const report = buildReviewBrief(target, {
      baseRef,
      maxLines: maxLinesRaw ? Number(maxLinesRaw) : undefined,
      maxDirs: maxDirsRaw ? Number(maxDirsRaw) : undefined,
      maxDocLines: maxDocRaw ? Number(maxDocRaw) : undefined,
    });
    if (asJson) console.log(JSON.stringify(report, null, 2));
    else if (asMd) console.log(formatReviewBriefMarkdown(report));
    else console.log(formatReviewBriefTerminal(report));
    return rest.includes("--fail") && !report.passed ? 1 : 0;
  }

  if (cmd === "classify") {
    const maxRaw = parseFlagValue(rest, "--max");
    const maxCandidates = maxRaw ? Number(maxRaw) : 30;
    let packet = buildSystem1Packet(target, { maxCandidates });
    const provider = parseProvider(parseFlagValue(rest, "--provider"));
    const corroboratePath = parseFlagValue(rest, "--corroborate");

    if (provider) {
      const answers = await runSystem1Provider(packet.requests, {
        provider,
        endpoint: parseFlagValue(rest, "--endpoint"),
        model: parseFlagValue(rest, "--model"),
        image: parseFlagValue(rest, "--image"),
        command: parseFlagValue(rest, "--command"),
      });
      packet = { ...corroborateSystem1Batch(packet, answers), provider };
    } else if (corroboratePath) {
      const answers: System1ModelAnswer[] = JSON.parse(fs.readFileSync(corroboratePath, "utf8"));
      packet = corroborateSystem1Batch(packet, answers);
    }

    if (rest.includes("--emit-requests")) {
      console.log(
        JSON.stringify(
          { rubricVersion: packet.rubricVersion, rubricHash: packet.rubricHash, requests: packet.requests },
          null,
          2,
        ),
      );
      return 0;
    }
    if (asJson) console.log(JSON.stringify(packet, null, 2));
    else console.log(formatSystem1Report(packet));
    return 0;
  }

  if (cmd === "circuit") {
    const sub = rest[0];
    if (sub === "list") {
      const circuits = listDefaultCircuits();
      if (asJson) console.log(JSON.stringify({ circuits }, null, 2));
      else {
        for (const c of circuits) {
          console.log(`${c.id} (v${c.version}) — ${c.title}\n  ${c.description}`);
        }
      }
      return 0;
    }
    if (sub === "run") {
      const circuitId = parseCircuitId(rest[1]);
      const circuitArgs = rest.slice(2);
      const circuitTarget = firstPositional(circuitArgs);
      const provider = parseProvider(parseFlagValue(circuitArgs, "--provider")) ?? "fixture";
      const engine = createSystem1Engine({
        provider,
        endpoint: parseFlagValue(circuitArgs, "--endpoint"),
        model: parseFlagValue(circuitArgs, "--model"),
        image: parseFlagValue(circuitArgs, "--image"),
        command: parseFlagValue(circuitArgs, "--command"),
      });
      const maxRaw = parseFlagValue(circuitArgs, "--max");
      const report = await runRepoCircuit(circuitId, circuitTarget, engine, {
        baseRef: parseFlagValue(circuitArgs, "--base"),
        maxCandidates: maxRaw ? Number(maxRaw) : undefined,
      });
      if (asJson) console.log(JSON.stringify(report, null, 2));
      else console.log(formatCircuitReport(report));
      return 0;
    }
    console.error(`Unknown circuit subcommand: ${sub ?? ""}\n`);
    console.error(usage());
    return 2;
  }

  if (cmd === "red-before-fix") {
    const baseRef = parseFlagValue(rest, "--base") ?? "HEAD";
    const testCmd = parseFlagValue(rest, "--test-cmd");
    if (!testCmd) {
      throw new Error("vstack red-before-fix requires --test-cmd <command>.");
    }
    const result = runRedBeforeFix(target, baseRef, testCmd);
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else console.log(`${result.passed ? "PASS" : "FAIL"}: ${result.reason}`);
    return result.passed ? 0 : 1;
  }

  if (cmd === "mcdc") {
    const expr = rest.find((a) => !a.startsWith("-"));
    if (!expr) throw new Error('vstack mcdc requires a boolean expression, e.g. vstack mcdc "a || (b && !c)".');
    const result = generateMcdcVectors(expr);
    if (asJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`MC/DC Independence Table for: ${result.expression} (${result.vectors.length} vectors)`);
      for (const row of result.vectors) {
        const vals = result.variables.map((v) => `${v}=${row.inputs[v] ? "T" : "F"}`).join(" ");
        console.log(`  #${row.index}: ${vals} => ${row.output ? "T" : "F"}  [proves: ${row.provesIndependent.join(", ")}]`);
      }
      if (result.uncoveredVariables.length > 0) {
        console.log(`  UNCOVERED (redundant/dead condition): ${result.uncoveredVariables.join(", ")}`);
      }
    }
    return result.uncoveredVariables.length > 0 ? 1 : 0;
  }

  if (cmd === "spc") {
    const metricsPath = rest.find((a) => !a.startsWith("-"));
    if (!metricsPath) throw new Error("vstack spc requires a JSON metrics file ({ metric, upperSpecLimit, values }).");
    const parsed = JSON.parse(fs.readFileSync(metricsPath, "utf8")) as {
      metric: string;
      upperSpecLimit: number;
      values: number[];
    };
    const result = evaluateSpcSeries(parsed.metric, parsed.values, parsed.upperSpecLimit);
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else {
      console.log(
        `SPC [${result.status.toUpperCase()}] ${result.metric}: n=${result.count} mean=${result.mean} sd=${result.stdDev} USL=${result.upperSpecLimit} Cpk=${result.cpk ?? "n/a"}`,
      );
      for (const r of result.reasons) console.log(`  - ${r}`);
    }
    return rest.includes("--fail") && result.status !== "in_control" ? 1 : 0;
  }

  if (cmd === "big-o") {
    const samplesPath = rest.find((a) => !a.startsWith("-"));
    if (!samplesPath) {
      throw new Error("vstack big-o requires a JSON samples file ({ samples: [{ n, timeMs, memoryBytes? }], maxTimeExponent? }).");
    }
    const parsed = JSON.parse(fs.readFileSync(samplesPath, "utf8")) as {
      samples: ScalingSample[];
      maxTimeExponent?: number;
      maxSpaceExponent?: number;
    };
    const maxTimeRaw = parseFlagValue(rest, "--max-time-exp");
    const maxSpaceRaw = parseFlagValue(rest, "--max-space-exp");
    const maxTimeExp = maxTimeRaw !== undefined ? Number(maxTimeRaw) : (parsed.maxTimeExponent ?? 1.45);
    const maxSpaceExp = maxSpaceRaw !== undefined ? Number(maxSpaceRaw) : parsed.maxSpaceExponent;
    if (!Number.isFinite(maxTimeExp) || maxTimeExp <= 0) {
      throw new Error(`Invalid --max-time-exp '${maxTimeRaw ?? String(maxTimeExp)}'; expected a positive finite number.`);
    }
    if (maxSpaceExp !== undefined && (!Number.isFinite(maxSpaceExp) || maxSpaceExp <= 0)) {
      throw new Error(`Invalid --max-space-exp '${maxSpaceRaw ?? String(maxSpaceExp)}'; expected a positive finite number.`);
    }
    const result = fitEmpiricalBigO(parsed.samples, {
      maxTimeExponent: maxTimeExp,
      maxSpaceExponent: maxSpaceExp,
    });
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else {
      const spaceStr = result.spaceExponent !== null ? ` spaceExp=${result.spaceExponent} (${result.spaceClass})` : "";
      console.log(
        `Big-O [${result.passed ? "PASS" : "FAIL"}]: timeExp=${result.timeExponent} (${result.timeClass}, R2=${result.timeR2})${spaceStr}`,
      );
      for (const r of result.reasons) console.log(`  - ${r}`);
    }
    return rest.includes("--fail") && !result.passed ? 1 : 0;
  }

  if (cmd === "invariants") {
    const tracesPath = firstPositional(rest);
    if (!tracesPath || tracesPath === ".") {
      throw new Error("vstack invariants requires a JSON traces file ({ samples: [{ fn, args?, result?, throws? }] }).");
    }
    const parsed = JSON.parse(fs.readFileSync(tracesPath, "utf8")) as { samples?: TraceSample[] } | TraceSample[];
    const samples = Array.isArray(parsed) ? parsed : (parsed.samples ?? []);
    const current = inferDynamicInvariants(samples);
    const baselinePath = parseFlagValue(rest, "--baseline");
    const update = rest.includes("--update");
    if (update && rest.includes("--fail")) {
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
        const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8")) as InvariantSnapshot;
        diff = compareInvariantSnapshots(baseline, current, baselinePath);
      }
    }

    if (asJson) console.log(JSON.stringify(diff ? { snapshot: current, diff } : { snapshot: current }, null, 2));
    else console.log(formatInvariantDiffReport(current, diff));
    if (rest.includes("--fail")) {
      if (samples.length === 0) return 1;
      if (diff && !diff.passed) return 1;
    }
    return 0;
  }

  console.error(`Unknown command: ${cmd}\n`);
  console.error(usage());
  return 2;
}

run()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`vstack error: ${message}`);
    process.exitCode = 1;
  });
