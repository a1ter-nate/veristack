import { runGitClean } from "./config-audit.ts";
import crypto from "node:crypto";
import fs from "node:fs";
import { discoverRepo } from "../discover.ts";
import { formatMarkdownReport, formatTerminalReport } from "../format.ts";
import { scanRepo } from "../ladder.ts";
import {
  buildRatchetBaseline,
  evaluateRatchet,
  type RatchetBaseline,
  writeRatchetBaseline,
} from "../ratchet.ts";
import { countDirectRuntimeDependencies } from "../tigerstyle/index.ts";
import type { RungId } from "../types.ts";
import { auditManifestDowngrade } from "../zero-defect/anti-evasion.ts";
import { runPlantedFaultCanaryAsync } from "./mutation-probe.ts";
import { runAllDeclaredRungsAsync } from "./receipts.ts";
import { evaluateCrapForCoverageFile } from "./reports.ts";
import { auditCodeownersPerimeter, checkGitHubBranchProtection } from "./workflow-audit.ts";

const VALID_RUNG_ARGS = new Set(["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "all"]);

function parseFlagValue(args: readonly string[], flag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) return args[i + 1];
    if (a.startsWith(`${flag}=`)) return a.slice(flag.length + 1);
  }
  return undefined;
}

function loadBaseline(repoRoot: string, ratchetPath: string, baseRef?: string): RatchetBaseline | undefined {
  if (baseRef) {
    const cleanPath = ratchetPath.replace(/^\.\//, "");
    const gitShow = runGitClean(repoRoot, ["show", `${baseRef}:${cleanPath}`]);
    if (gitShow.status !== 0) return undefined;
    return JSON.parse(gitShow.stdout) as RatchetBaseline;
  }
  if (!fs.existsSync(ratchetPath)) return undefined;
  return JSON.parse(fs.readFileSync(ratchetPath, "utf8")) as RatchetBaseline;
}

export interface ScanCliOutputOptions {
  asJson: boolean;
  asMd: boolean;
  receiptHmacKey?: string;
}

function evaluateStrictScanExit(report: ReturnType<typeof scanRepo>): number {
  if (!report.summary) throw new Error("ScanReport.summary is required.");
  const s = report.summary;
  if (report.config) {
    console.error("vstack scan --strict failed: .vstack.json overrides/ignores are forbidden under --strict.");
    return 1;
  }
  if (s.excludedCount > 0) {
    console.error(`vstack scan --strict failed: ${s.excludedCount} unallowlisted excluded/ignored/oversized/minified/truncated path(s).`);
    return 1;
  }
  const failingWorkspaces = (report.workspaces ?? []).filter((w) => w.score < 80);
  if (failingWorkspaces.length > 0) {
    console.error(`vstack scan --strict failed: ${failingWorkspaces.length} workspace(s) scored below 80% (${failingWorkspaces.map((w) => `${w.name}=${w.score}%`).join(", ")}).`);
    return 1;
  }
  const reasons: string[] = [];
  if (s.errorCount > 0) reasons.push(`${s.errorCount} error(s)`);
  if (s.warnCount > 0) reasons.push(`${s.warnCount} warning(s)`);
  if (s.cheatCount > 0) reasons.push(`${s.cheatCount} cheat(s)`);
  if (s.noCommentCount > 0) reasons.push(`${s.noCommentCount} no-comments finding(s)`);
  if (s.holeCount > 0) reasons.push(`${s.holeCount} uncovered/over-budget rung(s)`);
  if (s.poorlyCoveredCount > 0) reasons.push(`${s.poorlyCoveredCount} poorly-covered rung(s)`);
  if (s.unexecutedRungCount > 0) reasons.push(`${s.unexecutedRungCount} unexecuted rung(s)`);
  if (s.pushDownCount > 0) reasons.push(`${s.pushDownCount} push-down opportunity(ies)`);
  if (s.overallCoverageScore < 80) reasons.push(`ladder score ${s.overallCoverageScore}% < 80%`);
  if (reasons.length > 0 || s.totalFindings > 0) {
    console.error(`vstack scan --strict failed: ${reasons.join(", ") || `${s.totalFindings} finding(s)`}.`);
    return 1;
  }
  return 0;
}

function printRatchetEvaluation(ratchetPath: string, ratchetEval: ReturnType<typeof evaluateRatchet>): void {
  console.log(`\nRATCHET (${ratchetPath}): ${ratchetEval.passed ? "PASS" : "FAIL"}`);
  for (const r of ratchetEval.regressions) console.log(`  - [REGRESSION] ${r.rule}: ${r.baseline} -> ${r.current} (+${r.delta})`);
  for (const t of ratchetEval.tightenAvailable) console.log(`  - [TIGHTEN] ${t.rule}: ${t.baseline} -> ${t.current} (${t.delta}) — rerun with --update-ratchet`);
  for (const rr of ratchetEval.rungRegressions) console.log(`  - [RUNG REGRESSION] ${rr.rung}: ${rr.reason}`);
}

export function handleScanCli(
  rest: readonly string[],
  target: string,
  options: ScanCliOutputOptions,
): number {
  const { asJson, asMd, receiptHmacKey } = options;
  const strict = rest.includes("--strict");
  const allowMissingRungs = rest.includes("--allow-missing-rungs");
  const configPath = parseFlagValue(rest, "--config");
  const disableRaw = parseFlagValue(rest, "--disable");
  const disableRules = disableRaw ? disableRaw.split(",").map((r) => r.trim()).filter(Boolean) : undefined;
  const ratchetPath = parseFlagValue(rest, "--ratchet");
  const ratchetBase = parseFlagValue(rest, "--ratchet-base");
  const updateRatchet = rest.includes("--update-ratchet");

  if (strict && (ratchetPath || updateRatchet || ratchetBase)) { console.error("vstack scan --strict forbids --ratchet, --ratchet-base, and --update-ratchet baselines."); return 1; }
  if (strict && (configPath || (disableRules && disableRules.length > 0))) { console.error("vstack scan --strict forbids --config and --disable rule overrides."); return 1; }
  if (strict && allowMissingRungs) { console.error("vstack scan --strict forbids --allow-missing-rungs."); return 1; }

  const report = scanRepo(target, { configPath, disableRules, strict, receiptHmacKey });
  let ratchetEval: ReturnType<typeof evaluateRatchet> | undefined;
  if (ratchetPath) {
    const depCount = countDirectRuntimeDependencies(discoverRepo(target)).count;
    if (updateRatchet) {
      const nextBaseline = buildRatchetBaseline(report.findings, report.rungs, depCount);
      writeRatchetBaseline(ratchetPath, nextBaseline);
      ratchetEval = evaluateRatchet(report.findings, nextBaseline, report.rungs, depCount);
    } else {
      const baseline = loadBaseline(report.repo, ratchetPath, ratchetBase);
      if (!baseline) {
        console.error(`vstack scan --ratchet failed: baseline '${ratchetPath}' not found${ratchetBase ? ` at ${ratchetBase}` : ""}. Refusing to auto-create passing baseline (pass --update-ratchet intentionally to initialize).`);
        return 1;
      }
      ratchetEval = evaluateRatchet(report.findings, baseline, report.rungs, depCount);
    }
  }

  if (asJson) console.log(JSON.stringify(ratchetEval ? { ...report, ratchet: ratchetEval } : report, null, 2));
  else if (asMd) console.log(formatMarkdownReport(report));
  else {
    console.log(formatTerminalReport(report));
    if (ratchetEval && ratchetPath) printRatchetEvaluation(ratchetPath, ratchetEval);
  }
  if (strict) return evaluateStrictScanExit(report);

  const s = report.summary;
  const targetedGateOnly =
    !strict &&
    !ratchetEval &&
    !rest.includes("--fail-on-poor-coverage") &&
    (rest.includes("--fail-on-errors") || rest.includes("--fail-on-cheats"));
  if (ratchetEval) {
    if (!ratchetEval.passed || (!allowMissingRungs && (s.holeCount > 0 || s.unexecutedRungCount > 0))) return 1;
  } else if (!allowMissingRungs && !targetedGateOnly && (s.holeCount > 0 || s.unexecutedRungCount > 0)) {
    if (!asJson && !asMd) console.error(`\nFAIL: ${s.holeCount} not-covered/over-budget rung(s) and ${s.unexecutedRungCount} rung(s) not executing in CI. Wire missing rungs into CI (or pass --allow-missing-rungs for snippet-only scans).`);
    return 1;
  }
  if (rest.includes("--fail-on-poor-coverage") && s.poorlyCoveredCount > 0) return 1;
  if (rest.includes("--fail-on-errors") && s.errorCount > 0) return 1;
  if (rest.includes("--fail-on-cheats") && (s.cheatCount > 0 || s.noCommentCount > 0)) return 1;
  return 0;
}

function checkAncestorManifestDowngrades(repoRoot: string): ReturnType<typeof auditManifestDowngrade> {
  const histGroups: Array<[string[], number]> = [[ [".verification/rungs.json"], 10 ], [ ["package.json"], 10 ], [ [".gitattributes"], 5 ]];
  const manifestFile = `${repoRoot}/.verification/rungs.json`;
  if (fs.existsSync(manifestFile)) {
    const subPkgs: string[] = [];
    for (const m of fs.readFileSync(manifestFile, "utf8").matchAll(/(?:--cwd|--filter|-F)\s+["']?([^\s"']+)["']?/g)) {
      const sub = (m[1] ?? "").replace(/^\.\//, "").replace(/\/+$/, "");
      if (sub) subPkgs.push(`${sub}/package.json`);
    }
    if (subPkgs.length > 0) histGroups.push([subPkgs, 10]);
  }
  const touchedCommits = new Set<string>();
  for (const [paths, maxN] of histGroups) {
    const mh = runGitClean(repoRoot, ["log", `--max-count=${maxN}`, "--format=%H", "--", ...paths]);
    if (mh.status === 0) for (const s of mh.stdout.trim().split(/\r?\n/).filter(Boolean)) touchedCommits.add(s);
  }
  const checkedRefs = new Set<string>();
  for (const sha of touchedCommits) {
    for (const cand of [sha, `${sha}~1`]) {
      if (checkedRefs.has(cand)) continue;
      checkedRefs.add(cand);
      const rev = runGitClean(repoRoot, ["rev-parse", "--verify", `${cand}^{commit}`]);
      if (rev.status !== 0) continue;
      const anc = auditManifestDowngrade(repoRoot, rev.stdout.trim(), { downgradeOnly: true });
      if (anc.length > 0) return anc;
    }
  }
  return [];
}

function auditVerifyControlPlane(repoRoot: string, explicitBase?: string): boolean {
  if (process.env.VSTACK_ALLOW_MANIFEST_CHANGE === "1") return true;
  let baseToCheck = explicitBase;
  let failClosed = Boolean(explicitBase);
  let hasTrustedOriginBase = false;
  if (!baseToCheck && runGitClean(repoRoot, ["rev-parse", "--git-dir"]).status === 0) {
    const hasOrigin = runGitClean(repoRoot, ["remote", "get-url", "origin"]).status === 0;
    const candidates = [...(process.env.GITHUB_BASE_REF ? [`origin/${process.env.GITHUB_BASE_REF}`] : []), "origin/main", "origin/master", "origin/HEAD"];
    for (const candidate of candidates) {
      if (runGitClean(repoRoot, ["rev-parse", "--verify", `${candidate}^{commit}`]).status !== 0) continue;
      const mb = runGitClean(repoRoot, ["merge-base", "HEAD", candidate]);
      baseToCheck = mb.status === 0 && mb.stdout.trim() ? mb.stdout.trim() : candidate;
      failClosed = true;
      hasTrustedOriginBase = true;
      break;
    }
    if (!baseToCheck) {
      if (hasOrigin) {
        console.error("verify control-plane lock [missing-base-ref]: git remote 'origin' exists but origin/main|origin/master could not be resolved (shallow/detached clone). Fetch base branch or pass --base <ref>.");
        return false;
      }
      if (runGitClean(repoRoot, ["rev-parse", "--verify", "HEAD^{commit}"]).status === 0) baseToCheck = "HEAD";
    }
  }
  if (!baseToCheck) return true;
  const downgrades = auditManifestDowngrade(repoRoot, baseToCheck, { failClosedOnMissingBase: failClosed });
  if (!explicitBase && !hasTrustedOriginBase) downgrades.push(...checkAncestorManifestDowngrades(repoRoot));
  for (const d of downgrades) console.error(`verify control-plane lock [${d.rule}]: ${d.message}`);
  return downgrades.length === 0;
}

function logRungExecutionReceipts(
  prefix: "verify" | "run-rung",
  result: Awaited<ReturnType<typeof runAllDeclaredRungsAsync>>,
): void {
  for (const r of result.receipts) {
    const invTag = r.canary && r.canary.invalidKills > 0 ? `, invalid=${r.canary.invalidKills}` : "";
    const canaryTag = r.canary ? ` | canary=${(r.canary.killRate * 100).toFixed(0)}% (${r.canary.killedMutants}/${r.canary.totalMutants}${invTag})` : "";
    const suffix = prefix === "run-rung" ? ` -> .verification/receipts/${r.rung}.json` : "";
    console.log(`${prefix} ${r.rung}: ${r.exitCode === 0 ? "PASS" : "FAIL"} (${r.durationMs}ms${canaryTag})${suffix}`);
    if (r.canary && !r.canary.passed) {
      for (const s of r.canary.survivors) console.log(`  - [SURVIVED] ${s.file}:${s.line} (${s.operator}) — ${s.original}`);
      for (const d of r.canary.invalidDiagnostics ?? []) console.log(`  - [INVALID] ${d}`);
    } else if (r.exitCode !== 0 && result.failureOutputs?.[r.rung]) {
      const out = result.failureOutputs[r.rung] ?? "";
      for (const line of out.split(/\r?\n/)) console.log(`  | ${line}`);
    }
  }
}

async function handleVerifyCommand(rest: readonly string[], target: string, asJson: boolean): Promise<number> {
  const asMd = rest.includes("--md");
  const repo = discoverRepo(target);
  if (!auditVerifyControlPlane(repo.root, parseFlagValue(rest, "--base"))) return 1;
  const ephemeralKey = crypto.randomBytes(32).toString("hex");
  const runResult = await runAllDeclaredRungsAsync(repo, "all", ephemeralKey);
  if (!asJson && !asMd) logRungExecutionReceipts("verify", runResult);
  const scanArgs = rest.includes("--strict") ? rest : [...rest, "--strict"];
  const scanExit = handleScanCli(scanArgs, target, { asJson, asMd, receiptHmacKey: ephemeralKey });
  return runResult.passed && scanExit === 0 ? 0 : 1;
}

async function handleCanaryCommand(rest: readonly string[], target: string, asJson: boolean): Promise<number> {
  const testCmd = parseFlagValue(rest, "--test-cmd");
  if (!testCmd) throw new Error("vstack canary requires --test-cmd <command>.");
  const targetsRaw = parseFlagValue(rest, "--targets");
  const maxRaw = parseFlagValue(rest, "--max-mutants");
  const minRateRaw = parseFlagValue(rest, "--min-kill-rate");
  const report = await runPlantedFaultCanaryAsync({
    repoRoot: target, testCmd,
    targets: targetsRaw ? targetsRaw.split(",").map((t) => t.trim()).filter(Boolean) : undefined,
    baseRef: parseFlagValue(rest, "--base"),
    maxMutants: maxRaw ? Number(maxRaw) : undefined,
    minKillRate: minRateRaw ? Number(minRateRaw) : undefined,
  });
  if (asJson) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`canary [${report.passed ? "PASS" : "FAIL"}]: killed=${report.killedMutants}/${report.totalMutants} (${(report.killRate * 100).toFixed(1)}%, floor=${(report.minKillRate * 100).toFixed(0)}%, invalid=${report.invalidKills})`);
    for (const s of report.survivors) console.log(`  - [SURVIVED] ${s.file}:${s.line} (${s.operator}) — ${s.original}`);
    for (const d of report.invalidDiagnostics ?? []) console.log(`  - [INVALID] ${d}`);
  }
  return rest.includes("--fail") && !report.passed ? 1 : 0;
}

export async function handleRungToolsCli(cmd: string, rest: readonly string[], target: string, asJson: boolean): Promise<number | null> {
  if (cmd === "verify") return handleVerifyCommand(rest, target, asJson);
  if (cmd === "run-rung") {
    const rungArg = rest[0] ?? "all";
    if (!VALID_RUNG_ARGS.has(rungArg)) { console.error(`Invalid rung '${rungArg}'. Expected R0..R8 or all.`); return 2; }
    const dirArg = rest[1] && !rest[1].startsWith("-") ? rest[1] : ".";
    const result = await runAllDeclaredRungsAsync(discoverRepo(dirArg), rungArg as RungId | "all");
    if (asJson) console.log(JSON.stringify(result, null, 2));
    else logRungExecutionReceipts("run-rung", result);
    return result.passed ? 0 : 1;
  }
  if (cmd === "canary") return handleCanaryCommand(rest, target, asJson);
  if (cmd === "perimeter") {
    const repo = discoverRepo(target);
    const co = auditCodeownersPerimeter(repo.files, repo.allRelPaths);
    const gh = rest.includes("--check-github") ? checkGitHubBranchProtection(repo.root) : undefined;
    const passed = co.passed && (!gh || gh.passed);
    if (asJson) console.log(JSON.stringify({ passed, codeowners: co, branchProtection: gh }, null, 2));
    else {
      console.log(`perimeter [${passed ? "PASS" : "FAIL"}]: CODEOWNERS=${co.passed ? "LOCKED" : `UNCOVERED (${co.uncoveredSurfaces.join(", ")})`}`);
      if (gh) console.log(`  GitHub branch protection: ${gh.passed ? "PASS" : "FAIL"} — ${gh.detail}`);
    }
    return rest.includes("--fail") && !passed ? 1 : 0;
  }
  if (cmd === "crap") {
    const covPath = parseFlagValue(rest, "--coverage");
    if (!covPath) throw new Error("vstack crap requires --coverage <lcov.info|cobertura.xml>.");
    const maxRaw = parseFlagValue(rest, "--max-crap");
    const report = evaluateCrapForCoverageFile(target, covPath, maxRaw ? Number(maxRaw) : 30);
    if (asJson) console.log(JSON.stringify(report, null, 2));
    else {
      console.log(`crap [${report.passed ? "PASS" : "FAIL"}]: evaluated=${report.evaluatedFiles} worst=${report.worstCrap} maxAllowed=${report.maxAllowed} offenders=${report.offenders.length}`);
      for (const o of report.offenders.slice(0, 20)) console.log(`  - ${o.file}: CRAP=${o.crapScore} (CC=${o.cyclomaticComplexity}, cov=${o.coveragePct}%)`);
    }
    return rest.includes("--fail") && !report.passed ? 1 : 0;
  }
  return null;
}
