import crypto from "node:crypto";
import fs from "node:fs";
import { runGitClean, type Finding, type RungId, type RungReceipt, type ScanReport } from "@veristack/plugin";
import { formatMarkdownReport, formatTerminalReport } from "../format.ts";
import type { VeristackHostInstance } from "../plugin/host.ts";
import { buildRatchetBaseline, evaluateRatchet, type RatchetBaseline, writeRatchetBaseline } from "../ratchet.ts";

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

function evaluateStrictScanExit(report: ScanReport): number {
  if (!report.summary) throw new Error("ScanReport.summary is required.");
  const s = report.summary;
  if (report.config && !(report.config as { monotonicStrengthenOnly?: boolean }).monotonicStrengthenOnly) {
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

export async function handleScanCli(
  host: VeristackHostInstance,
  rest: readonly string[],
  target: string,
  options: ScanCliOutputOptions,
): Promise<number> {
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

  const report = await host.scan(target, { configPath, disableRules, strict, receiptHmacKey });
  let ratchetEval: ReturnType<typeof evaluateRatchet> | undefined;
  if (ratchetPath) {
    const depFn = host.registries.reporters().find((r) => typeof r.countDirectDeps === "function")?.countDirectDeps;
    const depCount = depFn ? depFn(host.discover(target)).count : 0;
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
    !strict && !ratchetEval && !rest.includes("--fail-on-poor-coverage") && (rest.includes("--fail-on-errors") || rest.includes("--fail-on-cheats"));
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

function checkAncestorManifestDowngrades(
  repoRoot: string,
  auditManifest: (root: string, ref: string, opts?: { downgradeOnly?: boolean }) => Finding[],
): Finding[] {
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
      const anc = auditManifest(repoRoot, rev.stdout.trim(), { downgradeOnly: true });
      if (anc.length > 0) return anc;
    }
  }
  return [];
}

function auditVerifyControlPlane(host: VeristackHostInstance, repoRoot: string, explicitBase?: string): boolean {
  if (process.env.VSTACK_ALLOW_MANIFEST_CHANGE === "1") return true;
  const auditManifest = host.registries.rungs().find((r) => typeof r.auditManifest === "function")?.auditManifest;
  if (!auditManifest) return true;
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
  const downgrades = auditManifest(repoRoot, baseToCheck, { failClosedOnMissingBase: failClosed }).filter((d) => d.severity !== "info");
  if (!explicitBase && !hasTrustedOriginBase) downgrades.push(...checkAncestorManifestDowngrades(repoRoot, auditManifest).filter((d) => d.severity !== "info"));
  for (const d of downgrades) console.error(`verify control-plane lock [${d.rule}]: ${d.message}`);
  return downgrades.length === 0;
}

function logRungExecutionReceipts(
  prefix: "verify" | "run-rung",
  result: { receipts: RungReceipt[]; failureOutputs?: Record<string, string> },
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
      for (const line of (result.failureOutputs[r.rung] ?? "").split(/\r?\n/)) console.log(`  | ${line}`);
    }
  }
}

export async function handleVerifyAndRunRungCli(
  host: VeristackHostInstance,
  cmd: string,
  rest: readonly string[],
  target: string,
): Promise<number | null> {
  if (cmd !== "verify" && cmd !== "run-rung") return null;
  const asJson = rest.includes("--json");
  const asMd = rest.includes("--md");
  const runnerSpec = host.registries.rungs().find((r) => typeof r.runAllDeclaredRungsAsync === "function") as
    | { runAllDeclaredRungsAsync?: (repo: unknown, rung: RungId | "all", hmacKey?: string) => Promise<{ receipts: RungReceipt[]; passed: boolean; failureOutputs?: Record<string, string> }> }
    | undefined;
  if (!runnerSpec?.runAllDeclaredRungsAsync) {
    throw new Error("Canary / receipt runner plugin is not active.");
  }
  if (cmd === "verify") {
    const repo = host.discover(target);
    const controlPlaneOk = auditVerifyControlPlane(host, repo.root, parseFlagValue(rest, "--base"));
    if (repo.manifestError) {
      for (const errLine of repo.manifestError.split(/\r?\n/)) {
        console.error(`verify manifest error [rung-manifest-invalid]: ${errLine}`);
      }
    }
    if (!controlPlaneOk || repo.manifestError) return 1;
    const ephemeralKey = crypto.randomBytes(32).toString("hex");
    const runResult = await runnerSpec.runAllDeclaredRungsAsync(repo, "all", ephemeralKey);
    if (!asJson && !asMd) logRungExecutionReceipts("verify", runResult);
    const scanArgs = rest.includes("--strict") ? rest : [...rest, "--strict"];
    const scanExit = await handleScanCli(host, scanArgs, target, { asJson, asMd, receiptHmacKey: ephemeralKey });
    return runResult.passed && scanExit === 0 ? 0 : 1;
  }
  const rungArg = rest[0] ?? "all";
  if (!VALID_RUNG_ARGS.has(rungArg)) { console.error(`Invalid rung '${rungArg}'. Expected R0..R8 or all.`); return 2; }
  const dirArg = rest[1] && !rest[1].startsWith("-") ? rest[1] : ".";
  const result = await runnerSpec.runAllDeclaredRungsAsync(host.discover(dirArg), rungArg as RungId | "all");
  if (asJson) console.log(JSON.stringify(result, null, 2));
  else logRungExecutionReceipts("run-rung", result);
  return result.passed ? 0 : 1;
}
