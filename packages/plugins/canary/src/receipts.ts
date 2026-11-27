import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getCoreServices, type DiscoveredRepo, type Finding, type PlantedFaultReport, type RungId, type RungManifest, type RungReceipt } from "@veristack/plugin";
import { extractToolHead, parseAndValidateCommandArgv, runArgvChain, scrubChildEnv, runGitClean } from "@veristack/plugin-control-plane";
import { runPlantedFaultCanary, runPlantedFaultCanaryAsync } from "./mutation-probe.ts";
import { parseStructuredReports, reportParsers } from "./reports.ts";
import { hasTestRunnerCommand, parseRunnerTestCounts, stripAnsi } from "./runner-metrics.ts";

const RECEIPTS_REL_DIR = ".verification/receipts";

function isEphemeralReportPath(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  return norm.startsWith(`${RECEIPTS_REL_DIR}/`) || reportParsers.EXACT_REPORT_PATHS.has(norm);
}

function digestPayload(receipt: Omit<RungReceipt, "digest">, hmacKeyOverride?: string): string {
  const canonical = JSON.stringify({
    schemaVersion: receipt.schemaVersion,
    rung: receipt.rung,
    command: receipt.command,
    commitSha: receipt.commitSha,
    treeHash: receipt.treeHash,
    exitCode: receipt.exitCode,
    ciRunId: receipt.ciRunId ?? null,
    metrics: receipt.metrics ?? null,
    canary: receipt.canary ?? null,
  });
  const key = hmacKeyOverride ?? process.env.VSTACK_RECEIPT_KEY;
  if (key && key.length > 0) return `hmac:${crypto.createHmac("sha256", key).update(canonical).digest("hex")}`;
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

function listHashablePaths(repo: DiscoveredRepo): string[] {
  const paths = new Set<string>();
  const gitList = runGitClean(repo.root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]);
  if (gitList.status === 0) {
    for (const rel of gitList.stdout.split("\0")) {
      if (!rel || isEphemeralReportPath(rel)) continue;
      paths.add(rel);
    }
  }
  for (const rel of repo.allRelPaths) {
    if (!isEphemeralReportPath(rel)) paths.add(rel);
  }
  for (const extra of [".vstackignore", ".vstack.json", ".verification/vstack.json", "bun.lock", "pnpm-lock.yaml", "package-lock.json"]) {
    if (fs.existsSync(path.join(repo.root, extra))) paths.add(extra);
  }
  return [...paths].sort();
}

export function computeRepoTreeHash(repo: DiscoveredRepo): string {
  const hasher = crypto.createHash("sha256");
  for (const rel of listHashablePaths(repo)) {
    const abs = path.join(repo.root, rel);
    try {
      const stat = fs.lstatSync(abs);
      if (stat.isSymbolicLink()) {
        hasher.update(rel); hasher.update("\0symlink:"); hasher.update(fs.readlinkSync(abs)); hasher.update("\0");
        continue;
      }
      if (!stat.isFile()) continue;
      hasher.update(rel); hasher.update("\0"); hasher.update(fs.readFileSync(abs)); hasher.update("\0");
    } catch {
      continue;
    }
  }
  return hasher.digest("hex");
}

export function hasGitTrackedReceipts(repoRoot: string): boolean {
  const res = runGitClean(repoRoot, ["ls-files", RECEIPTS_REL_DIR]);
  return res.status === 0 && res.stdout.trim().length > 0;
}

function readGitHeadSha(repoRoot: string): string {
  const res = runGitClean(repoRoot, ["rev-parse", "HEAD"]);
  return res.status === 0 && res.stdout.trim() ? res.stdout.trim() : "no-git";
}

function snapshotReportFiles(repoRoot: string): Map<string, { mtimeMs: number; size: number }> {
  const snap = new Map<string, { mtimeMs: number; size: number }>();
  for (const rel of reportParsers.EXACT_REPORT_PATHS) {
    const abs = path.join(repoRoot, rel);
    try {
      if (fs.existsSync(abs)) {
        const st = fs.statSync(abs);
        snap.set(rel, { mtimeMs: st.mtimeMs, size: st.size });
      }
    } catch {
      continue;
    }
  }
  return snap;
}

interface CommandMetricsInput {
  repoRoot: string;
  rawOutput: string;
  rung: RungId;
  steps: readonly string[][];
  preSnapshot: ReadonlyMap<string, { mtimeMs: number; size: number }>;
}

function parseCommandMetrics(input: CommandMetricsInput): { metrics: RungReceipt["metrics"]; hasTestRunner: boolean } {
  if (!input.repoRoot) throw new Error("repoRoot is required.");
  if (!input.rung) throw new Error("rung is required.");
  const { repoRoot, rawOutput, rung, steps, preSnapshot } = input;
  const output = stripAnsi(rawOutput);
  const structured = parseStructuredReports(repoRoot, { rung, preSnapshot });
  const parsedCounts = parseRunnerTestCounts(output, steps);
  const metrics: NonNullable<RungReceipt["metrics"]> = {};
  if (parsedCounts.hasTestRunner) {
    const hasStructuredReporterFlag = steps.some((seg) => seg.some((tok) => /^(?:--junitxml(?:=|$)|--logger(?:=|$)|--reporter(?:s)?=junit|--test-reporter=junit)$/i.test(tok) || /^(?:junit|trx)$/i.test(tok)));
    if (parsedCounts.matched) {
      metrics.testsPassed =
        typeof structured.testsPassed === "number"
          ? Math.min(parsedCounts.passed, structured.testsPassed)
          : parsedCounts.passed;
      metrics.testsFailed = Math.max(parsedCounts.failed, structured.testsFailed ?? 0);
    } else if (typeof structured.testsFailed === "number" && structured.testsFailed > 0) {
      metrics.testsPassed = 0;
      metrics.testsFailed = structured.testsFailed;
    } else if (hasStructuredReporterFlag && typeof structured.testsPassed === "number" && structured.testsPassed > 0) {
      metrics.testsPassed = structured.testsPassed;
      metrics.testsFailed = structured.testsFailed ?? 0;
    }
  } else {
    if (typeof structured.testsPassed === "number") metrics.testsPassed = structured.testsPassed;
    if (typeof structured.testsFailed === "number") metrics.testsFailed = structured.testsFailed;
  }
  const hasMutationTool = steps.some((seg) => {
    const h = extractToolHead(seg).head;
    return /^(?:stryker|mutmut|pitest|gremlins|go-mutesting|cargo mutants|dotnet stryker)$/.test(h);
  });
  if (hasMutationTool && typeof structured.mutationScore === "number") metrics.mutationScore = structured.mutationScore;
  if (metrics.mutationScore === undefined && rung === "R5" && hasMutationTool) {
    const mutationMatch = /mutation\s+score[:\s]+(\d+(?:\.\d+)?)%/i.exec(output);
    if (mutationMatch?.[1]) metrics.mutationScore = Number(mutationMatch[1]);
  }
  if (/check-perf-budget:\s*PASS|Big-O\s*\[PASS\]/i.test(output)) metrics.perfPassed = true;
  return { metrics: Object.keys(metrics).length > 0 ? metrics : undefined, hasTestRunner: parsedCounts.hasTestRunner };
}

interface FinalizeReceiptInput {
  repo: DiscoveredRepo;
  rung: RungId;
  entry: NonNullable<RungManifest["rungs"][RungId]>;
  commitSha: string;
  treeHashAfter: string;
  mutatedTree: boolean;
  exitCode: number;
  durationMs: number;
  metrics: RungReceipt["metrics"];
  hasTestRunner: boolean;
  canary: PlantedFaultReport | undefined;
  hmacKeyOverride?: string;
}

function finalizeAndWriteReceipt(input: FinalizeReceiptInput): RungReceipt {
  if (!input.repo.root) throw new Error("repo.root is required.");
  if (!input.entry.command) throw new Error("rung command is required.");
  const { repo, rung, entry, commitSha, treeHashAfter, mutatedTree, exitCode, durationMs, metrics, hasTestRunner, canary, hmacKeyOverride } = input;
  const testsPassed = metrics?.testsPassed;
  const testsFailed = metrics?.testsFailed ?? 0;
  const requiresPositiveTests = rung === "R2" || rung === "R3" || ((rung === "R4" || rung === "R7") && hasTestRunner);
  const testCountMissing =
    requiresPositiveTests &&
    (testsPassed === undefined || !Number.isFinite(testsPassed) || testsPassed <= 0 || !Number.isFinite(testsFailed) || testsFailed > 0);
  const minCanaryMutants = entry.canary?.enabled ? Math.min(4, entry.canary.maxMutants ?? 4) : 0;
  const canaryFailed = Boolean(canary && (!canary.passed || canary.totalMutants < minCanaryMutants || canary.invalidKills > 0));
  const finalExit = mutatedTree || testCountMissing || canaryFailed ? 1 : exitCode;
  const baseReceipt: Omit<RungReceipt, "digest"> = {
    schemaVersion: 1, rung, command: entry.command, commitSha, treeHash: treeHashAfter, exitCode: finalExit, durationMs,
    ...(process.env.GITHUB_RUN_ID ? { ciRunId: process.env.GITHUB_RUN_ID } : {}),
    ...(metrics ? { metrics } : {}),
    ...(canary ? { canary } : {}),
    timestamp: new Date().toISOString(),
  };
  const receipt: RungReceipt = { ...baseReceipt, digest: digestPayload(baseReceipt, hmacKeyOverride) };
  const dir = path.join(repo.root, RECEIPTS_REL_DIR);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${rung}.json`), `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return receipt;
}

function trimFailureTail(stdout: string, stderr: string): string {
  const combined = stripAnsi(`${stdout}\n${stderr}`).trim();
  if (!combined) return "";
  const lines = combined.split(/\r?\n/);
  return lines.slice(-30).join("\n").slice(-2400);
}

export function runRungAndWriteReceipt(
  repo: DiscoveredRepo,
  rung: RungId,
  manifest: RungManifest,
  hmacKeyOverride?: string,
): RungReceipt {
  const entry = manifest.rungs[rung];
  if (!entry) throw new Error(`Rung ${rung} is not declared in .verification/rungs.json.`);
  const parsedCmd = parseAndValidateCommandArgv(rung, entry.command, repo.root);
  if (parsedCmd.error) throw new Error(parsedCmd.error);
  const treeHashBefore = computeRepoTreeHash(repo);
  const preSnapshot = snapshotReportFiles(repo.root);
  const commitSha = readGitHeadSha(repo.root);
  const started = performance.now();
  const proc = runArgvChain(parsedCmd.steps, { cwd: repo.root, env: scrubChildEnv(), timeoutMs: 300_000, stepCwds: parsedCmd.stepCwds });
  const durationMs = Math.round(performance.now() - started);
  const { metrics, hasTestRunner } = parseCommandMetrics({ repoRoot: repo.root, rawOutput: `${proc.stdout}\n${proc.stderr}`, rung, steps: parsedCmd.steps, preSnapshot });
  const treeHashAfter = computeRepoTreeHash(repo);
  const mutatedTree = treeHashBefore !== treeHashAfter;
  let canary: PlantedFaultReport | undefined;
  if (proc.status === 0 && !mutatedTree && entry.canary?.enabled) {
    canary = runPlantedFaultCanary({
      repoRoot: repo.root, testCmd: entry.canary.testCommand ?? entry.command,
      targets: entry.canary.targets, maxMutants: entry.canary.maxMutants, minKillRate: entry.canary.minKillRate,
    });
  }
  return finalizeAndWriteReceipt({ repo, rung, entry, commitSha, treeHashAfter, mutatedTree, exitCode: proc.status, durationMs, metrics, hasTestRunner, canary, hmacKeyOverride });
}

async function runRungAndWriteReceiptAsync(
  repo: DiscoveredRepo,
  rung: RungId,
  manifest: RungManifest,
  hmacKeyOverride?: string,
): Promise<{ receipt: RungReceipt; failureOutput?: string }> {
  const entry = manifest.rungs[rung];
  if (!entry) throw new Error(`Rung ${rung} is not declared in .verification/rungs.json.`);
  const parsedCmd = parseAndValidateCommandArgv(rung, entry.command, repo.root);
  if (parsedCmd.error) throw new Error(parsedCmd.error);
  const treeHashBefore = computeRepoTreeHash(repo);
  const preSnapshot = snapshotReportFiles(repo.root);
  const commitSha = readGitHeadSha(repo.root);
  const started = performance.now();
  const proc = runArgvChain(parsedCmd.steps, { cwd: repo.root, env: scrubChildEnv(), timeoutMs: 300_000, stepCwds: parsedCmd.stepCwds });
  const durationMs = Math.round(performance.now() - started);
  const { metrics, hasTestRunner } = parseCommandMetrics({ repoRoot: repo.root, rawOutput: `${proc.stdout}\n${proc.stderr}`, rung, steps: parsedCmd.steps, preSnapshot });
  const treeHashAfter = computeRepoTreeHash(repo);
  const mutatedTree = treeHashBefore !== treeHashAfter;
  let canary: PlantedFaultReport | undefined;
  if (proc.status === 0 && !mutatedTree && entry.canary?.enabled) {
    canary = await runPlantedFaultCanaryAsync({
      repoRoot: repo.root, testCmd: entry.canary.testCommand ?? entry.command,
      targets: entry.canary.targets, maxMutants: entry.canary.maxMutants, minKillRate: entry.canary.minKillRate,
    });
  }
  const receipt = finalizeAndWriteReceipt({ repo, rung, entry, commitSha, treeHashAfter, mutatedTree, exitCode: proc.status, durationMs, metrics, hasTestRunner, canary, hmacKeyOverride });
  const failureOutput = receipt.exitCode !== 0 ? trimFailureTail(proc.stdout, proc.stderr) : undefined;
  return { receipt, ...(failureOutput ? { failureOutput } : {}) };
}

function validateLoadedReceipt(ctx: {
  raw: RungReceipt;
  name: string;
  repoRoot: string;
  manifest?: RungManifest;
  requireHmac: boolean;
  activeKey?: string;
  expectedTreeHash: string;
  expectedHead: string;
  activeCiRunId?: string;
}): boolean {
  const { raw, name, repoRoot, manifest, requireHmac, activeKey, expectedTreeHash, expectedHead, activeCiRunId } = ctx;
  if (raw.schemaVersion !== 1 || !raw.rung || typeof raw.digest !== "string") return false;
  if (name !== `${raw.rung}.json`) return false;
  const declared = manifest?.rungs[raw.rung];
  if (!declared || raw.command !== declared.command) return false;
  if (requireHmac && !raw.digest.startsWith("hmac:")) return false;
  const { digest, ...rest } = raw;
  if (digestPayload(rest, activeKey) !== digest) return false;
  if (raw.exitCode !== 0 || raw.treeHash !== expectedTreeHash) return false;
  if (expectedHead !== "no-git" && raw.commitSha !== expectedHead) return false;
  if (activeCiRunId && raw.ciRunId !== activeCiRunId) return false;
  const needsTests = raw.rung === "R2" || raw.rung === "R3" || ((raw.rung === "R4" || raw.rung === "R7") && hasTestRunnerCommand(raw.rung, declared.command, repoRoot));
  if (needsTests && ((raw.metrics?.testsPassed ?? 0) <= 0 || (raw.metrics?.testsFailed ?? 0) > 0)) return false;
  if (declared.canary?.enabled) {
    const minFloor = Math.max(0.75, declared.canary.minKillRate ?? 0.8);
    const minMutants = Math.min(4, declared.canary.maxMutants ?? 4);
    if (!raw.canary || !raw.canary.passed || raw.canary.killRate < minFloor || raw.canary.totalMutants < minMutants || raw.canary.invalidKills > 0) return false;
  }
  if (raw.canary && !raw.canary.passed) return false;
  return true;
}

export function loadValidReceipts(
  repo: DiscoveredRepo,
  manifest?: RungManifest,
  options?: { strict?: boolean; hmacKeyOverride?: string },
): { receipts: Map<RungId, RungReceipt>; findings: Finding[] } {
  if (!repo.root) throw new Error("repo.root is required.");
  const valid = new Map<RungId, RungReceipt>();
  const findings: Finding[] = [];

  if (hasGitTrackedReceipts(repo.root)) {
    findings.push({
      id: "RCPT:tracked-in-git:.verification/receipts", rule: "receipt-committed-to-git", category: "cheat", rung: "R0", severity: "error",
      file: ".verification/receipts", line: 1,
      message: "Receipts in .verification/receipts/ are tracked by git — receipts must be generated dynamically at CI runtime, never committed.",
      fix: "Add .verification/receipts/ to .gitignore and run 'git rm -r --cached .verification/receipts'.",
    });
    return { receipts: valid, findings };
  }

  const activeKey = options?.hmacKeyOverride ?? process.env.VSTACK_RECEIPT_KEY;
  const requireHmac = Boolean(options?.strict);
  if (requireHmac && (!activeKey || activeKey.length < 8)) {
    findings.push({
      id: "RCPT:unsigned-strict:.verification/receipts", rule: "receipt-unsigned-strict", category: "oracle-lock", rung: "R0", severity: "error",
      file: ".verification/receipts", line: 1,
      message: "Strict scan requires HMAC-authenticated receipts (unkeyed SHA-256 receipts are forgeable offline).",
      fix: "Run 'vstack verify . --strict' (ephemeral in-memory HMAC key) or set VSTACK_RECEIPT_KEY in the parent CI orchestrator.",
    });
    return { receipts: valid, findings };
  }

  const dir = path.join(repo.root, RECEIPTS_REL_DIR);
  if (!fs.existsSync(dir)) return { receipts: valid, findings };

  const expectedTreeHash = computeRepoTreeHash(repo);
  const expectedHead = readGitHeadSha(repo.root);
  const activeCiRunId = process.env.GITHUB_RUN_ID;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")) as RungReceipt;
      if (validateLoadedReceipt({ raw, name, repoRoot: repo.root, manifest, requireHmac, activeKey, expectedTreeHash, expectedHead, activeCiRunId })) {
        valid.set(raw.rung, raw);
      }
    } catch { continue; }
  }
  return { receipts: valid, findings };
}

export function runAllDeclaredRungs(
  repo: DiscoveredRepo,
  targetRung: RungId | "all",
  hmacKeyOverride?: string,
): { receipts: RungReceipt[]; passed: boolean; manifestPath: string } {
  const loaded = (getCoreServices().loadRungManifest ?? (() => { throw new Error("Core loadRungManifest service not registered."); }))(repo.root);
  if (!loaded.manifest) throw new Error(loaded.error ?? "Missing .verification/rungs.json manifest.");
  const rungsToRun: RungId[] = targetRung === "all" ? (Object.keys(loaded.manifest.rungs) as RungId[]) : [targetRung];
  const receipts: RungReceipt[] = [];
  let passed = true;
  for (const r of rungsToRun) {
    const rec = runRungAndWriteReceipt(repo, r, loaded.manifest, hmacKeyOverride);
    receipts.push(rec);
    if (rec.exitCode !== 0) passed = false;
  }
  return { receipts, passed, manifestPath: loaded.path ?? ".verification/rungs.json" };
}

export async function runAllDeclaredRungsAsync(
  repo: DiscoveredRepo,
  targetRung: RungId | "all",
  hmacKeyOverride?: string,
): Promise<{ receipts: RungReceipt[]; passed: boolean; manifestPath: string; failureOutputs?: Record<string, string> }> {
  const loaded = (getCoreServices().loadRungManifest ?? (() => { throw new Error("Core loadRungManifest service not registered."); }))(repo.root);
  if (!loaded.manifest) throw new Error(loaded.error ?? "Missing .verification/rungs.json manifest.");
  const rungsToRun: RungId[] = targetRung === "all" ? (Object.keys(loaded.manifest.rungs) as RungId[]) : [targetRung];
  const receipts: RungReceipt[] = [];
  const failureOutputs: Record<string, string> = {};
  let passed = true;
  for (const r of rungsToRun) {
    const { receipt, failureOutput } = await runRungAndWriteReceiptAsync(repo, r, loaded.manifest, hmacKeyOverride);
    receipts.push(receipt);
    if (failureOutput) failureOutputs[r] = failureOutput;
    if (receipt.exitCode !== 0) passed = false;
  }
  return {
    receipts, passed, manifestPath: loaded.path ?? ".verification/rungs.json",
    ...(Object.keys(failureOutputs).length > 0 ? { failureOutputs } : {}),
  };
}
