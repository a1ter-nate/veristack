import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo } from "../discover.ts";
import type { Finding, PlantedFaultReport, RungId, RungManifest, RungReceipt } from "../types.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "./command-audit.ts";
import { loadRungManifest } from "./manifest.ts";
import { runPlantedFaultCanary } from "./mutation-probe.ts";
import { parseStructuredReports, reportParsers } from "./reports.ts";
import { parseRunnerTestCounts, stripAnsi } from "./runner-metrics.ts";

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
  const gitList = spawnSync("git", ["-C", repo.root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
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
  const res = spawnSync("git", ["-C", repoRoot, "ls-files", RECEIPTS_REL_DIR], { encoding: "utf8" });
  return res.status === 0 && res.stdout.trim().length > 0;
}

function readGitHeadSha(repoRoot: string): string {
  const res = spawnSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], { encoding: "utf8" });
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

function parseCommandMetrics(
  repoRoot: string,
  rawOutput: string,
  rung: RungId,
  steps: readonly string[][],
  preSnapshot: ReadonlyMap<string, { mtimeMs: number; size: number }>,
): { metrics: RungReceipt["metrics"]; hasTestRunner: boolean } {
  const output = stripAnsi(rawOutput);
  const structured = parseStructuredReports(repoRoot, { rung, preSnapshot });
  const metrics: NonNullable<RungReceipt["metrics"]> = {};
  if (typeof structured.testsPassed === "number") metrics.testsPassed = structured.testsPassed;
  if (typeof structured.testsFailed === "number") metrics.testsFailed = structured.testsFailed;
  if (typeof structured.mutationScore === "number") metrics.mutationScore = structured.mutationScore;

  const parsedCounts = parseRunnerTestCounts(output, steps);
  if (metrics.testsPassed === undefined && parsedCounts.matched) {
    metrics.testsPassed = parsedCounts.passed;
    metrics.testsFailed = parsedCounts.failed;
  }
  if (metrics.mutationScore === undefined && rung === "R5") {
    const mutationMatch = /mutation\s+score[:\s]+(\d+(?:\.\d+)?)%/i.exec(output);
    if (mutationMatch?.[1]) metrics.mutationScore = Number(mutationMatch[1]);
  }
  if (/check-perf-budget:\s*PASS|Big-O\s*\[PASS\]/i.test(output)) metrics.perfPassed = true;
  return { metrics: Object.keys(metrics).length > 0 ? metrics : undefined, hasTestRunner: parsedCounts.hasTestRunner };
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
  const proc = runArgvChain(parsedCmd.steps, repo.root, scrubChildEnv(), 300_000);
  const durationMs = Math.round(performance.now() - started);
  const exitCode = proc.status;
  const combined = `${proc.stdout}\n${proc.stderr}`;
  const { metrics, hasTestRunner } = parseCommandMetrics(repo.root, combined, rung, parsedCmd.steps, preSnapshot);
  const treeHashAfter = computeRepoTreeHash(repo);
  const mutatedTree = treeHashBefore !== treeHashAfter;

  let canary: PlantedFaultReport | undefined;
  if (exitCode === 0 && !mutatedTree && entry.canary?.enabled) {
    canary = runPlantedFaultCanary({
      repoRoot: repo.root,
      testCmd: entry.canary.testCommand ?? entry.command,
      targets: entry.canary.targets,
      maxMutants: entry.canary.maxMutants,
      minKillRate: entry.canary.minKillRate,
    });
  }

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
    schemaVersion: 1,
    rung,
    command: entry.command,
    commitSha,
    treeHash: treeHashAfter,
    exitCode: finalExit,
    durationMs,
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

export function loadValidReceipts(
  repo: DiscoveredRepo,
  manifest?: RungManifest,
  options?: { strict?: boolean; hmacKeyOverride?: string },
): { receipts: Map<RungId, RungReceipt>; findings: Finding[] } {
  const valid = new Map<RungId, RungReceipt>();
  const findings: Finding[] = [];

  if (hasGitTrackedReceipts(repo.root)) {
    findings.push({
      id: "RCPT:tracked-in-git:.verification/receipts",
      rule: "receipt-committed-to-git",
      category: "cheat",
      rung: "R0",
      severity: "error",
      file: ".verification/receipts",
      line: 1,
      message: "Receipts in .verification/receipts/ are tracked by git — receipts must be generated dynamically at CI runtime, never committed.",
      fix: "Add .verification/receipts/ to .gitignore and run 'git rm -r --cached .verification/receipts'.",
    });
    return { receipts: valid, findings };
  }

  const activeKey = options?.hmacKeyOverride ?? process.env.VSTACK_RECEIPT_KEY;
  const requireHmac = Boolean(options?.strict);
  if (requireHmac && (!activeKey || activeKey.length < 8)) {
    findings.push({
      id: "RCPT:unsigned-strict:.verification/receipts",
      rule: "receipt-unsigned-strict",
      category: "oracle-lock",
      rung: "R0",
      severity: "error",
      file: ".verification/receipts",
      line: 1,
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
      if (raw.schemaVersion !== 1 || !raw.rung || typeof raw.digest !== "string") continue;
      if (name !== `${raw.rung}.json`) continue;
      const declared = manifest?.rungs[raw.rung];
      if (!declared || raw.command !== declared.command) continue;
      if (requireHmac && !raw.digest.startsWith("hmac:")) continue;
      const { digest, ...rest } = raw;
      if (digestPayload(rest, activeKey) !== digest) continue;
      if (raw.exitCode !== 0 || raw.treeHash !== expectedTreeHash) continue;
      if (expectedHead !== "no-git" && raw.commitSha !== expectedHead) continue;
      if (activeCiRunId && raw.ciRunId !== activeCiRunId) continue;
      const needsTests = raw.rung === "R2" || raw.rung === "R3" || ((raw.rung === "R4" || raw.rung === "R7") && /\b(?:test|pytest|vitest|jest|mocha|ava|playwright|cypress|unittest|nextest)\b/i.test(declared.command));
      if (needsTests && ((raw.metrics?.testsPassed ?? 0) <= 0 || (raw.metrics?.testsFailed ?? 0) > 0)) continue;
      if (declared.canary?.enabled) {
        const minFloor = Math.max(0.75, declared.canary.minKillRate ?? 0.8);
        const minMutants = Math.min(4, declared.canary.maxMutants ?? 4);
        if (!raw.canary || !raw.canary.passed || raw.canary.killRate < minFloor || raw.canary.totalMutants < minMutants || raw.canary.invalidKills > 0) continue;
      }
      if (raw.canary && !raw.canary.passed) continue;
      valid.set(raw.rung, raw);
    } catch {
      continue;
    }
  }
  return { receipts: valid, findings };
}

export function runAllDeclaredRungs(
  repo: DiscoveredRepo,
  targetRung: RungId | "all",
  hmacKeyOverride?: string,
): { receipts: RungReceipt[]; passed: boolean; manifestPath: string } {
  const loaded = loadRungManifest(repo.root);
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
