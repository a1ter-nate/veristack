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
        hasher.update(rel);
        hasher.update("\0symlink:");
        hasher.update(fs.readlinkSync(abs));
        hasher.update("\0");
        continue;
      }
      if (!stat.isFile()) continue;
      hasher.update(rel);
      hasher.update("\0");
      hasher.update(fs.readFileSync(abs));
      hasher.update("\0");
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

function sumMatches(text: string, regex: RegExp): { found: boolean; sum: number } {
  let found = false;
  let sum = 0;
  for (const m of text.matchAll(regex)) {
    if (m[1] !== undefined) {
      found = true;
      sum += Number(m[1]);
    }
  }
  return { found, sum };
}

function detectRunners(steps: readonly string[][]): Set<string> {
  const runners = new Set<string>();
  for (const seg of steps) {
    for (const tok of seg.slice(0, 4)) {
      const low = tok.toLowerCase();
      if (/^(?:bun|node|vitest|jest|mocha|ava|pytest|cargo|dotnet|go|phpunit|rspec|unittest)$/.test(low)) {
        runners.add(low);
      }
    }
  }
  return runners;
}

function parseCommandMetrics(
  repoRoot: string,
  output: string,
  rung: RungId,
  steps: readonly string[][],
  preSnapshot: ReadonlyMap<string, { mtimeMs: number; size: number }>,
): RungReceipt["metrics"] {
  const structured = parseStructuredReports(repoRoot, { rung, preSnapshot });
  const metrics: NonNullable<RungReceipt["metrics"]> = {};
  if (structured.testsPassed !== undefined && Number.isFinite(structured.testsPassed)) metrics.testsPassed = structured.testsPassed;
  if (structured.testsFailed !== undefined && Number.isFinite(structured.testsFailed)) metrics.testsFailed = structured.testsFailed;
  if (structured.mutationScore !== undefined && Number.isFinite(structured.mutationScore)) metrics.mutationScore = structured.mutationScore;

  if (metrics.testsPassed === undefined) {
    const runners = detectRunners(steps);
    let passed = 0;
    let failed = 0;
    let matched = false;

    if (runners.has("cargo")) {
      const p = sumMatches(output, /test result:\s*(?:ok|FAILED)\.\s*(\d+)\s+passed/gi);
      const f = sumMatches(output, /test result:[^;\n]*?(\d+)\s+failed/gi);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("bun")) {
      const p = sumMatches(output, /^\s*(\d+)\s+pass$/gm);
      const f = sumMatches(output, /^\s*(\d+)\s+fail$/gm);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("node")) {
      const p = sumMatches(output, /^\s*(?:ℹ|#)\s*pass\s+(\d+)\s*$/gm);
      const f = sumMatches(output, /^\s*(?:ℹ|#)\s*fail\s+(\d+)\s*$/gm);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("vitest") || runners.has("jest")) {
      const p = sumMatches(output, /^\s*Tests:?\s+[^\n]*?(\d+)\s+passed\b/gm);
      const f = sumMatches(output, /^\s*Tests:?\s+[^\n]*?(\d+)\s+failed\b/gm);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("pytest")) {
      const p = sumMatches(output, /\b(\d+)\s+passed\b/gi);
      const f = sumMatches(output, /\b(\d+)\s+failed\b/gi);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("dotnet")) {
      const p = sumMatches(output, /\bPassed:\s*(\d+)/gi);
      const f = sumMatches(output, /\bFailed:\s*(\d+)/gi);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("go")) {
      const noTestsWarn = /testing:\s*warning:\s*no tests to run/i.test(output);
      const goVerbose = (output.match(/^---\s+PASS:/gm) ?? []).length;
      const goPkg = noTestsWarn ? 0 : (output.match(/^ok\s+\S+(?![^\n]*\[no tests to run\])/gm) ?? []).length;
      const goFail = (output.match(/^FAIL\s+\S+/gm) ?? []).length;
      if (goVerbose > 0 || goPkg > 0 || goFail > 0) {
        passed += goVerbose > 0 ? goVerbose : goPkg;
        failed += goFail;
        matched = true;
      }
    }
    if (runners.has("mocha")) {
      const p = sumMatches(output, /^\s*(\d+)\s+passing\b/gm);
      const f = sumMatches(output, /^\s*(\d+)\s+failing\b/gm);
      if (p.found) { passed += p.sum; failed += f.sum; matched = true; }
    }
    if (runners.has("ava")) {
      const p = sumMatches(output, /^\s*(\d+)\s+tests?\s+passed\b/gm);
      if (p.found) { passed += p.sum; matched = true; }
    }
    if (runners.has("phpunit")) {
      const p = sumMatches(output, /OK\s*\((\d+)\s+tests?/gi);
      if (p.found) { passed += p.sum; matched = true; }
    }
    if (runners.has("rspec")) {
      const p = sumMatches(output, /(\d+)\s+examples?,\s*0\s+failures?/gi);
      if (p.found) { passed += p.sum; matched = true; }
    }
    if (matched) {
      metrics.testsPassed = passed;
      metrics.testsFailed = failed;
    }
  }

  if (metrics.mutationScore === undefined && rung === "R5") {
    const mutationMatch = /mutation\s+score[:\s]+(\d+(?:\.\d+)?)%/i.exec(output);
    if (mutationMatch?.[1]) metrics.mutationScore = Number(mutationMatch[1]);
  }
  if (/check-perf-budget:\s*PASS|Big-O\s*\[PASS\]/i.test(output)) metrics.perfPassed = true;
  return Object.keys(metrics).length > 0 ? metrics : undefined;
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
  const metrics = parseCommandMetrics(repo.root, combined, rung, parsedCmd.steps, preSnapshot);
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
  const testCountMissing =
    (rung === "R2" || rung === "R3") &&
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
      if ((raw.rung === "R2" || raw.rung === "R3") && ((raw.metrics?.testsPassed ?? 0) <= 0 || (raw.metrics?.testsFailed ?? 0) > 0)) continue;
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
