import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo } from "../discover.ts";
import type { PlantedFaultReport, RungId, RungManifest, RungReceipt } from "../types.ts";
import { loadRungManifest } from "./manifest.ts";
import { runPlantedFaultCanary } from "./mutation-probe.ts";

const RECEIPTS_REL_DIR = ".verification/receipts";

function digestPayload(receipt: Omit<RungReceipt, "digest">): string {
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
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

export function computeRepoTreeHash(repo: DiscoveredRepo): string {
  const hasher = crypto.createHash("sha256");
  const sorted = [...repo.files]
    .filter((f) => !f.rel.startsWith(`${RECEIPTS_REL_DIR}/`))
    .sort((a, b) => a.rel.localeCompare(b.rel));
  for (const file of sorted) {
    hasher.update(file.rel);
    hasher.update("\0");
    hasher.update(file.content);
    hasher.update("\0");
  }
  return hasher.digest("hex");
}

function readGitHeadSha(repoRoot: string): string {
  const res = spawnSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], { encoding: "utf8" });
  if (res.status === 0 && res.stdout.trim()) return res.stdout.trim();
  return "no-git";
}

function parseCommandMetrics(output: string): RungReceipt["metrics"] {
  const metrics: NonNullable<RungReceipt["metrics"]> = {};
  const bunPass = /\b(\d+)\s+pass\b/i.exec(output);
  const bunFail = /\b(\d+)\s+fail\b/i.exec(output);
  if (bunPass?.[1]) metrics.testsPassed = Number(bunPass[1]);
  if (bunFail?.[1]) metrics.testsFailed = Number(bunFail[1]);

  const pytestPass = /(\d+)\s+passed\b/i.exec(output);
  if (pytestPass?.[1] && metrics.testsPassed === undefined) metrics.testsPassed = Number(pytestPass[1]);

  const mutationMatch = /mutation\s+score[:\s]+(\d+(?:\.\d+)?)%/i.exec(output);
  if (mutationMatch?.[1]) metrics.mutationScore = Number(mutationMatch[1]);

  if (/check-perf-budget:\s*PASS|Big-O\s*\[PASS\]/i.test(output)) metrics.perfPassed = true;
  return Object.keys(metrics).length > 0 ? metrics : undefined;
}

export function runRungAndWriteReceipt(
  repo: DiscoveredRepo,
  rung: RungId,
  manifest: RungManifest,
): RungReceipt {
  const entry = manifest.rungs[rung];
  if (!entry) {
    throw new Error(`Rung ${rung} is not declared in .verification/rungs.json.`);
  }
  const treeHash = computeRepoTreeHash(repo);
  const commitSha = readGitHeadSha(repo.root);
  const started = performance.now();
  const proc = spawnSync(entry.command, [], {
    cwd: repo.root,
    shell: true,
    encoding: "utf8",
    timeout: 300_000,
  });
  const durationMs = Math.round(performance.now() - started);
  const exitCode = proc.status ?? 1;
  const combined = `${proc.stdout ?? ""}\n${proc.stderr ?? ""}`;
  const metrics = parseCommandMetrics(combined);

  let canary: PlantedFaultReport | undefined;
  if (exitCode === 0 && entry.canary?.enabled) {
    canary = runPlantedFaultCanary({
      repoRoot: repo.root,
      testCmd: entry.canary.testCommand ?? entry.command,
      targets: entry.canary.targets,
      maxMutants: entry.canary.maxMutants,
      minKillRate: entry.canary.minKillRate,
    });
  }

  const finalExit = canary && !canary.passed ? 1 : exitCode;
  const baseReceipt: Omit<RungReceipt, "digest"> = {
    schemaVersion: 1,
    rung,
    command: entry.command,
    commitSha,
    treeHash,
    exitCode: finalExit,
    durationMs,
    ...(process.env.GITHUB_RUN_ID ? { ciRunId: process.env.GITHUB_RUN_ID } : {}),
    ...(metrics ? { metrics } : {}),
    ...(canary ? { canary } : {}),
    timestamp: new Date().toISOString(),
  };

  const receipt: RungReceipt = {
    ...baseReceipt,
    digest: digestPayload(baseReceipt),
  };

  const dir = path.join(repo.root, RECEIPTS_REL_DIR);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${rung}.json`), `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return receipt;
}

export function loadValidReceipts(
  repo: DiscoveredRepo,
  manifest?: RungManifest,
): Map<RungId, RungReceipt> {
  const valid = new Map<RungId, RungReceipt>();
  const dir = path.join(repo.root, RECEIPTS_REL_DIR);
  if (!fs.existsSync(dir)) return valid;

  const expectedTreeHash = computeRepoTreeHash(repo);

  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")) as RungReceipt;
      if (raw.schemaVersion !== 1 || !raw.rung || typeof raw.digest !== "string") continue;
      const { digest, ...rest } = raw;
      if (digestPayload(rest) !== digest) continue;
      if (raw.exitCode !== 0) continue;
      if (raw.treeHash !== expectedTreeHash) continue;
      const declared = manifest?.rungs[raw.rung];
      if (declared && raw.command !== declared.command) continue;
      if (declared?.canary?.enabled && (!raw.canary || !raw.canary.passed)) continue;
      if (raw.canary && !raw.canary.passed) continue;
      valid.set(raw.rung, raw);
    } catch {
      continue;
    }
  }
  return valid;
}

export function runAllDeclaredRungs(
  repo: DiscoveredRepo,
  targetRung: RungId | "all",
): { receipts: RungReceipt[]; passed: boolean; manifestPath: string } {
  const loaded = loadRungManifest(repo.root);
  if (!loaded.manifest) {
    throw new Error(loaded.error ?? "Missing .verification/rungs.json manifest.");
  }
  const rungsToRun: RungId[] =
    targetRung === "all"
      ? (Object.keys(loaded.manifest.rungs) as RungId[])
      : [targetRung];
  const receipts: RungReceipt[] = [];
  let passed = true;
  for (const r of rungsToRun) {
    const rec = runRungAndWriteReceipt(repo, r, loaded.manifest);
    receipts.push(rec);
    if (rec.exitCode !== 0) passed = false;
  }
  return { receipts, passed, manifestPath: loaded.path ?? ".verification/rungs.json" };
}
