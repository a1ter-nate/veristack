import fs from "node:fs";
import path from "node:path";
import { discoverRepo, type DiscoveredRepo } from "../discover.ts";
import { buildRungStatuses } from "../rungs/coverage.ts";
import { analyzeTests } from "../test-analyzer.ts";
import type { Language, RepoArchetype, RungId, RungManifest } from "../types.ts";
import { manageHooks } from "./install.ts";
import type { HookHarness } from "./runtime.ts";

export interface InitRepoOptions {
  force?: boolean;
  noHooks?: boolean;
  harnesses?: readonly HookHarness[];
  commandPrefix?: string;
}

export interface InitRepoResult {
  repoRoot: string;
  archetype: RepoArchetype;
  languages: Language[];
  manifestPath: string;
  manifestCreated: boolean;
  gitignoreUpdated: boolean;
  hooksEnabled: boolean;
  touchedFiles: string[];
  uncoveredRungs: RungId[];
  testFilesCount: number;
  summary: string;
}

function buildDefaultRungEntries(
  languages: readonly Language[],
  archetype: RepoArchetype,
  hasBun: boolean,
): RungManifest["rungs"] {
  if (!archetype) throw new Error("archetype is required.");
  const isTs = languages.includes("typescript") || languages.includes("javascript") || languages.length === 0;
  const isCs = languages.includes("csharp");
  const isRust = languages.includes("rust");
  const isPy = languages.includes("python");
  const isGo = languages.includes("go");
  const needsService = archetype === "service" || archetype === "fullstack";
  const needsE2e = archetype !== "library";

  const rungs: RungManifest["rungs"] = {};
  if (isTs) {
    const testCmd = hasBun ? "bun test ./tests/" : "vitest run";
    rungs.R0 = { command: "npx --no-install oxlint src tests && npx --no-install vstack no-comments . --fail && npx --no-install vstack state-machines . --fail", required: true };
    rungs.R1 = { command: "npx --no-install tsc --noEmit", required: true };
    rungs.R2 = { command: testCmd, required: true, canary: { enabled: true, testCommand: testCmd, maxMutants: 8, minKillRate: 0.75 } };
    rungs.R3 = { command: testCmd, required: true };
    if (needsService) rungs.R4 = { command: testCmd, required: true };
    rungs.R5 = { command: `npx --no-install vstack canary . --test-cmd "${testCmd}" --max-mutants 6 --min-kill-rate 0.75 --fail`, required: true };
    rungs.R6 = { command: "npx --no-install vstack big-o .verification/perf-samples.json --fail", required: true };
    if (needsE2e) rungs.R7 = { command: "npx --no-install playwright test", required: true };
    if (needsService) rungs.R8 = { command: "npx --no-install vstack spc .verification/slo-metrics.json --fail", required: true };
    return rungs;
  }
  if (isCs) {
    rungs.R0 = { command: "dotnet format --verify-no-changes && npx --no-install vstack no-comments . --fail && npx --no-install vstack state-machines . --fail", required: true };
    rungs.R1 = { command: "dotnet build --warnaserror", required: true };
    rungs.R2 = { command: "dotnet test", required: true, canary: { enabled: true, testCommand: "dotnet test", maxMutants: 8, minKillRate: 0.75 } };
    rungs.R3 = { command: "dotnet test", required: true };
    if (needsService) rungs.R4 = { command: "dotnet test --filter Category=Integration", required: true };
    rungs.R5 = { command: "dotnet stryker", required: true };
    rungs.R6 = { command: "dotnet test --filter Category=Benchmark", required: true };
    if (needsE2e) rungs.R7 = { command: "dotnet test --filter Category=E2E", required: true };
    return rungs;
  }
  if (isRust) {
    rungs.R0 = { command: "cargo fmt --check && cargo clippy --all-targets -- -D warnings", required: true };
    rungs.R1 = { command: "cargo check --all-targets", required: true };
    rungs.R2 = { command: "cargo test", required: true, canary: { enabled: true, testCommand: "cargo test", maxMutants: 8, minKillRate: 0.75 } };
    rungs.R3 = { command: "cargo test", required: true };
    rungs.R5 = { command: "cargo mutants", required: true };
    rungs.R6 = { command: "cargo bench", required: true };
    return rungs;
  }
  if (isPy) {
    rungs.R0 = { command: "ruff check && ruff format --check", required: true };
    rungs.R1 = { command: "mypy --strict src", required: true };
    rungs.R2 = { command: "pytest", required: true, canary: { enabled: true, testCommand: "pytest", maxMutants: 8, minKillRate: 0.75 } };
    rungs.R3 = { command: "pytest", required: true };
    rungs.R5 = { command: "mutmut run", required: true };
    rungs.R6 = { command: "pytest --benchmark-only", required: true };
    return rungs;
  }
  if (isGo) {
    rungs.R0 = { command: "golangci-lint run", required: true };
    rungs.R1 = { command: "go vet ./...", required: true };
    rungs.R2 = { command: "go test -race -count=1 ./...", required: true, canary: { enabled: true, testCommand: "go test -race -count=1 ./...", maxMutants: 8, minKillRate: 0.75 } };
    rungs.R3 = { command: "go test -race -count=1 ./...", required: true };
    rungs.R5 = { command: "gremlins unleash", required: true };
    rungs.R6 = { command: "go test -bench=. ./...", required: true };
  }
  return rungs;
}

function ensureReceiptsGitignored(repoRoot: string): boolean {
  const giPath = path.join(repoRoot, ".gitignore");
  const entry = ".verification/receipts/";
  if (fs.existsSync(giPath)) {
    const raw = fs.readFileSync(giPath, "utf8");
    if (raw.includes(".verification/receipts")) return false;
    const sep = raw.length > 0 && !raw.endsWith("\n") ? "\n" : "";
    fs.writeFileSync(giPath, `${raw}${sep}${entry}\n`, "utf8");
    return true;
  }
  fs.writeFileSync(giPath, `${entry}\n`, "utf8");
  return true;
}

function hasBunIndicator(repo: DiscoveredRepo): boolean {
  return repo.allRelPaths.some((p) => p === "bun.lock" || p === "bun.lockb" || p === "bunfig.toml");
}

export function initVeristackRepo(repoPath: string, options: InitRepoOptions = {}): InitRepoResult {
  if (!repoPath) throw new Error("repoPath is required.");
  const repoRoot = path.resolve(repoPath);
  if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
    throw new Error(`Directory not found: ${repoPath}`);
  }
  const repo = discoverRepo(repoRoot);
  const manifestRel = ".verification/rungs.json";
  const manifestAbs = path.join(repoRoot, manifestRel);
  const touchedFiles: string[] = [];
  let manifestCreated = false;

  if (options.force || !fs.existsSync(manifestAbs)) {
    const manifest: RungManifest = {
      schemaVersion: 1,
      archetype: repo.observedArchetype,
      allowExcluded: [],
      rungs: buildDefaultRungEntries(repo.languages, repo.observedArchetype, hasBunIndicator(repo)),
    };
    fs.mkdirSync(path.dirname(manifestAbs), { recursive: true });
    fs.writeFileSync(manifestAbs, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    manifestCreated = true;
    touchedFiles.push(manifestRel);
  }

  const gitignoreUpdated = ensureReceiptsGitignored(repoRoot);
  if (gitignoreUpdated) touchedFiles.push(".gitignore");

  let hooksEnabled = false;
  if (!options.noHooks) {
    const hookRes = manageHooks(repoRoot, "on", {
      harnesses: options.harnesses,
      commandPrefix: options.commandPrefix,
    });
    hooksEnabled = hookRes.enabled;
    touchedFiles.push(...hookRes.touchedManifests, hookRes.configPath);
  }

  const afterRepo = discoverRepo(repoRoot);
  const testResult = analyzeTests(afterRepo);
  const rungs = buildRungStatuses(afterRepo, testResult.inventory, { requireReceipts: false });
  const uncoveredRungs = rungs
    .filter((r) => r.coverageGrade === "not-covered" || r.coverageGrade === "over-budget")
    .map((r) => r.rung);
  const testFilesCount = afterRepo.files.filter((f) => f.language && f.isTest).length;
  const summary = `vstack init: archetype=${afterRepo.archetype} | languages=[${afterRepo.languages.join(", ") || "none"}] | manifest=${manifestCreated ? "created" : "kept"} | hooks=${hooksEnabled ? "ON" : "skipped"} | tests=${testFilesCount} | uncovered=[${uncoveredRungs.join(", ") || "none"}]`;

  return {
    repoRoot,
    archetype: afterRepo.archetype,
    languages: afterRepo.languages,
    manifestPath: manifestRel,
    manifestCreated,
    gitignoreUpdated,
    hooksEnabled,
    touchedFiles: [...new Set(touchedFiles)],
    uncoveredRungs,
    testFilesCount,
    summary,
  };
}

export function formatInitReport(result: InitRepoResult): string {
  const lines = [result.summary];
  if (result.touchedFiles.length > 0) lines.push(`  Touched: ${result.touchedFiles.join(", ")}`);
  if (result.testFilesCount === 0 || result.uncoveredRungs.length > 0) {
    lines.push("  Next required steps before Veristack passes:");
    if (result.testFilesCount === 0) lines.push("    - Write real behavioral tests (R2 unit tables + PBT, R3 boundary/MBT) — zero-test repos are blocked by Stop hook & --strict.");
    if (result.uncoveredRungs.length > 0) lines.push(`    - Cover missing applicable rungs [${result.uncoveredRungs.join(", ")}] and wire them into CI.`);
    lines.push("    - Run 'vstack verify . --strict' and 'vstack doctor . --fail' until both exit 0.");
  }
  return lines.join("\n");
}
