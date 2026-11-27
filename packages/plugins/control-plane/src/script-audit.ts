import fs from "node:fs";
import path from "node:path";
import type { RungId } from "@veristack/plugin";

const SAFE_SCRIPT_BOOL_FLAGS = new Set(["--fail", "--strict", "--json", "--check", "--verify", "--quiet"]);
const SAFE_SCRIPT_VALUE_FLAGS = new Set(["--out", "--output", "--config", "--filter", "--base", "--max-time-exp", "--max-space-exp", "--samples", "--iterations", "--runs", "--warmup"]);
const SCRIPT_PATH_FLAGS = new Set(["--out", "--output", "--config"]);
const RUNG_SCRIPT_EVIDENCE: Record<RungId, RegExp> = {
  R0: /\b(?:oxlint|oxfmt|eslint|prettier|biome|ruff|golangci-lint|gofmt|cargo\s+(?:fmt|clippy)|dotnet\s+(?:format|build)|vstack|no-comments|state-machines)\b/i,
  R1: /\b(?:tsc|tsgo|mypy|pyright|basedpyright|knip|dotnet\s+build|cargo\s+(?:check|clippy)|go\s+(?:vet|build)|check-max-lines|bun\s+build)\b/i,
  R2: /\b(?:bun\s+test|vitest|jest|mocha|pytest|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test|node\s+--test)\b/i,
  R3: /\b(?:bun\s+test|vitest|jest|pytest|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test|pact|storybook|schemathesis)\b/i,
  R4: /\b(?:bun\s+test|vitest|jest|pytest|dotnet\s+test|cargo\s+(?:test|nextest)|go\s+test|migrate|testcontainers|pglite|emulator)\b/i,
  R5: /\b(?:stryker|mutmut|cargo\s+mutants|gremlins|quint|dafny|kani|bend|vstack|canary|laws|formal-sync|crap)\b/i,
  R6: /\b(?:performance\.now|hrtime|big-o|fitEmpiricalBigO|spc|k6|lighthouse|BenchmarkDotNet|tinybench|mitata|hyperfine|bench)\b/i,
  R7: /\b(?:playwright|cypress|maestro|detox|webdriverio|e2e|dotnet\s+test|bun\s+test|pytest)\b/i,
  R8: /\b(?:health|smoke|synthetic|canary|fetch|spc|curl|k6|playwright)\b/i,
};

export const REPO_VERIFY_SCRIPT_RE = /^(?:bun|node)\s+(?:\.\/)?(?:scripts|tools)\/verify[-_a-z0-9]*\.[cm]?[jt]sx?$/;
export const REPO_BENCH_SCRIPT_RE = /^(?:bun|node)\s+(?:\.\/)?(?:[a-z0-9_.-]+\/)*(?:bench|perf)[a-z0-9_.-]*\.[cm]?[jt]sx?$/;

export function isAllowedDotnetFilter(rung: RungId | "canary", val: string): boolean {
  if (!val) return false;
  if (rung === "R6") return /benchmark|perf/i.test(val);
  if (rung === "R4") return /integration|db|migration|postgres|sql|redis|kafka|rabbit|servicebus|emulator/i.test(val);
  if (rung === "R7") return /e2e|endtoend|playwright|browser|smoke/i.test(val);
  return false;
}

export function validateRepoScriptFlags(
  head: string,
  toolArgs: readonly string[],
  repoRoot: string | undefined,
  isInside: (candidate: string, root: string) => boolean,
): string | null {
  for (let i = 0; i < toolArgs.length; i++) {
    const tok = toolArgs[i] ?? "";
    if (!tok.startsWith("-")) {
      if (repoRoot && (tok.startsWith("/") || tok.includes("..")) && !isInside(tok, repoRoot)) return `positional path '${tok}' on '${head}' escapes repo root`;
      continue;
    }
    const eq = tok.indexOf("="); const fn = eq > 0 ? tok.slice(0, eq) : tok; const iv = eq > 0 ? tok.slice(eq + 1) : undefined;
    if (SAFE_SCRIPT_BOOL_FLAGS.has(tok) || (iv === undefined && SAFE_SCRIPT_BOOL_FLAGS.has(fn))) continue;
    if (!SAFE_SCRIPT_VALUE_FLAGS.has(fn)) return `unrecognized flag '${tok}' on '${head}'`;
    const val = iv ?? toolArgs[i + 1];
    if (!val || (iv === undefined && val.startsWith("-"))) return `flag '${fn}' on '${head}' requires a value`;
    if (SCRIPT_PATH_FLAGS.has(fn) && repoRoot && !isInside(val, repoRoot)) return `path flag '${fn}=${val}' on '${head}' escapes repo root`;
    if (iv === undefined) i += 1;
  }
  return null;
}

export function validateRepoScriptStep(input: {
  rung: RungId | "canary";
  head: string;
  repoRoot?: string;
  chainedWithBigO: boolean;
  isInside: (candidate: string, root: string) => boolean;
}): { error: string | null; satisfiesR1Typecheck: boolean } {
  const { rung, head, repoRoot, chainedWithBigO, isInside } = input;
  const scriptPath = head.split(/\s+/)[1] ?? "";
  if (repoRoot && !isInside(scriptPath, repoRoot)) return { error: `script path '${scriptPath}' escapes repo root`, satisfiesR1Typecheck: false };
  if (rung === "canary") return { error: `executable '${head}' is not an allowed canary verification tool.`, satisfiesR1Typecheck: false };
  if (!repoRoot) return REPO_BENCH_SCRIPT_RE.test(head) && rung === "R6" ? { error: null, satisfiesR1Typecheck: false } : { error: `script '${head}' requires a repository root to verify its contents`, satisfiesR1Typecheck: false };
  const absScript = path.resolve(repoRoot, scriptPath);
  if (!fs.existsSync(absScript) || !fs.statSync(absScript).isFile()) return { error: `verification script '${scriptPath}' not found`, satisfiesR1Typecheck: false };
  const raw = fs.readFileSync(absScript, "utf8");
  if (!(rung === "R6" && chainedWithBigO) && !RUNG_SCRIPT_EVIDENCE[rung].test(raw)) return { error: `verification script '${scriptPath}' lacks real ${rung} tool/benchmark logic`, satisfiesR1Typecheck: false };
  const satisfiesR1Typecheck = rung === "R1" && /\b(?:tsc|tsgo|mypy|pyright|basedpyright|cargo\s+(?:check|clippy)|dotnet\s+build|go\s+(?:vet|build))\b/i.test(raw);
  return { error: null, satisfiesR1Typecheck };
}
