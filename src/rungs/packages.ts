import fs from "node:fs";
import path from "node:path";
import type { Language, RungId } from "../types.ts";

const PACKAGES_BY_LANG: Record<Language, Record<RungId, string>> = {
  typescript: {
    R0: "oxfmt, oxlint, veristack (veristack/lint), lefthook",
    R1: "typescript (strict + noUnusedLocals), knip, dependency-cruiser",
    R2: "vitest / bun:test, fast-check (PBT)",
    R3: "fast-check (fc.commands MBT), @testing-library/react, msw (onUnhandledRequest: 'error'), @pact-foundation/pact",
    R4: "@testcontainers/postgresql / @electric-sql/pglite, prisma/drizzle migration tests",
    R5: "@stryker-mutator/core, vstack canary, bend / quint, @playwright/test (toHaveScreenshot)",
    R6: "k6, @lhci/cli, web-vitals, vstack big-o / spc",
    R7: "@playwright/test (5-15 golden journeys, zero network mocks)",
    R8: "@opentelemetry/sdk-node, synthetic health probes",
  },
  javascript: {
    R0: "oxfmt, oxlint, veristack (veristack/lint), lefthook",
    R1: "knip, dependency-cruiser, JSDoc checkJs",
    R2: "vitest / node:test, fast-check (PBT)",
    R3: "fast-check (fc.commands MBT), @testing-library/react, msw, @pact-foundation/pact",
    R4: "testcontainers, pglite, DB migration checks",
    R5: "@stryker-mutator/core, vstack canary, quint / bend",
    R6: "k6, lighthouse, vstack big-o / spc",
    R7: "@playwright/test (thin golden journeys)",
    R8: "@opentelemetry/sdk-node, synthetic checks",
  },
  csharp: {
    R0: "dotnet format, VStack.Analyzers, Roslyn AnalysisLevel=latest-all, lefthook",
    R1: "Nullable=enable, TreatWarningsAsErrors, NetArchTest.Rules",
    R2: "xUnit (Theory/InlineData), FsCheck.Xunit (PBT)",
    R3: "FsCheck.Experimental (MBT), Microsoft.AspNetCore.Mvc.Testing, PactNet",
    R4: "Testcontainers.PostgreSql / Testcontainers.MsSql, Respawn, EF Core MigrateAsync",
    R5: "Stryker.NET (dotnet-stryker), Dafny / Quint / Bend 2",
    R6: "BenchmarkDotNet, NBomber / k6",
    R7: "Microsoft.Playwright (1-3 cross-service / 5-15 UI golden journeys)",
    R8: "OpenTelemetry.Extensions.Hosting, Aspire / synthetic probes",
  },
  rust: {
    R0: "rustfmt, clippy (-D warnings, unwrap_used/expect_used = deny), lefthook",
    R1: "rustc (unsafe_code = forbid), cargo-udeps / cargo-machete",
    R2: "rstest (tables), proptest (PBT)",
    R3: "proptest-state-machine / stateright (MBT), tower::ServiceExt / axum oneshot",
    R4: "testcontainers-modules, sqlx::test + migrations",
    R5: "cargo-mutants, kani / stateright / loom / Bend 2",
    R6: "criterion, divan, k6",
    R7: "thin black-box CLI/service smoke harness",
    R8: "tracing-opentelemetry, synthetic probes",
  },
  python: {
    R0: "ruff (check + format, S101 prod assert ban), pre-commit / lefthook",
    R1: "mypy --strict / pyright, vulture / import-linter",
    R2: "pytest (@pytest.mark.parametrize), hypothesis (PBT)",
    R3: "hypothesis.stateful.RuleBasedStateMachine (MBT), FastAPI TestClient, schemathesis",
    R4: "testcontainers-python, alembic upgrade tests",
    R5: "mutmut, crosshair / z3-solver / Bend 2",
    R6: "pytest-benchmark, locust / k6",
    R7: "playwright-python (thin golden journeys)",
    R8: "opentelemetry-sdk, synthetic probes",
  },
  go: {
    R0: "gofmt, golangci-lint, lefthook",
    R1: "go vet, deadcode, internal/ package boundaries",
    R2: "testing (table-driven), pgregory.net/rapid or testing/quick (PBT)",
    R3: "pgregory.net/rapid StateMachine (MBT), httptest.Server, pact-go",
    R4: "testcontainers-go, golang-migrate / goose verification",
    R5: "go-mutesting / gremlins, Bend 2 / Quint / TLA+",
    R6: "testing.B + benchstat, k6",
    R7: "thin cross-service black-box E2E (go test -race)",
    R8: "go.opentelemetry.io/otel, synthetic probes",
  },
};

export function recommendPackagesForRung(languages: readonly Language[], rung: RungId): string[] {
  const langs: readonly Language[] = languages.length > 0 ? languages : ["typescript"];
  const lines: string[] = [];
  for (const lang of langs) {
    const rec = PACKAGES_BY_LANG[lang]?.[rung];
    if (rec) lines.push(`${lang}: ${rec}`);
  }
  return lines;
}

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
