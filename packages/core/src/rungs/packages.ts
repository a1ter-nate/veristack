import type { Language, RungId } from "@veristack/plugin";

const PACKAGES_BY_LANG: Record<string, Record<RungId, string>> = {
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
