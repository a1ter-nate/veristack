import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { discoverRepo } from "../../src/discover.ts";
import { runDoctor } from "../../src/hooks/doctor.ts";
import { scanRepo } from "../../src/ladder.ts";
import { parseAndValidateCommandArgv } from "../../src/rungs/command-audit.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";

const cliPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "cli.ts");

function makeTempRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oss-cal-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }
  return dir;
}

test("workflow audit allows benign GOFLAGS build tags, rejects dangerous GOFLAGS, and recognizes verification actions", () => {
  const safeGoWf = parseGitHubWorkflow({
    abs: "/tmp/ci.yml",
    rel: ".github/workflows/ci.yml",
    isTest: false,
    isWorkflow: true,
    lines: 12,
    content: [
      "on: [pull_request]",
      "env:",
      "  GOFLAGS: '-tags=nobadger,nomysql -race'",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: golangci/golangci-lint-action@v6",
      "      - uses: golang/govulncheck-action@v1",
      "      - run: go test ./...",
    ].join("\n"),
  });
  assert.equal(safeGoWf.isPrBlocking, true);
  assert.ok(safeGoWf.activeCommands.includes("golangci-lint run"));
  assert.ok(safeGoWf.activeCommands.includes("govulncheck"));
  assert.ok(safeGoWf.activeCommands.some((c) => c.includes("go test")));

  const poisonedGoWf = parseGitHubWorkflow({
    abs: "/tmp/ci.yml",
    rel: ".github/workflows/ci.yml",
    isTest: false,
    isWorkflow: true,
    lines: 9,
    content: [
      "on: [pull_request]",
      "env:",
      "  GOFLAGS: '-exec=/tmp/fake'",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: go test ./...",
    ].join("\n"),
  });
  assert.equal(poisonedGoWf.activeCommands.length, 0);
});

test("partitioned CI paths-ignore is accepted only when sibling PR workflow covers ignored paths", () => {
  const covered = makeTempRepo({
    "package.json": JSON.stringify({ name: "my-lib", exports: { ".": "./dist/index.js" }, scripts: { test: "vp test --run" } }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
    "src/index.test.ts": "import { test } from 'vitest'; import { add } from './index'; test('a', () => { if (add(1,2) !== 3) throw new Error(); });\n",
    ".github/workflows/ci.yml": [
      "on:",
      "  pull_request:",
      "    paths-ignore: ['adapters/**', 'docs/**', '.gitignore']",
      "jobs:",
      "  main:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: pnpm run test",
    ].join("\n"),
    ".github/workflows/ci-adapters.yml": [
      "on:",
      "  pull_request:",
      "    paths: ['adapters/**']",
      "jobs:",
      "  adapters:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: pnpm run test",
    ].join("\n"),
  });
  const uncovered = makeTempRepo({
    "package.json": JSON.stringify({ name: "my-lib", scripts: { test: "vitest run" } }),
    "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
    ".github/workflows/ci.yml": [
      "on:",
      "  pull_request:",
      "    paths-ignore: ['src/**']",
      "jobs:",
      "  main:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: pnpm run test",
    ].join("\n"),
  });
  try {
    const okRepo = discoverRepo(covered);
    assert.equal(okRepo.ci.hasCiWorkflows, true);
    assert.equal(okRepo.ci.runsUnitTests, true);

    const badRepo = discoverRepo(uncovered);
    assert.equal(badRepo.ci.hasCiWorkflows, false);
  } finally {
    fs.rmSync(covered, { recursive: true, force: true });
    fs.rmSync(uncovered, { recursive: true, force: true });
  }
});

test("CI shell-script expansion, Rust inline cfg(test), pure re-export facade crates, and scoped npm signals work accurately", () => {
  const pyDir = makeTempRepo({
    "pyproject.toml": '[project]\nname = "fastapi"\ndependencies = ["starlette>=1.0"]\n',
    "fastapi/applications.py": 'class FastAPI:\n    """app = FastAPI()"""\n    pass\n',
    "docs_src/tutorial001.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    "tests/test_app.py": "from fastapi.applications import FastAPI\ndef test_ok():\n    assert FastAPI is not None\n",
    "scripts/test-cov.sh": "#!/usr/bin/env bash\nbash scripts/test.sh\n",
    "scripts/test.sh": "#!/usr/bin/env bash\npytest tests\n",
    ".github/workflows/test.yml": [
      "on: [pull_request]",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: uv run --no-sync bash scripts/test-cov.sh",
    ].join("\n"),
  });
  const rsDir = makeTempRepo({
    "Cargo.toml": '[workspace]\nmembers = ["crates/core", "crates/facade"]\n',
    "crates/core/Cargo.toml": '[package]\nname = "core"\nversion = "0.1.0"\n',
    "crates/core/src/lib.rs": "pub fn double(x: i32) -> i32 { x * 2 }\n#[cfg(test)]\nmod tests {\n  use super::*;\n  #[test]\n  fn doubles() { assert_eq!(double(2), 4); }\n}\n",
    "crates/facade/Cargo.toml": '[package]\nname = "facade"\nversion = "0.1.0"\n',
    "crates/facade/src/lib.rs": "pub extern crate core as reexported;\n",
    "fuzz/Cargo.toml": '[package]\nname = "fuzz"\nversion = "0.1.0"\n',
    "fuzz/src/main.rs": "fn main() {}\n",
  });
  const goDir = makeTempRepo({
    "go.mod": "module example.com/demo\ngo 1.23\n",
    "main.go": "package demo\nfunc Add(a, b int) int { return a + b }\n",
    "main_test.go": [
      "package demo",
      'import ("runtime"; "testing")',
      "func TestCondSkip(t *testing.T) {",
      '  if runtime.GOOS != "linux" {',
      '    t.Skip("linux only")',
      "  }",
      "  if Add(1, 2) != 3 { t.Fatal(1) }",
      "}",
      "func TestUncondSkip(t *testing.T) {",
      '  t.Skip("broken")',
      "}",
    ].join("\n"),
  });
  const scopedDir = makeTempRepo({
    "package.json": JSON.stringify({
      name: "svc",
      dependencies: { express: "^5.0.0", "@sentry/node": "^10.0.0" },
      devDependencies: { "@electric-sql/pglite": "^0.5.0", "@stryker-mutator/core": "^9.0.0", vitest: "^4.0.0" },
      scripts: { test: "vitest run" },
    }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "src/app.ts": "export const ok = true;\n",
    "test/db/migrate.test.ts": "import { PGlite } from '@electric-sql/pglite'; import { test, expect } from 'vitest'; test('m', () => { expect(typeof PGlite).toBe('function'); });\n",
    ".github/workflows/ci.yml": "on: [pull_request]\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n",
  });
  try {
    const pyRepo = discoverRepo(pyDir);
    assert.equal(pyRepo.archetype, "library");
    assert.equal(pyRepo.ci.runsUnitTests, true);

    const rsReport = scanRepo(rsDir);
    assert.equal(rsReport.workspaces?.length, 1);
    assert.equal(rsReport.workspaces?.[0]?.path, "crates/core");
    assert.ok((rsReport.workspaces?.[0]?.score ?? 0) > 0);

    const goReport = scanRepo(goDir);
    const skips = goReport.findings.filter((f) => f.rule === "test-discipline");
    assert.equal(skips.length, 1);
    assert.equal(skips[0]?.line, 10);

    const scRepo = discoverRepo(scopedDir);
    assert.equal(scRepo.signals.hasProdTelemetryOrCanary, true);
    assert.equal(scRepo.signals.hasMigrationTest, true);
    assert.equal(scRepo.signals.hasMutationTool, true);
    assert.equal(scRepo.ci.runsIntegrationOrDbTests, true);
    assert.equal(scRepo.ci.runsBoundaryOrMbtTests, true);
  } finally {
    fs.rmSync(pyDir, { recursive: true, force: true });
    fs.rmSync(rsDir, { recursive: true, force: true });
    fs.rmSync(goDir, { recursive: true, force: true });
    fs.rmSync(scopedDir, { recursive: true, force: true });
  }
});

test("AI-first CI patterns: draft guard, parallel steps, benign git token rewrite, QML pragma, shell tests, and agent-doc symlinks", () => {
  const wfDraftAndParallel = parseGitHubWorkflow({
    abs: "/tmp/ci.yml",
    rel: ".github/workflows/ci.yml",
    isTest: false,
    isWorkflow: true,
    lines: 22,
    content: [
      "on: [pull_request]",
      "env:",
      '  GIT_CONFIG_COUNT: "1"',
      "  GIT_CONFIG_KEY_0: url.https://x-access-token:${{ github.token }}@github.com/.insteadOf",
      "  GIT_CONFIG_VALUE_0: https://github.com/",
      "jobs:",
      "  check:",
      "    if: ${{ !github.event.pull_request.draft }}",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - parallel:",
      "          - name: Lint",
      "            run: pnpm biome ci",
      "          - name: Test",
      "            env:",
      "              MUTATION_TARGET: MutationTestsCore",
      "            shell: pwsh",
      "            run: ./build.ps1 -Target ${env:MUTATION_TARGET}",
    ].join("\n"),
  });
  assert.equal(wfDraftAndParallel.isPrBlocking, true);
  assert.ok(wfDraftAndParallel.activeCommands.some((c) => c.includes("biome ci")));
  assert.ok(wfDraftAndParallel.activeCommands.some((c) => c.includes("MutationTestsCore")));

  const wfBadGitConfig = parseGitHubWorkflow({
    abs: "/tmp/bad.yml",
    rel: ".github/workflows/bad.yml",
    isTest: false,
    isWorkflow: true,
    lines: 10,
    content: [
      "on: [pull_request]",
      "env:",
      '  GIT_CONFIG_COUNT: "1"',
      "  GIT_CONFIG_KEY_0: core.hooksPath",
      "  GIT_CONFIG_VALUE_0: /tmp/evil",
      "jobs:",
      "  t:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: bun test",
    ].join("\n"),
  });
  assert.equal(wfBadGitConfig.activeCommands.length, 0);

  const dir = makeTempRepo({
    "shell/ui.js": ".pragma library\nfunction fmt(x) { return String(x); }\n",
    "test/shell.d/proc-test.sh": "#!/usr/bin/env bash\npkill -f dummy\n",
    "bin/run.sh": "#!/usr/bin/env bash\necho ok\n",
    "AGENTS.md": "# Agent Rules\n",
    "web/docs/package.json": JSON.stringify({ name: "docs", dependencies: { astro: "^5.0.0" } }),
    "web/docs/src/Page.astro": "---\n---\n<div/>",
    "common/eslint-config/package.json": JSON.stringify({ name: "@org/eslint-config" }),
    "common/eslint-config/index.js": "export default [];\n",
    "samples/DemoApp/DemoApp.csproj": "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
    "samples/DemoApp/Program.cs": "var b = WebApplication.CreateBuilder(args);\n",
    "src/Core/Core.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n",
    "src/Core/Policy.cs": "namespace Core; public class Policy { public int Ok() => 1; }\n",
    "test/Core.Tests/Core.Tests.csproj": "<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup><ItemGroup><ProjectReference Include=\"..\\..\\src\\Core\\Core.csproj\" /></ItemGroup></Project>\n",
    "test/Core.Tests/PolicyTests.cs": "using Core; using Xunit; public class PolicyTests { [Fact] public void T() => Assert.Equal(1, new Policy().Ok()); }\n",
    ".github/workflows/agent-sweep.lock.yml": "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  sweep:\n    runs-on: ubuntu-latest\n    steps:\n      - continue-on-error: true\n        run: echo sweep\n",
  });
  fs.symlinkSync(path.join(dir, "AGENTS.md"), path.join(dir, "CLAUDE.md"));
  try {
    const rep = scanRepo(dir);
    assert.equal(rep.archetype, "library");
    assert.equal(rep.summary.excludedCount, 0);
    assert.equal(rep.findings.filter((f) => f.rule === "ts-syntax-parse-error").length, 0);
    assert.equal(rep.findings.filter((f) => f.rule === "sh-pkill-f-pattern-kill").length, 0);
    assert.equal(rep.findings.filter((f) => f.rule === "ci-continue-on-error").length, 0);
    assert.equal(rep.workspaces?.length, 1);
    assert.equal(rep.workspaces?.[0]?.path, "src/Core");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("workflow audit honors repo default branch, default-false workflow inputs, and bun turbo task recursion", () => {
  const wf = parseGitHubWorkflow(
    {
      abs: "/tmp/check.yml",
      rel: ".github/workflows/check.yml",
      isTest: false,
      isWorkflow: true,
      lines: 18,
      content: [
        "on:",
        "  pull_request:",
        "    branches: [dev, beta]",
        "  workflow_dispatch:",
        "    inputs:",
        "      quarantine:",
        "        type: boolean",
        "        default: false",
        "jobs:",
        "  unit:",
        "    if: ${{ !inputs.quarantine && !github.event.pull_request.draft }}",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: bun turbo test --affected",
      ].join("\n"),
    },
    undefined,
    "dev",
  );
  assert.equal(wf.isPrBlocking, true);
  assert.ok(wf.activeCommands.some((c) => c.includes("bun turbo test")));

  const fakeBranchWf = parseGitHubWorkflow(
    {
      abs: "/tmp/check.yml",
      rel: ".github/workflows/check.yml",
      isTest: false,
      isWorkflow: true,
      lines: 8,
      content: "on:\n  pull_request:\n    branches: [dev]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun test\n",
    },
    undefined,
    "main",
  );
  assert.equal(fakeBranchWf.isPrBlocking, false);

  const turboRepo = makeTempRepo({
    "package.json": JSON.stringify({ name: "root", scripts: { typecheck: "bun turbo typecheck" } }),
    "packages/core/package.json": JSON.stringify({ name: "@r/core", scripts: { test: "bun test", typecheck: "tsc --noEmit" } }),
    "packages/core/tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "packages/core/src/a.ts": "export const x = 1;\n",
    "packages/core/src/a.test.ts": "import { test } from 'bun:test'; import { x } from './a'; test('x', () => { if (x !== 1) throw new Error(); });\n",
    ".github/workflows/ci.yml": "on: [pull_request]\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bun run typecheck\n      - run: bun turbo test --affected\n",
  });
  try {
    const repo = discoverRepo(turboRepo);
    assert.equal(repo.ci.runsTypeOrStructureCheck, true);
    assert.equal(repo.ci.runsUnitTests, true);
  } finally {
    fs.rmSync(turboRepo, { recursive: true, force: true });
  }
});

test("blind-panel Bucket-A calibrations: reusable workflows, extensionless scripts, node --run, strict bash shell, miri, docker compose, and EXPOSE-gated Dockerfile", () => {
  const dir = makeTempRepo({
    "package.json": JSON.stringify({ name: "lib", exports: { ".": "./dist/index.js" }, scripts: { "lint:check": "oxlint", "test:cov": "vitest run --coverage", test: "vitest run", "bench:ci": "vitest bench --run" } }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true } }),
    "src/a.ts": "export const x = 1;\n",
    "src/a.test.ts": "import { test, expect } from 'vitest'; import { x } from './a'; test('x', () => { expect(x).toBe(1); });\n",
    "Dockerfile": "FROM oven/bun:1\nENTRYPOINT [\"bun\"]\n",
    "scripts/check": "#!/usr/bin/env bash\nruff check\nmypy src\n",
    ".github/workflows/sub.yml": "on:\n  workflow_call:\njobs:\n  sub:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: bash --noprofile --norc -eo pipefail {0}\n        run: |\n          node --run lint:check\n          scripts/check\n          if [ \"$COV\" = \"true\" ]; then\n            pnpm run test:cov\n          else\n            pnpm run test\n          fi\n          node --run bench:ci\n          docker compose up -d\n",
    ".github/workflows/ci.yml": "on: [pull_request]\njobs:\n  call:\n    uses: $/.github/workflows/sub.yml\n",
    ".github/workflows/miri.yml": "on:\n  pull_request:\n    paths: ['crates/**']\njobs:\n  miri:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo +nightly miri test\n",
  });
  try {
    const repo = discoverRepo(dir);
    assert.equal(repo.archetype, "library");
    assert.equal(repo.ci.runsFormatterOrLint, true);
    assert.equal(repo.ci.runsTypeOrStructureCheck, true);
    assert.equal(repo.ci.runsUnitTests, true);
    assert.equal(repo.ci.runsIntegrationOrDbTests, true);
    assert.equal(repo.ci.runsMutationOrFormal, true);
    assert.equal(repo.ci.runsPerfOrBench, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Azure Pipelines detection, pre-commit targeted scan, bun run <file.ts> + R6 bench/dotnet filters, and default build/generated ignores", () => {
  const longSdk = Array.from({ length: 85 }, (_, i) => `  const k${i} = ${i};`).join("\n");
  const dir = makeTempRepo({
    "package.json": JSON.stringify({ name: "hybrid-app", version: "1.0.0" }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { strict: true, noUnusedLocals: true } }),
    ".githooks/pre-commit": "#!/usr/bin/env bash\nvstack scan . --fail-on-cheats --fail-on-errors\n",
    ".vstackignore": ".repospec/\nobj/\n",
    ".verification/ratchet.json": JSON.stringify({ version: 1, rules: {} }),
    ".verification/rungs.json": JSON.stringify({
      schemaVersion: 1,
      archetype: "library",
      rungs: {
        R0: { command: "bun run scripts/verify-r0.ts", required: true },
        R1: { command: "bun run scripts/verify-r1.ts", required: true },
        R6: { command: "bun scripts/bench-r6.ts && dotnet test --filter Category=Benchmark", required: true },
      },
    }),
    "ci/azure-pipelines.yml": [
      "pr:",
      "  branches:",
      "    include: [main]",
      "stages:",
      "  - stage: Verify",
      "    jobs:",
      "      - job: Check",
      "        steps:",
      "          - template: steps.yml",
      "          - task: DotNetCoreCLI@2",
      "            inputs:",
      "              command: test",
      "              arguments: --filter Category=Benchmark",
    ].join("\n"),
    "ci/steps.yml": [
      "steps:",
      "  - script: bun run scripts/verify-r0.ts",
      "  - bash: bun run scripts/verify-r1.ts",
      "  - script: bun scripts/bench-r6.ts",
    ].join("\n"),
    "ci/manual-only.yml": "trigger: none\npr: none\nsteps:\n  - script: cargo test\n",
    "scripts/verify-r0.ts": 'export const cmd = "oxlint src";\n',
    "scripts/verify-r1.ts": 'export const cmd = "tsc --noEmit && dotnet build";\n',
    "scripts/verify-fake.ts": 'export const ok = 1;\n',
    "scripts/bench-r6.ts": 'export function runBench(): number { return performance.now(); }\n',
    "src/App/App.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><Nullable>enable</Nullable></PropertyGroup></Project>\n",
    "src/App/Service.cs": "namespace App;\npublic sealed class Service { public int Add(int a, int b) => a + b; }\n",
    "src/App/obj/Debug/net10.0/App.AssemblyInfo.cs": "// generated prose comment\n[assembly: System.Reflection.AssemblyTitle(\"App\")]\n",
    "src/App/bin/Debug/net10.0/Temp.cs": "// generated bin comment\nclass B {}\n",
    "bin/Debug/net10.0/RootBin.cs": "// generated root bin comment\nclass R {}\n",
    ".repospec/repospec.sdk.ts": `// generated sdk\nexport function sdk(): number {\n${longSdk}\n  return k0;\n}\n`,
    ".runtime/scratch.ts": "// scratch prose\nexport const s = 1 as any;\n",
    "vendor/third-party.ts": "// vendored prose\nexport const v = 1 as any;\n",
  });
  try {
    const repo = discoverRepo(dir);
    assert.equal(repo.ci.hasCiWorkflows, true);
    assert.equal(repo.ci.workflowFiles.includes("ci/azure-pipelines.yml"), true);
    assert.equal(repo.ci.workflowFiles.includes("ci/manual-only.yml"), false);
    assert.equal(repo.ci.runsFormatterOrLint, true);
    assert.equal(repo.ci.runsTypeOrStructureCheck, true);
    assert.equal(repo.ci.runsUnitTests, true);
    assert.equal(repo.ci.runsPerfOrBench, true);
    assert.equal(repo.signals.hasPreCommitHook, true);

    assert.equal(repo.files.some((f) => f.rel.includes("/obj/") || f.rel.includes("/bin/") || f.rel.startsWith("bin/Debug/") || f.rel.startsWith(".repospec/") || f.rel.startsWith(".runtime/") || f.rel.startsWith("vendor/")), false);
    assert.equal(runDoctor(dir).healthy, true);

    assert.equal(parseAndValidateCommandArgv("R0", "bun run scripts/verify-r0.ts", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R1", "bun run scripts/verify-r1.ts", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R6", "bun scripts/bench-r6.ts", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R6", "bun run scripts/bench-r6.ts --samples 5", dir).error, undefined);
    assert.equal(parseAndValidateCommandArgv("R6", "dotnet test --filter Category=Benchmark", dir).error, undefined);
    assert.ok(parseAndValidateCommandArgv("R0", "bun run scripts/verify-fake.ts", dir).error?.includes("lacks real R0"));
    assert.ok(parseAndValidateCommandArgv("R2", "dotnet test --filter Category=Fast", dir).error?.includes("disallowed flag"));
    assert.ok(parseAndValidateCommandArgv("R6", "dotnet test", dir).error?.includes("requires --filter"));

    const preCommitClean = spawnSync(process.execPath, [cliPath, "scan", dir, "--fail-on-cheats", "--fail-on-errors"], { encoding: "utf8" });
    assert.equal(preCommitClean.status, 0, preCommitClean.stdout + preCommitClean.stderr);
    const noComments = spawnSync(process.execPath, [cliPath, "no-comments", dir, "--fail"], { encoding: "utf8" });
    assert.equal(noComments.status, 0, noComments.stdout + noComments.stderr);
    const strictStillFails = spawnSync(process.execPath, [cliPath, "scan", dir, "--strict"], { encoding: "utf8" });
    assert.equal(strictStillFails.status, 1);

    fs.writeFileSync(path.join(dir, "src", "bad.ts"), "// prose\nexport const bad = (1 as any);\n");
    const preCommitDirty = spawnSync(process.execPath, [cliPath, "scan", dir, "--fail-on-cheats", "--fail-on-errors"], { encoding: "utf8" });
    assert.equal(preCommitDirty.status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
